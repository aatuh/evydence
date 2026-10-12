package wiring

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type countedSignatureStager struct {
	*filesystem.Store
	stages int
}

func (s *countedSignatureStager) StagePayload(ctx context.Context, p app.ObjectPayload, r io.Reader) (app.ObjectPayload, error) {
	s.stages++
	return s.Store.StagePayload(ctx, p, r)
}

func TestPostgresArtifactSignatureCreationUsesCurrentGrantsAndAtomicStaging(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Signatures'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product')`)
	exec(`INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state)VALUES('release','tenant','product','1','draft')`)
	digest := "sha256:" + strings.Repeat("a", 64)
	exec(`INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('artifact','tenant',repeat('x',9000000),'application/json',$1,1),('pending','tenant','Pending','application/json',$2,1),('foreign','other','Foreign','application/json',$3,1)`, digest, "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64))
	exec(`INSERT INTO build_runs(id,tenant_id,project_id,release_id,provider,commit_sha,status,started_at,outputs,schema_version)VALUES('build','tenant','project','release','generic_ci',$1,'passed',now(),$2,'build-run.v1.0.0')`, strings.Repeat("1", 40), []map[string]string{{"artifact_id": "artifact", "digest": digest}})
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	c, err := BuildArtifactSignatureCommands(store, store, objects)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	in := verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "cosign", Signature: "recorded", RawPayload: []byte(`{"bundle":"opaque"}`), PayloadMediaType: "application/json"}
	count := func() [4]int {
		t.Helper()
		var counts [4]int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM artifact_signatures WHERE tenant_id='tenant'),(SELECT count(*) FROM audit_chain_entries WHERE tenant_id='tenant'),(SELECT count(*) FROM object_payloads WHERE tenant_id='tenant'),(SELECT count(*) FROM outbox_jobs WHERE tenant_id='tenant')`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	v, err := c.CreateArtifactSignature(ctx, a, in)
	if err != nil || v.VerificationStatus != "recorded" || v.SubjectDigest != digest || count() != [4]int{1, 1, 1, 1} {
		t.Fatal(v, count(), err)
	}
	p, err := store.GetObjectPayload(ctx, a.TenantID, v.PayloadHash)
	if err != nil || p.Status != app.ObjectPayloadStaged || p.Size != int64(len(in.RawPayload)) || v.PayloadRef != p.Reference() {
		t.Fatal(p, err)
	}
	if _, err := objects.Get(ctx, p.FinalKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("payload finalized before worker", err)
	}
	if err := app.FinalizeStagedObjectPayload(ctx, store, objects, a.TenantID, v.PayloadHash); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.Get(ctx, p.FinalKey); err != nil {
		t.Fatal(err)
	}
	baseline := count()
	for _, table := range []string{"object_payloads", "outbox_jobs", "artifact_signatures", "audit_chain_entries"} {
		exec(`CREATE OR REPLACE FUNCTION reject_signature_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected signature failure'; END $$`)
		exec(fmt.Sprintf(`CREATE TRIGGER reject_signature_write BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_signature_write()`, table))
		failed := in
		failed.RawPayload = []byte(fmt.Sprintf(`{"failure":%q}`, table))
		v, err := c.CreateArtifactSignature(ctx, a, failed)
		if err == nil || v.ID != "" || count() != baseline {
			t.Fatal("partial signature transaction", table, v, count(), err)
		}
		exec(fmt.Sprintf(`DROP TRIGGER reject_signature_write ON %s`, table))
	}
	beforeStages := objects.stages
	for _, tc := range []struct {
		actor    identitydomain.Actor
		artifact string
		want     error
	}{
		{a, "foreign", verificationapp.ErrNotFound}, {a, "missing", verificationapp.ErrNotFound},
		{identitydomain.Actor{TenantID: "tenant", KeyID: "read", Scopes: []string{"evidence:read"}}, "artifact", verificationapp.ErrForbidden},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:write"}}, "artifact", application.ErrForbidden},
		{identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "wrong-product", Scopes: []string{"evidence:write"}}}}, "artifact", application.ErrForbidden},
	} {
		input := in
		input.ArtifactID = tc.artifact
		if _, err := c.CreateArtifactSignature(ctx, tc.actor, input); !errors.Is(err, tc.want) {
			t.Fatal(err, tc)
		}
	}
	if objects.stages != beforeStages || count() != baseline {
		t.Fatal("unauthorized staging", objects.stages, count())
	}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:write"}}}}
	if _, err := c.CreateArtifactSignature(ctx, human, verificationapp.CreateArtifactSignatureInput{ArtifactID: "artifact", Algorithm: "other-recorded-algorithm", Signature: "recorded"}); err != nil {
		t.Fatal("current product association denied", err)
	}
	// A grant association added by the enclosing transaction must be visible
	// to authorization, not read from a separate pool connection or Ledger map.
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	if _, _, err := executor.WithBody(ctx, human, "POST", "/v1/artifact-signatures", "pending-association", []byte(`{"pending":true}`), func(ctx context.Context, repos app.Repositories) (int, any, error) {
		if err := repos.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: "pending-build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "generic_ci", CommitSHA: strings.Repeat("2", 40), Status: "passed", StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC(), SchemaVersion: "build-run.v1.0.0", Outputs: []domain.BuildOutput{{ArtifactID: "pending", Digest: "sha256:" + strings.Repeat("b", 64)}}}); err != nil {
			return 0, nil, err
		}
		v, err := c.CreateArtifactSignature(ctx, human, verificationapp.CreateArtifactSignatureInput{ArtifactID: "pending", Algorithm: "cosign", Signature: "recorded"})
		return 201, v, err
	}); err != nil {
		t.Fatal("authorization missed enclosing transaction", err)
	}
	beforeStages = objects.stages
	baseline = count()
	for i := 0; i < 2; i++ {
		_, _, err := executor.WithBody(ctx, a, "POST", "/v1/artifact-signatures", "signature-replay", []byte(`{"replay":true}`), func(ctx context.Context, _ app.Repositories) (int, any, error) {
			input := in
			input.RawPayload = []byte(`{"replay":true}`)
			v, err := c.CreateArtifactSignature(ctx, a, input)
			return 201, v, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := count(); objects.stages != beforeStages+1 || got != [4]int{baseline[0] + 1, baseline[1] + 1, baseline[2] + 1, baseline[3] + 1} {
		t.Fatal("replay duplicated effects", objects.stages, got, baseline)
	}
	baseline = count()
	beforeStages = objects.stages
	if _, _, err := executor.WithBody(ctx, a, "POST", "/v1/artifact-signatures", "signature-replay", []byte(`{"changed":true}`), func(context.Context, app.Repositories) (int, any, error) {
		t.Fatal("changed replay body executed")
		return 0, nil, nil
	}); !errors.Is(err, app.ErrIdempotencyConflict) {
		t.Fatal(err)
	}
	if count() != baseline || objects.stages != beforeStages {
		t.Fatal("changed replay body wrote effects")
	}
}

package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestPostgresCandidateCreationRejectsForeignReferencesAndRequiresArtifactGrants(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name)VALUES('tenant','Candidates'),('other','Other');INSERT INTO products(id,tenant_id,name,slug)VALUES('product','tenant','Product','product'),('foreign-product','other','Other','product');INSERT INTO projects(id,tenant_id,product_id,name)VALUES('project','tenant','product','Project'),('foreign-project','other','foreign-product','Other');INSERT INTO releases(id,tenant_id,product_id,version,state,revision)VALUES('release','tenant','product','1','draft',1),('foreign-release','other','foreign-product','1','draft',1),('wrong-release','tenant','product','2','draft',1)`)
	if err := app.ExecuteUnitOfWork(ctx, store, candidateReferenceFixture); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"foreign-", "wrong-"} {
		tenant, product, project, release := "other", "foreign-product", "foreign-project", "foreign-release"
		if prefix == "wrong-" {
			tenant, product, project, release = "tenant", "product", "project", "wrong-release"
		}
		for _, id := range []string{"ev-sbom", "ev-scan", "ev-vex", "ev-contract"} {
			exec(fmt.Sprintf(`INSERT INTO evidence_items SELECT(jsonb_populate_record(NULL::evidence_items,to_jsonb(e)||jsonb_build_object('id','%s','tenant_id','%s','product_id','%s','release_id','%s'))).* FROM evidence_items e WHERE e.id='%s'`, prefix+id, tenant, product, release, id))
		}
		for _, row := range []struct{ table, id string }{{"build_runs", "build"}, {"artifacts", "artifact"}, {"sboms", "sbom"}, {"vulnerability_scans", "scan"}, {"vex_documents", "vex"}, {"openapi_contracts", "contract"}, {"release_bundles", "bundle"}} {
			exec(fmt.Sprintf(`INSERT INTO %s SELECT(jsonb_populate_record(NULL::%s,to_jsonb(x)||jsonb_build_object('id','%s','tenant_id','%s','product_id','%s','project_id','%s','release_id','%s','evidence_id','%s'||(to_jsonb(x)->>'evidence_id'),'digest','sha256:'||repeat('b',64)))).* FROM %s x WHERE x.id='%s'`, row.table, row.table, prefix+row.id, tenant, product, project, release, prefix, row.table, row.id))
		}
	}
	commands, err := BuildCandidateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"release:write"}}
	counts := func(wantCandidates, wantAudits int) {
		t.Helper()
		var c, a int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM release_candidates),(SELECT count(*)FROM audit_chain_entries)`).Scan(&c, &a); err != nil || c != wantCandidates || a != wantAudits {
			t.Fatal("candidate effects changed", c, a, err)
		}
	}
	for _, prefix := range []string{"foreign-", "wrong-", "missing-"} {
		for _, kind := range []string{"build", "artifact", "sbom", "scan", "vex", "contract", "bundle"} {
			if prefix == "wrong-" && kind == "artifact" {
				continue
			} // Artifacts are tenant-scoped, not release-scoped.
			in := releaseapp.CreateReleaseCandidateInput{ReleaseID: "release", Name: "Denied"}
			id := prefix + kind
			switch kind {
			case "build":
				in.BuildIDs = []string{id}
			case "artifact":
				in.ArtifactIDs = []string{id}
			case "sbom":
				in.SBOMIDs = []string{id}
			case "scan":
				in.ScanIDs = []string{id}
			case "vex":
				in.VEXIDs = []string{id}
			case "contract":
				in.ContractIDs = []string{id}
			case "bundle":
				in.BundleIDs = []string{id}
			}
			if v, err := commands.CreateReleaseCandidate(ctx, actor, in); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
				t.Fatal("foreign/missing reference accepted", prefix, kind, v.ID, err)
			}
			counts(0, 0)
		}
	}
	for _, tc := range []struct{ tenant, release string }{{"other", "release"}, {"tenant", "foreign-release"}} {
		foreign := actor
		foreign.TenantID = tc.tenant
		if v, err := commands.CreateReleaseCandidate(ctx, foreign, releaseapp.CreateReleaseCandidateInput{ReleaseID: tc.release, Name: "Denied"}); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
			t.Fatal("foreign parent accepted", v.ID, err)
		}
	}
	for _, kind := range []string{"sbom", "scan", "vex", "contract"} {
		exec(`UPDATE evidence_items SET type='wrong_type' WHERE id='ev-` + kind + `'`)
		in := releaseapp.CreateReleaseCandidateInput{ReleaseID: "release", Name: "Denied"}
		switch kind {
		case "sbom":
			in.SBOMIDs = []string{kind}
		case "scan":
			in.ScanIDs = []string{kind}
		case "vex":
			in.VEXIDs = []string{kind}
		case "contract":
			in.ContractIDs = []string{kind}
		}
		if v, err := commands.CreateReleaseCandidate(ctx, actor, in); !errors.Is(err, releaseapp.ErrNotFound) || v.ID != "" {
			t.Fatal("mismatched source evidence accepted", kind, v.ID, err)
		}
		typ := kind
		if kind == "scan" {
			typ = "vulnerability_scan"
		}
		if kind == "contract" {
			typ = "openapi_contract"
		}
		exec(`UPDATE evidence_items SET type='` + typ + `' WHERE id='ev-` + kind + `'`)
		counts(0, 0)
	}
	human := actor
	human.KeyID = ""
	human.UserID = "human"
	in := releaseapp.CreateReleaseCandidateInput{ReleaseID: "release", Name: "Snapshot", ArtifactIDs: []string{"artifact"}}
	if v, err := commands.CreateReleaseCandidate(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("removed grant accepted", v.ID, err)
	}
	human.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}
	in.ArtifactIDs = []string{"wrong-artifact"} // Tenant-owned but linked to no authorized parent.
	if v, err := commands.CreateReleaseCandidate(ctx, human, in); !errors.Is(err, application.ErrForbidden) || v.ID != "" {
		t.Fatal("unlinked artifact accepted", v.ID, err)
	}
	in.ArtifactIDs = []string{"artifact"}
	for _, table := range []string{"release_candidates", "audit_chain_entries"} {
		exec(`CREATE FUNCTION reject_candidate_creation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private candidate SQL';END$$;CREATE TRIGGER reject_candidate_creation BEFORE INSERT ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_candidate_creation()`)
		if v, err := commands.CreateReleaseCandidate(ctx, human, in); err == nil || v.ID != "" {
			t.Fatal("creation succeeded after insertion failure", v.ID, err)
		}
		exec(`DROP TRIGGER reject_candidate_creation ON ` + table + `;DROP FUNCTION reject_candidate_creation()`)
		counts(0, 0)
	}
	if v, err := commands.CreateReleaseCandidate(ctx, human, in); err != nil || v.ID == "" || v.State.String() != "open" {
		t.Fatal("linked artifact denied", v.ID, err)
	}
	counts(1, 1)
}

func TestPostgresCandidateCreationUsesAllCurrentReferencesAndRollsBackTogether(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Candidates')`); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildCandidateCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCandidateCommands(nil); err == nil {
		t.Fatal("nil candidate transaction factory accepted")
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"release:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"release:write"}}}}
	executor := app.IdempotencyUnitOfWork{Transactions: store}
	runs := 0
	rollback := errors.New("rollback pending candidate creation")
	run := func(fail bool) app.IdempotentUnitOfWorkCommand {
		return func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			runs++
			at := time.Now().UTC().Truncate(time.Microsecond)
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: "product", TenantID: "tenant", Name: strings.Repeat("x", 9000000), Slug: "product", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertProject(txCtx, domain.Project{ID: "project", TenantID: "tenant", ProductID: "product", Name: "Project", CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: "release", TenantID: "tenant", ProductID: "product", Version: strings.Repeat("v", 65537), State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := candidateReferenceFixture(txCtx, repos); err != nil {
				return 0, nil, err
			}
			in := releaseapp.CreateReleaseCandidateInput{ReleaseID: " release ", Name: " Snapshot ", BuildIDs: []string{" build "}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}}
			v, err := commands.CreateReleaseCandidate(txCtx, actor, in)
			if err != nil {
				return 0, nil, err
			}
			if v.Name != "Snapshot" || v.ID == "" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.State.String() != "open" || v.Revision != 1 || v.CreatedAt.Nanosecond()%1000 != 0 || len(v.BuildIDs) != 1 || v.BuildIDs[0] != "build" || len(v.ArtifactIDs) != 1 || len(v.SBOMIDs) != 1 || len(v.ScanIDs) != 1 || len(v.VEXIDs) != 1 || len(v.ContractIDs) != 1 || len(v.BundleIDs) != 1 {
				return 0, nil, errors.New("candidate fields/references changed")
			}
			if fail {
				return 0, nil, rollback
			}
			return 201, v, nil
		}
	}
	counts := func() [4]int {
		t.Helper()
		var n [4]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM release_candidates),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM products),(SELECT count(*)FROM idempotency_records WHERE state='completed')`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate-create", "rollback", nil, run(true)); !errors.Is(err, rollback) || counts() != [4]int{} {
		t.Fatal("candidate compound rollback failed", err, counts())
	}
	status, result, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate-create", "success", nil, run(false))
	if err != nil || status != 201 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("candidate not committed", status, err, counts())
	}
	v := result.(releasedomain.ReleaseCandidate)
	var raw []byte
	var storedHash string
	if err := pool.QueryRow(ctx, `SELECT document,snapshot_hash FROM release_candidates WHERE id=$1`, v.ID).Scan(&raw, &storedHash); err != nil {
		t.Fatal(err)
	}
	var record domain.ReleaseCandidate
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.ID != v.ID || record.SnapshotHash != v.SnapshotHash || storedHash != v.SnapshotHash {
		t.Fatal("durable candidate response mismatch", record, v)
	}
	record.SnapshotHash = ""
	hash, err := application.NormalizedJSONHash(record)
	if err != nil || hash != v.SnapshotHash {
		t.Fatal("legacy candidate canonical profile changed", hash, v.SnapshotHash, err)
	}
	if _, _, err := executor.WithBody(ctx, actor, "POST", "/pending-candidate-create", "success", nil, run(false)); err != nil || runs != 2 || counts() != [4]int{1, 1, 1, 1} {
		t.Fatal("replay repeated candidate", err, runs, counts())
	}
}

// Real transaction repositories create every referenced record in the same
// outer unit of work. Large foreign metadata must never be selected by the
// identifier-only validator.
func candidateReferenceFixture(ctx context.Context, repos app.Repositories) error {
	at := time.Now().UTC().Truncate(time.Microsecond)
	digest := "sha256:" + strings.Repeat("a", 64)
	if err := repos.ReleaseCatalog.InsertArtifact(ctx, domain.Artifact{ID: "artifact", TenantID: "tenant", Name: strings.Repeat("x", 9000000), MediaType: "application/octet-stream", Digest: digest, Size: 1, CreatedAt: at}); err != nil {
		return err
	}
	if err := repos.Builds.InsertBuildRun(ctx, domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "project", ReleaseID: "release", Provider: "manual", CommitSHA: "abc", Status: "passed", StartedAt: at, Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}, SchemaVersion: "evydence.build.v1", CreatedAt: at}); err != nil {
		return err
	}
	for _, e := range []domain.EvidenceItem{
		{ID: "ev-sbom", TenantID: "tenant", Type: "sbom", ReleaseID: "release", ProductID: "product"},
		{ID: "ev-scan", TenantID: "tenant", Type: "vulnerability_scan", ReleaseID: "release", ProductID: "product"},
		{ID: "ev-vex", TenantID: "tenant", Type: "vex", ReleaseID: "release", ProductID: "product"},
		{ID: "ev-contract", TenantID: "tenant", Type: "openapi_contract", ReleaseID: "release", ProductID: "product"},
	} {
		e.Title = "Reference"
		e.SourceSystem = "manual"
		e.PayloadHash = digest
		e.Canonicalization = "evydence-json-v1"
		e.TrustLevel = "unverified"
		e.CanonicalHash = digest
		e.SchemaVersion = "evydence.evidence.v1"
		e.ObservedAt = at
		e.CreatedAt = at
		e.VerificationStatus = "pending"
		if err := repos.Evidence.InsertEvidence(ctx, e); err != nil {
			return err
		}
	}
	if err := repos.Evidence.InsertSBOM(ctx, domain.SBOM{ID: "sbom", TenantID: "tenant", EvidenceID: "ev-sbom", ReleaseID: "release", Format: "cyclonedx", SpecVersion: "1.5", Components: []domain.SBOMComponent{}, CreatedAt: at}); err != nil {
		return err
	}
	if err := repos.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", EvidenceID: "ev-scan", ReleaseID: "release", Scanner: "manual", TargetRef: "release", Summary: map[string]int{}, Findings: []domain.VulnerabilityFinding{}, CreatedAt: at}); err != nil {
		return err
	}
	if err := repos.Evidence.InsertVEXDocument(ctx, domain.VEXDocument{ID: "vex", TenantID: "tenant", EvidenceID: "ev-vex", ReleaseID: "release", Format: "openvex", Author: "manual", StatusSummary: map[string]int{}, SchemaVersion: "evydence.vex.v1", CreatedAt: at}); err != nil {
		return err
	}
	if err := repos.Evidence.InsertOpenAPIContract(ctx, domain.OpenAPIContract{ID: "contract", TenantID: "tenant", EvidenceID: "ev-contract", ReleaseID: "release", ProductID: "product", Version: "1", Hash: digest, Operations: []domain.OpenAPIOperation{}, CreatedAt: at}); err != nil {
		return err
	}
	return repos.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: "bundle", TenantID: "tenant", ReleaseID: "release", State: "draft", Manifest: map[string]any{"large": strings.Repeat("x", 9000000)}, ManifestHash: digest, SignatureRefs: []string{}, CreatedAt: at})
}

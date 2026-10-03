package wiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const wiringCycloneDXDocument = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}]}`
const wiringSPDXDocument = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"example","documentNamespace":"https://example.test/spdx","dataLicense":"CC0-1.0","creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},"packages":[{"SPDXID":"SPDXRef-Package","name":"api","versionInfo":"1.0.0","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:generic/api@1.0.0"}]}],"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Package"}]}`

func TestPostgresSBOMIngestionUsesFocusedDurableCommandsForBothFormats(t *testing.T) {
	if _, err := BuildSBOMIngestionCommands(nil, nil, false); err == nil {
		t.Fatal("missing transactions accepted")
	}
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Second)
	defer cancel()
	seedControlEvidenceSubjects(t, ctx, store, pool)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	a := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"evidence:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"evidence:write"}}}}
	auth := &attestationHTTPActor{actor: a}
	counts := func() [5]int {
		t.Helper()
		var n [5]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM sboms),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM object_payloads)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseline := counts()
	request := func(path, key, body, media, artifact string, want int) domain.SBOM {
		t.Helper()
		opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects, WorkerOwnedParsers: true}, "test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
		if err != nil {
			t.Fatal(err)
		}
		if opts.SBOMIngestionCommands == nil {
			t.Fatal("SBOM ingress remains Ledger-backed")
		}
		opts.Authenticator = auth
		noReload := &decisionHTTPNoReloadStore{}
		ledger, err := app.NewLedgerWithContext(ctx, app.Config{Store: noReload, UnitOfWork: store})
		if err != nil {
			t.Fatal(err)
		}
		server, err := httpapi.NewServerWithOptionsContext(ctx, ledger, opts)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer isolated-auth")
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", media)
		if media != "application/json" {
			r.Header.Set("X-Evydence-Release-ID", "release")
			if artifact != "" {
				r.Header.Set("X-Evydence-Artifact-ID", artifact)
			}
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private SBOM SQL") {
			t.Fatalf("got %d want %d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
		}
		if want >= 400 {
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
				t.Fatal("unsafe error envelope")
			}
			return domain.SBOM{}
		}
		var result struct {
			Data domain.SBOM `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Data
	}
	var first domain.SBOM
	for _, tc := range []struct{ path, format, media, raw, spec string }{{"/v1/sboms", "cyclonedx", evidenceapp.CycloneDXMediaType, wiringCycloneDXDocument, "1.6"}, {"/v1/sboms/spdx", "spdx", evidenceapp.SPDXMediaType, wiringSPDXDocument, "SPDX-2.3"}} {
		body := `{"release_id":"release","artifact_id":"artifact","payload":` + tc.raw + `}`
		v := request(tc.path, tc.format+"-wrapped", body, "application/json", "", 201)
		if v.ID == "" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.ArtifactID != "artifact" || v.Format != tc.format || v.SpecVersion != tc.spec || v.ComponentCount != 1 || len(v.Components) != 1 || v.Components[0].Identity != "purl:pkg:generic/api@1.0.0" || v.CreatedAt.Nanosecond()%1000 != 0 {
			t.Fatal(v)
		}
		if replay := request(tc.path, tc.format+"-wrapped", body, "application/json", "", 201); !reflect.DeepEqual(replay, v) {
			t.Fatal("wrapped replay changed", replay, v)
		}
		native := request(tc.path, tc.format+"-native", tc.raw, tc.media, "artifact", 201)
		if replay := request(tc.path, tc.format+"-native", tc.raw, tc.media, "artifact", 201); !reflect.DeepEqual(replay, native) {
			t.Fatal("native replay changed", replay, native)
		}
		request(tc.path, tc.format+"-native", tc.raw, tc.media, "", 409)
		var components []byte
		var count int
		if err := pool.QueryRow(ctx, `SELECT component_count,components FROM sboms WHERE id=$1`, v.ID).Scan(&count, &components); err != nil || count != 0 || string(components) != "null" {
			t.Fatal("worker projection changed", count, string(components), err)
		}
		var encoded []byte
		if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)FROM evidence_items e WHERE id=$1`, v.EvidenceID).Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var item domain.EvidenceItem
		if err := json.Unmarshal(encoded, &item); err != nil {
			t.Fatal(err)
		}
		item.ObservedAt, item.CreatedAt = item.ObservedAt.UTC(), item.CreatedAt.UTC()
		hash, err := (evidenceCanonicalHasher{}).HashEvidence(ctx, domain.EvidenceToContextModel(item))
		if err != nil || hash != item.CanonicalHash || item.PayloadHash != app.BytesPayloadSource([]byte(tc.raw)).Digest || item.VerificationStatus != "pending" || item.ChainEntryID == "" {
			t.Fatal("durable evidence commitment changed", item, hash, err)
		}
		payload, err := store.GetObjectPayload(ctx, a.TenantID, item.PayloadHash)
		if err != nil || payload.Status != app.ObjectPayloadStaged || payload.Size != int64(len(tc.raw)) || payload.Reference() != item.PayloadRef {
			t.Fatal("staged payload changed", payload, err)
		}
		if _, err := objects.Get(ctx, payload.FinalKey); !errors.Is(err, app.ErrNotFound) {
			t.Fatal("finalized before worker", err)
		}
		_, _, err = (app.IdempotencyUnitOfWork{Transactions: store}).WithBodyDigest(ctx, a, "POST", tc.path, tc.format+"-legacy", item.PayloadHash, func(context.Context, app.Repositories) (int, any, error) { return 201, v, nil })
		if err != nil {
			t.Fatal(err)
		}
		if replay := request(tc.path, tc.format+"-legacy", tc.raw, tc.media, "artifact", 201); !reflect.DeepEqual(replay, v) {
			t.Fatal("legacy receipt changed")
		}
		request(tc.path, tc.format+"-legacy", tc.raw, tc.media, "", 409)
		auth.actor.ResourceGrants = nil
		request(tc.path, tc.format+"-wrapped", body, "application/json", "", 403)
		request(tc.path, tc.format+"-native", tc.raw, tc.media, "artifact", 403)
		auth.actor = a
		auth.actor.TenantID = "other"
		request(tc.path, tc.format+"-foreign", body, "application/json", "", 404)
		auth.actor = a
		for i, bad := range []string{`null`, `[]`, `{}`, `{} {}`, strings.Replace(body, `"release"`, `null`, 1), strings.Replace(body, `"artifact"`, `null`, 1), strings.Replace(body, tc.raw, `null`, 1), strings.Replace(body, `"release"`, `"bad\u0000"`, 1), strings.Replace(body, `"artifact"`, `"`+strings.Repeat("x", 1025)+`"`, 1), strings.Replace(body, `"payload":`, `"unknown":true,"payload":`, 1), strings.Replace(body, `"payload":`, `"payload":{},"payload":`, 1), strings.Replace(body, tc.raw, `{}`, 1)} {
			request(tc.path, fmt.Sprintf("%s-invalid-%d", tc.format, i), bad, "application/json", "", 400)
		}
		request(tc.path, tc.format+"-invalid-native", `{}`, tc.media, "artifact", 400)
		if tc.format == "cyclonedx" {
			first = v
		}
	}
	expected := [5]int{baseline[0] + 4, baseline[1] + 4, baseline[2] + 8, baseline[3] + 6, baseline[4] + 2}
	if counts() != expected || objects.stages != 4 {
		t.Fatal("replay/invalid request changed durable effects", counts(), objects.stages)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,tenant_id,name,media_type,digest,size)VALUES('foreign-artifact','other','foreign','application/json',$1,1)`, "sha256:"+strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	body := `{"release_id":"release","artifact_id":"artifact","payload":` + wiringCycloneDXDocument + `}`
	// The shared artifact-write policy masks both foreign and missing IDs as
	// forbidden before its existence validator, preserving the existing boundary.
	request("/v1/sboms", "wrong-artifact", strings.Replace(body, `"artifact"`, `"foreign-artifact"`, 1), "application/json", "", 403)
	request("/v1/sboms", "missing-artifact", strings.Replace(body, `"artifact"`, `"missing-artifact"`, 1), "application/json", "", 403)
	if counts() != expected || objects.stages != 4 {
		t.Fatal("foreign artifact reached staging")
	}
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='other-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("/v1/sboms", "cyclonedx-wrapped", body, "application/json", "", 404)
	request("/v1/sboms/spdx", "spdx-native", wiringSPDXDocument, evidenceapp.SPDXMediaType, "artifact", 404)
	// A coherent same-tenant reparenting is denied by current grants, not by
	// an ownership mismatch; saved upload responses must obey both checks.
	if _, err := pool.Exec(ctx, `INSERT INTO products(id,tenant_id,name,slug)VALUES('sibling-product','tenant','Sibling','sibling');UPDATE releases SET product_id='sibling-product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	request("/v1/sboms", "cyclonedx-wrapped", body, "application/json", "", 403)
	request("/v1/sboms/spdx", "spdx-native", wiringSPDXDocument, evidenceapp.SPDXMediaType, "artifact", 403)
	if _, err := pool.Exec(ctx, `UPDATE releases SET product_id='product' WHERE id='release'`); err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"object_payloads", "outbox_jobs", "audit_chain_entries", "evidence_items", "sboms", "idempotency_records", "commit"} {
		table, op := stage, "INSERT"
		if stage == "idempotency_records" {
			op = "UPDATE"
		}
		trigger := `CREATE TRIGGER reject_sbom_upload BEFORE ` + op + ` ON ` + table + ` FOR EACH ROW EXECUTE FUNCTION reject_sbom_upload()`
		if stage == "commit" {
			table = "sboms"
			trigger = `CREATE CONSTRAINT TRIGGER reject_sbom_upload AFTER INSERT ON sboms DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_sbom_upload()`
		}
		if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_sbom_upload()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SBOM SQL';END$$;`+trigger); err != nil {
			t.Fatal(err)
		}
		request("/v1/sboms", "fault-"+stage, body, "application/json", "", 500)
		if counts() != expected {
			t.Fatal("partial SBOM upload effects", stage, counts())
		}
		if _, err := pool.Exec(ctx, `DROP TRIGGER reject_sbom_upload ON `+table+`;DROP FUNCTION reject_sbom_upload()`); err != nil {
			t.Fatal(err)
		}
	}
	request("/v1/sboms", "fault-commit", body, "application/json", "", 201)
	if counts() != [5]int{baseline[0] + 5, baseline[1] + 5, baseline[2] + 10, baseline[3] + 7, baseline[4] + 2} {
		t.Fatal("commit retry duplicated effects", counts())
	}
	digest := app.BytesPayloadSource([]byte(wiringCycloneDXDocument)).Digest
	if err := app.FinalizeStagedObjectPayload(ctx, store, objects, a.TenantID, digest); err != nil {
		t.Fatal(err)
	}
	payload, err := store.GetObjectPayload(ctx, a.TenantID, digest)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := objects.Get(ctx, payload.FinalKey)
	if err != nil || !bytes.Equal(stored.Bytes, []byte(wiringCycloneDXDocument)) || stored.Digest != digest || stored.TenantID != a.TenantID {
		t.Fatal("finalized bytes changed", stored, err)
	}
	inline, err := BuildSBOMIngestionCommands(store, objects, false)
	if err != nil {
		t.Fatal(err)
	}
	v, err := inline.UploadSBOMPayload(ctx, a, evidenceapp.SBOMIngestionInput{ReleaseID: "release", ArtifactID: "artifact", Format: "cyclonedx"}, evidenceapp.BytesPayloadSource([]byte(wiringCycloneDXDocument)))
	if err != nil || v.ComponentCount != 1 || len(v.Components) != 1 || !reflect.DeepEqual(domain.SBOMFromContext(v).Components, first.Components) {
		t.Fatal("inline projection changed", v, err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT component_count FROM sboms WHERE id=$1`, v.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("inline projection not stored", count, err)
	}
	if counts() != [5]int{baseline[0] + 6, baseline[1] + 6, baseline[2] + 12, baseline[3] + 8, baseline[4] + 2} {
		t.Fatal("finalized reuse duplicated payload lifecycle", counts())
	}
}

func TestPostgresSBOMIngestionJoinsPendingParentsAndOuterRollback(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if err := app.ExecuteUnitOfWork(ctx, store, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "tenant", Name: "Pending SBOM", CreatedAt: at})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildSBOMIngestionCommands(store, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	a := domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}
	source := evidenceapp.BytesPayloadSource([]byte(wiringCycloneDXDocument))
	counts := func() [7]int {
		t.Helper()
		var n [7]int
		if err := pool.QueryRow(ctx, `SELECT(SELECT count(*)FROM products),(SELECT count(*)FROM releases),(SELECT count(*)FROM artifacts),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM sboms),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rollback := errors.New("outer SBOM command rolled back")
	for _, key := range []string{"rollback", "commit"} {
		_, _, err := (app.IdempotencyUnitOfWork{Transactions: store}).WithBody(ctx, a, "POST", "/compound-sbom", key, []byte(key), func(txCtx context.Context, repos app.Repositories) (int, any, error) {
			if err := repos.ReleaseCatalog.InsertProduct(txCtx, domain.Product{ID: key + "-product", TenantID: "tenant", Name: key, Slug: key, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertRelease(txCtx, domain.Release{ID: key + "-release", TenantID: "tenant", ProductID: key + "-product", Version: "1", State: "draft", Revision: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			if err := repos.ReleaseCatalog.InsertArtifact(txCtx, domain.Artifact{ID: key + "-artifact", TenantID: "tenant", Name: key, MediaType: "application/json", Digest: "sha256:" + strings.Repeat("a", 64), Size: 1, CreatedAt: at}); err != nil {
				return 0, nil, err
			}
			in := evidenceapp.SBOMIngestionInput{ReleaseID: key + "-release", ArtifactID: key + "-artifact", Format: "cyclonedx"}
			if err := commands.AuthorizeUploadSBOM(txCtx, a, in); err != nil {
				return 0, nil, err
			}
			v, err := commands.UploadSBOMPayload(txCtx, a, in, source)
			if err != nil {
				return 0, nil, err
			}
			if v.ComponentCount != 1 || len(v.Components) != 1 {
				t.Fatal("missing-object mode lost projection", v)
			}
			if key == "rollback" {
				return 0, nil, rollback
			}
			return 201, domain.SBOMFromContext(v), nil
		})
		if key == "rollback" {
			if !errors.Is(err, rollback) || counts() != [7]int{} {
				t.Fatal("escaped outer rollback", counts(), err)
			}
		} else if err != nil || counts() != [7]int{1, 1, 1, 1, 1, 2, 1} {
			t.Fatal("pending parents unavailable or non-atomic", counts(), err)
		}
	}
}

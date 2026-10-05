package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func attestationNativeBody(t *testing.T) string {
	t.Helper()
	statement, err := os.ReadFile("../../../testdata/intoto/slsa-provenance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString(statement) + `","signatures":[{"sig":"untrusted"}]}`
}

func attestationNativeHTTP(t *testing.T, store *postgres.Store, objects app.ObjectStore, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, objects)
	var err error
	o.BuildAttestationCommands, err = BuildBuildAttestationCommands(store, objects, true)
	if err != nil {
		t.Fatal(err)
	}
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/builds/linked-build/attestations", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/vnd.dsse.envelope+json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native attestation status=%d want=%d loads=%d: %s", w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("attestation lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("attestation lost Problem Details")
	}
	return w.Body.String()
}

func attestationNativeCounts(t *testing.T, p *pgxpool.Pool) [7]int {
	t.Helper()
	var n [7]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM build_attestations),(SELECT count(*)FROM evidence_items),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM object_payloads),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5], &n[6]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresBuildAttestationNativeHTTPReplayAndCurrentAuthority(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &countedSignatureStager{Store: fs}
	body := attestationNativeBody(t) + strings.Repeat(" ", int(app.SmallJSONRequestLimit))
	one := attestationNativeHTTP(t, store, objects, "original", body, 201)
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(body)))
	var envelope struct {
		Data domain.BuildAttestation `json:"data"`
	}
	if err := json.Unmarshal([]byte(one), &envelope); err != nil || envelope.Data.ID == "" || envelope.Data.EvidenceID == "" || envelope.Data.BuildID != "linked-build" || envelope.Data.TenantID != "tenant" || envelope.Data.PayloadHash != digest || envelope.Data.PayloadSize != int64(len(body)) || envelope.Data.SignatureCount != 1 || envelope.Data.VerificationStatus != "structurally_valid" || envelope.Data.SchemaVersion != domain.BuildAttestationSchemaVersion {
		t.Fatal("attestation response contract changed", one, err)
	}
	var status, payloadType string
	if err := p.QueryRow(t.Context(), `SELECT verification_status,payload_type FROM build_attestations WHERE id=$1`, envelope.Data.ID).Scan(&status, &payloadType); err != nil || status != "accepted" || payloadType != "" {
		t.Fatal("worker ownership changed", status, payloadType, err)
	}
	var wrongAudit int
	if err := p.QueryRow(t.Context(), `SELECT count(*)FROM audit_chain_entries WHERE actor_id!='user'OR actor_type!='human_user'`).Scan(&wrongAudit); err != nil || wrongAudit != 0 {
		t.Fatal("attestation lost audit caller", wrongAudit, err)
	}
	assertRetentionHTTPReplay(t, one, attestationNativeHTTP(t, store, objects, "original", body, 201))
	attestationNativeHTTP(t, store, objects, "original", body+" ", 409)
	o := subjectVerificationOptions(t, store, objects)
	a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/builds/linked-build/attestations", "historical", []byte(body), func(ctx context.Context) error {
		return o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(ctx, a, "linked-build")
	}, func(context.Context) (int, any, error) {
		return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(t.Context(), `UPDATE releases SET version=repeat('v',65537);UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000),media_type=repeat('private-',1200000);UPDATE build_runs SET repository=repeat('private-',1200000),source_identity=jsonb_build_object('private',repeat('private-',1200000)),outputs=jsonb_build_array(jsonb_build_object('artifact_id','artifact','digest','sha256:'||repeat('a',64),'private',repeat('private-',1200000)))`); err != nil {
		t.Fatal(err)
	}
	assertRetentionHTTPReplay(t, one, attestationNativeHTTP(t, store, objects, "original", body, 201))
	if out := attestationNativeHTTP(t, store, objects, "historical", body, 201); !strings.Contains(out, "9007199254740993") {
		t.Fatal("historical attestation number rounded", out)
	}
	attestationNativeHTTP(t, store, objects, "oversized-fresh", body, 409)
	for _, g := range []struct {
		kind, id string
		allowed  bool
	}{{"product", "product", true}, {"project", "project", true}, {"release", "release", true}, {"product", "other-product", false}, {"project", "other-project", false}, {"release", "other-release", false}, {"tenant", "other", false}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, g.kind, g.id); err != nil {
			t.Fatal(err)
		}
		want := 403
		if g.allowed {
			want = 201
		}
		attestationNativeHTTP(t, store, objects, "original", body, want)
	}
	if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant'WHERE id='grant';UPDATE products SET tenant_id='other'WHERE id='product'`); err != nil {
		t.Fatal(err)
	}
	attestationNativeHTTP(t, store, objects, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE products SET tenant_id='tenant'WHERE id='product';UPDATE artifacts SET tenant_id='other'WHERE id='artifact'`); err != nil {
		t.Fatal(err)
	}
	attestationNativeHTTP(t, store, objects, "original", body, 404)
	if _, err := p.Exec(t.Context(), `UPDATE artifacts SET tenant_id='tenant'WHERE id='artifact';UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	attestationNativeHTTP(t, store, objects, "original", body, 403)
	if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
		t.Fatal(err)
	}
	attestationNativeHTTP(t, store, objects, "original", body, 403)
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	attestationNativeHTTP(t, store, objects, "original", body, 401)
	if got := attestationNativeCounts(t, p); got != [7]int{1, 1, 2, 1, 2, 2, 1} || objects.stages != 1 {
		t.Fatal("replay or denial repeated ingestion", got, objects.stages)
	}
}

func TestPostgresBuildAttestationNativeHTTPRollbackAndRecovery(t *testing.T) {
	for _, stage := range []string{"payload", "evidence", "evidence-audit", "evidence-job", "attestation", "attestation-audit", "attestation-job", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBuildCreationNative(t, p)
			fs, err := filesystem.New(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			objects := &countedSignatureStager{Store: fs}
			table := map[string]string{"payload": "object_payloads", "evidence": "evidence_items", "evidence-audit": "audit_chain_entries", "evidence-job": "outbox_jobs", "attestation": "build_attestations", "attestation-audit": "audit_chain_entries", "attestation-job": "outbox_jobs", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			condition := ""
			if stage == "attestation-audit" {
				condition = " WHEN(NEW.subject_type='build_attestation')"
			}
			if stage == "attestation-job" {
				condition = " WHEN(NEW.kind='verify_attestation')"
			}
			trigger := fmt.Sprintf("CREATE TRIGGER reject_native_attestation BEFORE INSERT ON %s FOR EACH ROW%s EXECUTE FUNCTION reject_native_attestation()", table, condition)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_native_attestation BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_attestation()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_native_attestation AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_attestation()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_native_attestation()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-attestation-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := attestationNativeBody(t)
			attestationNativeHTTP(t, store, objects, "failed", body, 500)
			want := [7]int{}
			if stage != "replay" && stage != "commit" {
				want[6] = 1
			}
			if got := attestationNativeCounts(t, p); got != want || objects.stages != 1 {
				t.Fatal("partial durable attestation committed", stage, got, want, objects.stages)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_attestation ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[6] != 0 {
				attestationNativeHTTP(t, store, objects, key, body, 409)
				key = "recovered"
			}
			one := attestationNativeHTTP(t, store, objects, key, body, 201)
			assertRetentionHTTPReplay(t, one, attestationNativeHTTP(t, store, objects, key, body, 201))
			want[0], want[1], want[2], want[3], want[4], want[5] = 1, 1, 2, 1, 2, 1
			if got := attestationNativeCounts(t, p); got != want || objects.stages != 2 {
				t.Fatal("recovery or replay repeated ingestion", stage, got, want, objects.stages)
			}
		})
	}
}

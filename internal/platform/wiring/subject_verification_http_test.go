package wiring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func subjectVerificationOptions(t *testing.T, store *postgres.Store, objects app.ObjectStore) httpapi.ServerOptions {
	t.Helper()
	opts, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Objects: objects}, "receipt-test-pepper", []app.ReadinessCheck{{Name: "postgres", Check: store.CheckReadiness}, {Name: "migrations", Check: func(ctx context.Context) error { return store.CheckMigrationState(ctx, "../../../migrations") }}})
	if err != nil || opts.SubjectVerification == nil || opts.DurableCommandExecutor == nil {
		t.Fatal("native generic verification composition missing", err)
	}
	return opts
}

func subjectVerificationHTTP(t *testing.T, store *postgres.Store, objects app.ObjectStore, key, body string, want int) string {
	t.Helper()
	opts := subjectVerificationOptions(t, store, objects)
	noReload := newAggregateLoadCanary(t, t.Context(), store)
	s, err := newNativeHTTPFixture(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/verify", strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || !noReload.Intact(t.Context()) || strings.Contains(w.Body.String(), "private-") || want != 200 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("generic verification status=%d want=%d canary=%t body=%s", w.Code, want, noReload.Intact(t.Context()), w.Body.String())
	}
	if want == 200 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("missing replay key")
	}
	return w.Body.String()
}

func subjectVerificationBody(kind, id string) string {
	b, err := json.Marshal(map[string]string{"subject_type": kind, "subject_id": id})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestPostgresSubjectVerificationHTTPFreshProfilesAndRestartReplay(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedSubjectVerificationScopes(t, p)
	if _, err := p.Exec(t.Context(), `UPDATE artifact_signatures SET subject_digest=$1,algorithm='cosign'WHERE id='signature'`, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	for i, tc := range []struct {
		kind, id, result, profile string
		checks                    int
	}{
		{"audit_chain", "", "passed", "audit-chain-integrity.v1", 1},
		{"build_attestation", "attestation", "passed", domain.VerificationProfileDSSEAttestationSignature, 7},
		{"artifact_signature", "signature", "limited", "artifact-signature-metadata.v1", 2},
		{"backup_manifest", "backup", "passed", "backup-manifest-consistency.v1", 2},
	} {
		body := subjectVerificationBody(tc.kind, tc.id)
		one := subjectVerificationHTTP(t, store, objects, tc.kind, body, 200)
		var e struct {
			Data domain.VerificationResult `json:"data"`
		}
		if err := json.Unmarshal([]byte(one), &e); err != nil || e.Data.Result != tc.result || e.Data.SubjectType != tc.kind || e.Data.SubjectID != tc.id || len(e.Data.Checks) != tc.checks || e.Data.Profile.ID != tc.profile {
			t.Fatal("generic dispatch changed profile", tc, err, one)
		}
		assertRetentionHTTPReplay(t, one, subjectVerificationHTTP(t, store, nil, tc.kind, body, 200))
		want := i + 1
		if dsseHTTPCounts(t, p) != [5]int{want, want, want, 0, want} {
			t.Fatal("generic receipt effects not atomic", dsseHTTPCounts(t, p))
		}
	}
	if objects.reads != 1 {
		t.Fatal("restart replay inspected payload", objects.reads)
	}
	if _, err := p.Exec(t.Context(), `UPDATE backup_manifests SET consistency_checks='[{"name":"recorded","result":"failed"}]'WHERE id='backup'`); err != nil {
		t.Fatal(err)
	}
	body := subjectVerificationBody("backup_manifest", "backup")
	subjectVerificationHTTP(t, store, nil, "failed", body, 422)
	subjectVerificationHTTP(t, store, nil, "failed", body, 409)
	if dsseHTTPCounts(t, p) != [5]int{4, 4, 4, 1, 4} {
		t.Fatal("failed verification published success", dsseHTTPCounts(t, p))
	}
}

func TestPostgresSubjectVerificationHTTPLegacyReplayChecksAllCurrentScopes(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedSubjectVerificationScopes(t, p)
	opts := subjectVerificationOptions(t, store, objects)
	a, err := opts.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
	if err != nil {
		t.Fatal(err)
	}
	first := map[string]string{}
	// Synthetic pre-upgrade completed-response fixtures exercise the historical
	// replay format. Fresh profile execution is tested separately above; these
	// fixtures intentionally have no receipt, audit or outbox side effects.
	for _, tc := range subjectScopeCases() {
		body := subjectVerificationBody(tc.kind, tc.id)
		_, _, err := opts.DurableCommandExecutor.WithBody(t.Context(), a, "POST", "/v1/verify", tc.kind, []byte(body), func(ctx context.Context) error {
			return opts.SubjectVerification.AuthorizeSubjectVerification(ctx, a, tc.kind, tc.id)
		}, func(context.Context) (int, any, error) {
			return 200, map[string]any{"id": "historical-" + tc.kind, "subject_type": tc.kind, "subject_id": tc.id, "exact_number": json.Number("9007199254740993")}, nil
		})
		if err != nil {
			t.Fatal(tc, err)
		}
		first[tc.kind] = subjectVerificationHTTP(t, store, nil, tc.kind, body, 200)
		if !strings.Contains(first[tc.kind], "9007199254740993") {
			t.Fatal("historical exact number rounded")
		}
	}
	for _, sql := range []string{
		`UPDATE evidence_items SET title=repeat('private-',1200000)`,
		`UPDATE build_attestations SET payload_ref=repeat('private-',1200000)`,
		`UPDATE artifact_signatures SET subject_digest=repeat('private-',1200000)`,
		`UPDATE release_bundles SET manifest=jsonb_build_object('private',repeat('x',9000000))`,
		`UPDATE merkle_batches SET root_hash=repeat('private-',1200000)`,
		`UPDATE backup_manifests SET consistency_checks=jsonb_build_array(jsonb_build_object('private',repeat('x',9000000)))`,
		`UPDATE dsse_trust_roots SET status='legacy_untrusted'`,
		`UPDATE object_payloads SET status='failed'`,
	} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range []struct{ kind, id string }{{"tenant", "tenant"}, {"product", "product"}, {"project", "project"}, {"release", "release"}} {
		if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type=$1,resource_id=$2 WHERE id='grant'`, grant.kind, grant.id); err != nil {
			t.Fatal(err)
		}
		for _, tc := range subjectScopeCases() {
			allowed := grant.kind == "tenant" || tc.kind == "evidence_item" || tc.kind == "build_attestation" || tc.kind == "release_bundle" && grant.kind != "project"
			want := 403
			if allowed {
				want = 200
			}
			out := subjectVerificationHTTP(t, store, nil, tc.kind, subjectVerificationBody(tc.kind, tc.id), want)
			if allowed {
				assertRetentionHTTPReplay(t, first[tc.kind], out)
			}
		}
	}
	for _, sql := range []string{`UPDATE role_bindings SET resource_id='unrelated'WHERE id='grant'`, `UPDATE role_bindings SET role='viewer',resource_type='tenant',resource_id='tenant'WHERE id='grant'`, `DELETE FROM role_bindings WHERE id='grant'`} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
		for _, tc := range subjectScopeCases() {
			subjectVerificationHTTP(t, store, nil, tc.kind, subjectVerificationBody(tc.kind, tc.id), 403)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range subjectScopeCases() {
		subjectVerificationHTTP(t, store, nil, tc.kind, subjectVerificationBody(tc.kind, tc.id), 401)
	}
	if objects.reads != 0 || dsseHTTPCounts(t, p) != [5]int{0, 0, 9, 0, 0} {
		t.Fatal("legacy replay inspected or wrote business effects", objects.reads, dsseHTTPCounts(t, p))
	}
}

func TestPostgresSubjectVerificationHTTPFailuresRollbackAllEffects(t *testing.T) {
	for _, stage := range []string{"result", "audit", "outbox", "replay", "commit"} {
		t.Run(stage, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedSubjectVerificationScopes(t, p)
			table := map[string]string{"result": "verification_results", "audit": "audit_chain_entries", "outbox": "outbox_jobs", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
			trigger := fmt.Sprintf("CREATE TRIGGER reject_subject BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_subject()", table)
			if stage == "replay" {
				trigger = `CREATE TRIGGER reject_subject BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_subject()`
			}
			if stage == "commit" {
				trigger = `CREATE CONSTRAINT TRIGGER reject_subject AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_subject()`
			}
			if _, err := p.Exec(t.Context(), `CREATE FUNCTION reject_subject()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-subject-write-failure';END$$;`+trigger); err != nil {
				t.Fatal(err)
			}
			body := subjectVerificationBody("backup_manifest", "backup")
			subjectVerificationHTTP(t, store, nil, "failed", body, 500)
			want := [5]int{}
			if stage != "replay" && stage != "commit" {
				want[3] = 1
			}
			if dsseHTTPCounts(t, p) != want {
				t.Fatal("partial generic verification success", dsseHTTPCounts(t, p), want)
			}
			if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_subject ON "+table); err != nil {
				t.Fatal(err)
			}
			key := "failed"
			if want[3] == 1 {
				subjectVerificationHTTP(t, store, nil, key, body, 409)
				key = "recovered"
			}
			subjectVerificationHTTP(t, store, nil, key, body, 200)
			want[0], want[1], want[2], want[4] = 1, 1, 1, 1
			if dsseHTTPCounts(t, p) != want {
				t.Fatal("generic recovery effects", dsseHTTPCounts(t, p), want)
			}
		})
	}
}

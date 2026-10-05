package wiring

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

type nativeRegistrationCase struct{ kind, path, table, body string }

func nativeRegistrationCases() []nativeRegistrationCase {
	return []nativeRegistrationCase{
		{"artifact", "/v1/artifacts", "artifacts", `{"name":" Original ","media_type":" application/octet-stream ","digest":"sha256:` + strings.Repeat("c", 64) + `","size":9007199254740993}`},
		{"image", "/v1/container-images", "container_images", `{"artifact_id":" artifact ","repository":" registry.example.test/api ","tag":" v1 ","digest":"sha256:` + strings.Repeat("a", 64) + `","platform":" linux/amd64 "}`},
	}
}
func (c nativeRegistrationCase) guard(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) error {
	if c.kind == "artifact" {
		return o.ArtifactCommands.AuthorizeArtifactRegistration(ctx, a, releaseapp.RegisterArtifactInput{Name: "Original", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("c", 64), Size: 9007199254740993})
	}
	return o.ContainerImageCommands.AuthorizeContainerImageRegistration(ctx, a, releaseapp.RegisterContainerImageInput{ArtifactID: "artifact", Repository: "registry.example.test/api", Tag: "v1", Digest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64"})
}

func (c nativeRegistrationCase) create(ctx context.Context, o httpapi.ServerOptions, a domain.Actor) (int, any, error) {
	if c.kind == "artifact" {
		v, err := o.ArtifactCommands.RegisterArtifact(ctx, a, releaseapp.RegisterArtifactInput{Name: "Original", MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("c", 64), Size: 9007199254740993})
		return 201, domain.Artifact(v), err
	}
	v, err := o.ContainerImageCommands.RegisterContainerImage(ctx, a, releaseapp.RegisterContainerImageInput{ArtifactID: "artifact", Repository: "registry.example.test/api", Tag: "v1", Digest: "sha256:" + strings.Repeat("a", 64), Platform: "linux/amd64"})
	return 201, domain.ContainerImage(v), err
}

func registrationNativeHTTP(t *testing.T, store *postgres.Store, c nativeRegistrationCase, key, body string, want int) string {
	t.Helper()
	o := subjectVerificationOptions(t, store, nil)
	noReload := &decisionHTTPNoReloadStore{}
	l, err := app.NewLedgerWithContext(t.Context(), app.Config{Store: noReload, UnitOfWork: store})
	if err != nil {
		t.Fatal(err)
	}
	s, err := httpapi.NewServerWithOptionsContext(t.Context(), l, o)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", c.path, strings.NewReader(body)).WithContext(t.Context())
	r.Header.Set("Authorization", "Bearer evysso_receipt_fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want || noReload.loads != 1 || strings.Contains(w.Body.String(), "private-") || want != 201 && strings.Contains(w.Body.String(), `"data"`) {
		t.Fatalf("native %s status=%d want=%d loads=%d: %s", c.kind, w.Code, want, noReload.loads, w.Body.String())
	}
	if want == 201 && w.Header().Get("Idempotency-Key") != key {
		t.Fatal("registration lost replay key")
	}
	if want >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatal("registration lost Problem Details")
	}
	return w.Body.String()
}
func registrationNativeCounts(t *testing.T, p *pgxpool.Pool) [6]int {
	t.Helper()
	var n [6]int
	if err := p.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM artifacts),(SELECT count(*)FROM container_images),(SELECT count(*)FROM audit_chain_entries),(SELECT count(*)FROM outbox_jobs),(SELECT count(*)FROM idempotency_records WHERE state='completed'),(SELECT count(*)FROM idempotency_records WHERE state='failed')`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4], &n[5]); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPostgresArtifactImageRegistrationNativeReplayAndCurrentAuthority(t *testing.T) {
	for _, c := range nativeRegistrationCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBuildCreationNative(t, p)
			one := registrationNativeHTTP(t, store, c, "original", c.body, 201)
			var e struct {
				Data map[string]json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal([]byte(one), &e); err != nil {
				t.Fatal(err)
			}
			var id string
			if err := json.Unmarshal(e.Data["id"], &id); err != nil || id == "" {
				t.Fatal("registration lost identity", one, err)
			}
			if string(e.Data["tenant_id"]) != `"tenant"` {
				t.Fatal("registration lost tenant", one)
			}
			if c.kind == "artifact" {
				if string(e.Data["name"]) != `"Original"` || string(e.Data["media_type"]) != `"application/octet-stream"` || string(e.Data["size"]) != "9007199254740993" {
					t.Fatal("artifact normalization or exact size changed", one)
				}
				if _, err := p.Exec(t.Context(), `UPDATE build_runs SET outputs=outputs||jsonb_build_array(jsonb_build_object('artifact_id',$1::text,'digest','sha256:'||repeat('c',64)))WHERE id='linked-build'`, id); err != nil {
					t.Fatal(err)
				}
			} else if string(e.Data["artifact_id"]) != `"artifact"` || string(e.Data["repository"]) != `"registry.example.test/api"` || string(e.Data["tag"]) != `"v1"` || string(e.Data["platform"]) != `"linux/amd64"` {
				t.Fatal("image normalization changed", one)
			}
			var actor, kind string
			if err := p.QueryRow(t.Context(), `SELECT actor_id,actor_type FROM audit_chain_entries WHERE subject_id=$1`, id).Scan(&actor, &kind); err != nil || actor != "user" || kind != "human_user" {
				t.Fatal("registration lost audit actor", actor, kind, err)
			}
			assertRetentionHTTPReplay(t, one, registrationNativeHTTP(t, store, c, "original", c.body, 201))
			registrationNativeHTTP(t, store, c, "original", c.body+" ", 409)
			reuse := strings.Replace(c.body, `" Original "`, `"Ignored"`, 1)
			if c.kind == "image" {
				reuse = strings.Replace(c.body, `" v1 "`, `"Ignored"`, 1)
			}
			assertRetentionHTTPReplay(t, one, registrationNativeHTTP(t, store, c, "reuse", reuse, 201))
			o := subjectVerificationOptions(t, store, nil)
			a, err := o.Authenticator.Authenticate(t.Context(), "evysso_receipt_fixture")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := o.DurableCommandExecutor.WithBody(t.Context(), a, "POST", c.path, "historical", []byte(c.body), func(ctx context.Context) error { return c.guard(ctx, o, a) }, func(context.Context) (int, any, error) {
				return 201, map[string]any{"id": "historical", "exact_number": json.Number("9007199254740993")}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := p.Exec(t.Context(), `UPDATE products SET name=repeat('private-',1200000);UPDATE projects SET name=repeat('private-',1200000);UPDATE artifacts SET name=repeat('private-',1200000),media_type=repeat('private-',1200000);UPDATE container_images SET tag=repeat('private-',1200000),platform=repeat('private-',1200000)`); err != nil {
				t.Fatal(err)
			}
			assertRetentionHTTPReplay(t, one, registrationNativeHTTP(t, store, c, "original", c.body, 201))
			if out := registrationNativeHTTP(t, store, c, "historical", c.body, 201); !strings.Contains(out, "9007199254740993") {
				t.Fatal("historical replay rounded number", out)
			}
			registrationNativeHTTP(t, store, c, "oversized-fresh", c.body, 409)
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
				registrationNativeHTTP(t, store, c, "original", c.body, want)
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET resource_type='tenant',resource_id='tenant',role='tenant_admin'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			failed := 1
			if c.kind == "image" {
				if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest='sha256:'||repeat('d',64)WHERE id='artifact'`); err != nil {
					t.Fatal(err)
				}
				assertRetentionHTTPReplay(t, one, registrationNativeHTTP(t, store, c, "original", c.body, 201))
				registrationNativeHTTP(t, store, c, "digest-mismatch", c.body, 404)
				failed++
				if _, err := p.Exec(t.Context(), `UPDATE artifacts SET digest='sha256:'||repeat('a',64),tenant_id='other'WHERE id='artifact'`); err != nil {
					t.Fatal(err)
				}
				registrationNativeHTTP(t, store, c, "original", c.body, 404)
				if _, err := p.Exec(t.Context(), `UPDATE artifacts SET tenant_id='tenant'WHERE id='artifact'`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := p.Exec(t.Context(), `UPDATE role_bindings SET role='viewer'WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			registrationNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `DELETE FROM role_bindings WHERE id='grant'`); err != nil {
				t.Fatal(err)
			}
			registrationNativeHTTP(t, store, c, "original", c.body, 403)
			if _, err := p.Exec(t.Context(), `UPDATE sso_sessions SET revoked_at=now()WHERE id='operator-session'`); err != nil {
				t.Fatal(err)
			}
			registrationNativeHTTP(t, store, c, "original", c.body, 401)
			want := [6]int{2, 0, 1, 0, 3, failed}
			if c.kind == "artifact" {
				want[0]++
			} else {
				want[1]++
			}
			if got := registrationNativeCounts(t, p); got != want {
				t.Fatal("replay or denial wrote effects", got, want)
			}
		})
	}
}

func TestPostgresArtifactImageRegistrationNativeRollbackAndRecovery(t *testing.T) {
	for _, c := range nativeRegistrationCases() {
		t.Run(c.kind, func(t *testing.T) {
			store, p := openHTMLReportWiringStore(t)
			seedBuildCreationNative(t, p)
			for n, stage := range []string{"record", "audit", "replay", "commit"} {
				t.Run(stage, func(t *testing.T) {
					baseline := registrationNativeCounts(t, p)
					table := c.table
					if stage != "record" {
						table = map[string]string{"audit": "audit_chain_entries", "replay": "idempotency_records", "commit": "audit_chain_entries"}[stage]
					}
					trigger := fmt.Sprintf("CREATE TRIGGER reject_native_registration BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION reject_native_registration()", table)
					if stage == "replay" {
						trigger = `CREATE TRIGGER reject_native_registration BEFORE UPDATE ON idempotency_records FOR EACH ROW WHEN(NEW.state='completed')EXECUTE FUNCTION reject_native_registration()`
					}
					if stage == "commit" {
						trigger = `CREATE CONSTRAINT TRIGGER reject_native_registration AFTER INSERT ON audit_chain_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_native_registration()`
					}
					if _, err := p.Exec(t.Context(), `CREATE OR REPLACE FUNCTION reject_native_registration()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private-registration-write-failure';END$$;`+trigger); err != nil {
						t.Fatal(err)
					}
					body := strings.Replace(c.body, strings.Repeat("c", 64), strings.Repeat(fmt.Sprintf("%x", n+5), 64), 1)
					if c.kind == "image" {
						body = strings.Replace(c.body, "registry.example.test/api", "registry.example.test/"+stage, 1)
					}
					key := "failed-" + stage
					registrationNativeHTTP(t, store, c, key, body, 500)
					want := baseline
					if stage == "record" || stage == "audit" {
						want[5]++
					}
					if got := registrationNativeCounts(t, p); got != want {
						t.Fatal("partial registration committed", stage, got, want)
					}
					if _, err := p.Exec(t.Context(), "DROP TRIGGER reject_native_registration ON "+table); err != nil {
						t.Fatal(err)
					}
					if want[5] > baseline[5] {
						registrationNativeHTTP(t, store, c, key, body, 409)
						key = "recovered-" + stage
					}
					one := registrationNativeHTTP(t, store, c, key, body, 201)
					assertRetentionHTTPReplay(t, one, registrationNativeHTTP(t, store, c, key, body, 201))
					if c.kind == "artifact" {
						want[0]++
					} else {
						want[1]++
					}
					want[2]++
					want[4]++
					if got := registrationNativeCounts(t, p); got != want {
						t.Fatal("recovery duplicated effects", got, want)
					}
				})
			}
		})
	}
}

func TestPostgresContainerImageRegistrationIndexCapacityIsSafeValidation(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	var repository strings.Builder
	for n := 0; n < 180; n++ {
		fmt.Fprintf(&repository, "%x", sha256.Sum256([]byte(fmt.Sprintf("repository-%d", n))))
	}
	body := `{"repository":"` + repository.String() + `","digest":"sha256:` + strings.Repeat("a", 64) + `"}`
	c := nativeRegistrationCases()[1]
	baseline := registrationNativeCounts(t, p)
	registrationNativeHTTP(t, store, c, "index-capacity", body, 400)
	want := baseline
	want[5]++
	if got := registrationNativeCounts(t, p); got != want {
		t.Fatal("invalid indexed repository committed effects", got, want)
	}
}

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

type fakeStateLoader struct {
	state app.PersistedState
	ok    bool
	err   error
}

func (f fakeStateLoader) LoadState(context.Context) (app.PersistedState, bool, error) {
	return f.state, f.ok, f.err
}

type fakeObjectGetter struct {
	object app.Object
	err    error
}

func (f fakeObjectGetter) Get(context.Context, string) (app.Object, error) {
	if f.err != nil {
		return app.Object{}, f.err
	}
	return f.object, nil
}

func TestProcessJobVerifiesConfiguredJobState(t *testing.T) {
	job := postgres.ClaimedJob{
		ID:          "job_test",
		TenantID:    "ten_test",
		Kind:        "verify_subject",
		SubjectType: "release_bundle",
		SubjectID:   "rb_test",
		Payload:     map[string]any{"result_id": "vr_test", "payload_ref": "object://tenants/ten_test/payloads/raw-secret-name"},
	}
	state := app.PersistedState{Verifications: map[string]domain.VerificationResult{
		"vr_test": {ID: "vr_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "rb_test", Result: "passed", VerifiedAt: time.Now().UTC()},
	}}
	if err := processJob(context.Background(), fakeStateLoader{state: state, ok: true}, job); err != nil {
		t.Fatalf("process configured verification job: %v", err)
	}
}

func TestProcessJobWithObjectsVerifiesTenantPrefixedPayload(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX"}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID:        "job_test",
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process object-backed job: %v", err)
	}
}

func TestProcessJobWithObjectsFailsSafelyForPayloadProblems(t *testing.T) {
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	base := postgres.ClaimedJob{
		ID:        "job_test",
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "tenants/ten_test/payloads/raw-secret-name", "payload_hash": digestBytes([]byte("ok"))},
	}
	tests := []struct {
		name    string
		job     postgres.ClaimedJob
		objects jobObjectGetter
		want    string
	}{
		{
			name:    "wrong tenant prefix",
			job:     postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "sbom_test", Payload: map[string]any{"payload_ref": "tenants/other/payloads/raw-secret-name"}},
			objects: fakeObjectGetter{},
			want:    "tenant-prefixed",
		},
		{
			name: "missing object store",
			job:  base,
			want: "object store is not configured",
		},
		{
			name:    "object read failure",
			job:     base,
			objects: fakeObjectGetter{err: errors.New("backend leaked secret")},
			want:    "read outbox payload object",
		},
		{
			name:    "object tenant mismatch",
			job:     base,
			objects: fakeObjectGetter{object: app.Object{TenantID: "other", Bytes: []byte("ok"), Digest: digestBytes([]byte("ok"))}},
			want:    "tenant mismatch",
		},
		{
			name:    "metadata digest mismatch",
			job:     base,
			objects: fakeObjectGetter{object: app.Object{TenantID: "ten_test", Bytes: []byte("ok"), Digest: digestBytes([]byte("other"))}},
			want:    "metadata digest mismatch",
		},
		{
			name:    "byte digest mismatch",
			job:     base,
			objects: fakeObjectGetter{object: app.Object{TenantID: "ten_test", Bytes: []byte("other")}},
			want:    "digest mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, tt.objects, tt.job)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "raw-secret-name") || strings.Contains(err.Error(), "backend leaked secret") {
				t.Fatalf("error leaked payload details: %v", err)
			}
		})
	}
}

func TestProcessJobWithObjectsRejectsOversizedPayload(t *testing.T) {
	t.Setenv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", "2")
	body := []byte("large")
	hash := digestBytes(body)
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	object := app.Object{TenantID: "ten_test", Digest: hash, Bytes: body}
	err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, fakeObjectGetter{object: object}, job)
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("err=%v", err)
	}
}

func TestProcessJobFailsSafelyWhenDurableStateIsMissing(t *testing.T) {
	job := postgres.ClaimedJob{
		ID:          "job_test",
		TenantID:    "ten_test",
		Kind:        "parse_sbom",
		SubjectType: "sbom",
		SubjectID:   "sbom_test",
		Payload:     map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom/raw-secret-name"},
	}
	err := processJob(context.Background(), fakeStateLoader{state: app.PersistedState{}, ok: true}, job)
	if err == nil {
		t.Fatal("expected recognized unhandled job to fail closed")
	}
	if !strings.Contains(err.Error(), "parsed sbom is not available") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "raw-secret-name") || strings.Contains(err.Error(), job.SubjectID) {
		t.Fatalf("job error leaked payload or subject: %v", err)
	}
}

func TestProcessJobRejectsUnsupportedKinds(t *testing.T) {
	err := processJob(context.Background(), fakeStateLoader{state: app.PersistedState{}, ok: true}, postgres.ClaimedJob{Kind: "unknown", Payload: map[string]any{"token": "secret"}})
	if err == nil {
		t.Fatal("expected unsupported job kind to fail")
	}
	if !strings.Contains(err.Error(), "unsupported outbox job kind") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unexpected unsupported job error: %v", err)
	}
}

func TestProcessJobRecognizedKindsUseDurableTenantScopedState(t *testing.T) {
	now := time.Now().UTC()
	state := app.PersistedState{
		SBOMs: map[string]domain.SBOM{
			"sbom_1": {ID: "sbom_1", TenantID: "ten_1"},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_1": {ID: "scan_1", TenantID: "ten_1"},
		},
		Contracts: map[string]domain.OpenAPIContract{
			"contract_1": {ID: "contract_1", TenantID: "ten_1", Hash: "sha256:contract"},
		},
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_1": {ID: "vex_1", TenantID: "ten_1"},
		},
		Bundles: map[string]domain.ReleaseBundle{
			"bundle_1": {ID: "bundle_1", TenantID: "ten_1", ManifestHash: "sha256:bundle", SignatureRefs: []string{"sig_1"}},
		},
		BuildAttestations: map[string]domain.BuildAttestation{
			"att_1": {ID: "att_1", TenantID: "ten_1", PayloadHash: "sha256:att", VerificationStatus: "structurally_valid", CreatedAt: now},
		},
	}
	tests := []postgres.ClaimedJob{
		{TenantID: "ten_1", Kind: "parse_sbom", SubjectID: "sbom_1"},
		{TenantID: "ten_1", Kind: "parse_vulnerability_scan", SubjectID: "scan_1"},
		{TenantID: "ten_1", Kind: "parse_openapi_contract", SubjectID: "contract_1", Payload: map[string]any{"payload_hash": "sha256:contract"}},
		{TenantID: "ten_1", Kind: "parse_vex", SubjectID: "vex_1"},
		{TenantID: "ten_1", Kind: "sign_bundle", SubjectID: "bundle_1", Payload: map[string]any{"payload_hash": "sha256:bundle"}},
		{TenantID: "ten_1", Kind: "verify_attestation", SubjectID: "att_1", Payload: map[string]any{"payload_hash": "sha256:att"}},
	}
	for _, job := range tests {
		t.Run(job.Kind, func(t *testing.T) {
			if err := processJob(context.Background(), fakeStateLoader{state: state, ok: true}, job); err != nil {
				t.Fatalf("process %s: %v", job.Kind, err)
			}
		})
	}
}

func TestProcessJobFailsClosedForStateLoadAndTenantMismatches(t *testing.T) {
	if err := processJob(context.Background(), nil, postgres.ClaimedJob{}); err == nil || !strings.Contains(err.Error(), "requires durable state") {
		t.Fatalf("nil state err=%v", err)
	}
	if err := processJob(context.Background(), fakeStateLoader{err: errors.New("database secret")}, postgres.ClaimedJob{}); err == nil || err.Error() != "load durable state for outbox job" {
		t.Fatalf("state load err=%v", err)
	}
	if err := processJob(context.Background(), fakeStateLoader{ok: false}, postgres.ClaimedJob{}); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("missing state err=%v", err)
	}
	state := app.PersistedState{Contracts: map[string]domain.OpenAPIContract{
		"contract_1": {ID: "contract_1", TenantID: "other", Hash: "sha256:contract"},
	}}
	err := processJob(context.Background(), fakeStateLoader{state: state, ok: true}, postgres.ClaimedJob{TenantID: "ten_1", Kind: "parse_openapi_contract", SubjectID: "contract_1"})
	if err == nil || !strings.Contains(err.Error(), "parsed openapi contract is not available") || strings.Contains(err.Error(), "contract_1") {
		t.Fatalf("tenant mismatch err=%v", err)
	}
}

func TestWorkerHelpersValidatePayloadHashAndEnv(t *testing.T) {
	job := postgres.ClaimedJob{Payload: map[string]any{"payload_hash": " sha256:abc ", "ignored": 12}}
	if got := payloadString(job, "payload_hash"); got != "sha256:abc" {
		t.Fatalf("payloadString = %q", got)
	}
	if err := requirePayloadHash(job, "sha256:abc"); err != nil {
		t.Fatalf("matching payload hash: %v", err)
	}
	if err := requirePayloadHash(job, "sha256:def"); err == nil || !strings.Contains(err.Error(), "payload hash") {
		t.Fatalf("mismatch err=%v", err)
	}
	if err := requirePayloadHash(postgres.ClaimedJob{}, "sha256:def"); err != nil {
		t.Fatalf("missing wanted hash should be ignored: %v", err)
	}

	t.Setenv("EVYDENCE_WORKER_TEST_ENV", " value ")
	if got := envDefault("EVYDENCE_WORKER_TEST_ENV", "fallback"); got != "value" {
		t.Fatalf("envDefault configured = %q", got)
	}
	if got := envDefault("EVYDENCE_WORKER_MISSING_ENV", "fallback"); got != "fallback" {
		t.Fatalf("envDefault fallback = %q", got)
	}
	t.Setenv("EVYDENCE_WORKER_TEST_DURATION", "250ms")
	if got := durationEnv("EVYDENCE_WORKER_TEST_DURATION", time.Second); got != 250*time.Millisecond {
		t.Fatalf("durationEnv configured = %s", got)
	}
	t.Setenv("EVYDENCE_WORKER_TEST_DURATION", "-1s")
	if got := durationEnv("EVYDENCE_WORKER_TEST_DURATION", time.Second); got != time.Second {
		t.Fatalf("durationEnv fallback = %s", got)
	}
	t.Setenv("EVYDENCE_WORKER_TEST_INT", "7")
	if got := intEnv("EVYDENCE_WORKER_TEST_INT", 10); got != 7 {
		t.Fatalf("intEnv configured = %d", got)
	}
	t.Setenv("EVYDENCE_WORKER_TEST_INT", "0")
	if got := intEnv("EVYDENCE_WORKER_TEST_INT", 10); got != 10 {
		t.Fatalf("intEnv fallback = %d", got)
	}
}

func TestRunRequiresDatabaseURLAndWrapsOpenFailure(t *testing.T) {
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
		t.Fatalf("missing database err=%v", err)
	}
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://invalid-host.invalid/evydence")
	t.Setenv("EVYDENCE_SKIP_MIGRATIONS", "true")
	if err := run(); err == nil {
		t.Fatal("expected postgres open failure")
	}
}

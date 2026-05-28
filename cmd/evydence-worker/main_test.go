package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

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

type fakeStateStore struct {
	state app.PersistedState
	saved app.PersistedState
	ok    bool
	err   error
}

func (f *fakeStateStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	return f.state, f.ok, f.err
}

func (f *fakeStateStore) SaveState(_ context.Context, state app.PersistedState) error {
	f.saved = state
	return nil
}

type fakeObjectGetter struct {
	object  app.Object
	err     error
	wantKey string
}

func (f fakeObjectGetter) Get(_ context.Context, key string) (app.Object, error) {
	if f.err != nil {
		return app.Object{}, f.err
	}
	if f.wantKey != "" && key != f.wantKey {
		return app.Object{}, errors.New("unexpected object key")
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

func TestProcessJobWithObjectsPersistsParserDerivedFields(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	store := &fakeStateStore{
		ok: true,
		state: app.PersistedState{SBOMs: map[string]domain.SBOM{
			"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
		}},
	}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process object-backed job: %v", err)
	}
	updated := store.saved.SBOMs["sbom_test"]
	if updated.SpecVersion != "1.6" || updated.ComponentCount != 1 || len(updated.Components) != 1 || updated.Components[0].Name != "api" {
		t.Fatalf("saved sbom = %#v", updated)
	}
}

func TestProcessJobWithObjectsRequiresWritableStateForParserSideEffects(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, fakeObjectGetter{object: object}, job)
	if err == nil || !strings.Contains(err.Error(), "writable state") {
		t.Fatalf("err=%v", err)
	}
}

func TestProcessJobRejectsUnsupportedParserVersion(t *testing.T) {
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"parser_version": "cyclonedx-json.v0.0.1"},
	}
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	err := processJob(context.Background(), fakeStateLoader{state: state, ok: true}, job)
	if err == nil || !strings.Contains(err.Error(), "unsupported outbox parser version") {
		t.Fatalf("err=%v", err)
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
		Payload:   map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, fakeObjectGetter{object: object, wantKey: "tenants/ten_test/payloads/sbom.json"}, job); err != nil {
		t.Fatalf("process object-backed job: %v", err)
	}
}

func TestProcessJobWithObjectsParsesPayloadAndChecksDurableState(t *testing.T) {
	now := time.Now().UTC()
	attestationBody := dsseEnvelopeForTest(t, "sha256:"+strings.Repeat("a", 64))
	tests := []struct {
		name   string
		body   []byte
		job    postgres.ClaimedJob
		state  app.PersistedState
		object app.Object
	}{
		{
			name: "sbom component count",
			body: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"},{"name":"worker"}]}`),
			job:  postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "sbom_test"},
			state: app.PersistedState{SBOMs: map[string]domain.SBOM{
				"sbom_test": {ID: "sbom_test", TenantID: "ten_test", SpecVersion: "1.6", ComponentCount: 2},
			}},
		},
		{
			name: "vulnerability scan summary",
			body: []byte(`{"scanner":"grype","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[{"vulnerability":"CVE-1","severity":"critical"},{"vulnerability":"CVE-2","severity":"high"}]}`),
			job:  postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_vulnerability_scan", SubjectID: "scan_test"},
			state: app.PersistedState{Scans: map[string]domain.VulnerabilityScan{
				"scan_test": {ID: "scan_test", TenantID: "ten_test", Scanner: "grype", TargetRef: "pkg:oci/api", Summary: map[string]int{"critical": 1, "high": 1}, Findings: []domain.VulnerabilityFinding{{ID: "vf_1"}, {ID: "vf_2"}}},
			}},
		},
		{
			name: "openapi contract path count",
			body: []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"1"},"paths":{"/v1/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`),
			job:  postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_openapi_contract", SubjectID: "oas_test"},
			state: app.PersistedState{Contracts: map[string]domain.OpenAPIContract{
				"oas_test": {ID: "oas_test", TenantID: "ten_test", PathCount: 1},
			}},
		},
		{
			name: "openvex statement count",
			body: []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed","impact_statement":"fixed","action_statement":"none"}]}`),
			job:  postgres.ClaimedJob{TenantID: "ten_test", Kind: "parse_vex", SubjectID: "vex_test"},
			state: app.PersistedState{VEXDocuments: map[string]domain.VEXDocument{
				"vex_test": {ID: "vex_test", TenantID: "ten_test", Format: "openvex", Author: "security@example.test", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
			}},
		},
		{
			name: "dsse attestation subject digest",
			body: attestationBody,
			job:  postgres.ClaimedJob{TenantID: "ten_test", Kind: "verify_attestation", SubjectID: "att_test"},
			state: app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{
				"att_test": {ID: "att_test", TenantID: "ten_test", PayloadHash: digestBytes(attestationBody), SubjectDigests: []string{"sha256:" + strings.Repeat("a", 64)}, VerificationStatus: "structurally_valid", CreatedAt: now},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := digestBytes(tt.body)
			tt.job.Payload = map[string]any{"payload_ref": "tenants/ten_test/payloads/replay.json", "payload_hash": hash}
			tt.object = app.Object{Key: "tenants/ten_test/payloads/replay.json", TenantID: "ten_test", Digest: hash, Bytes: tt.body}
			if tt.job.Kind == "parse_openapi_contract" {
				contract := tt.state.Contracts[tt.job.SubjectID]
				contract.Hash = hash
				tt.state.Contracts[tt.job.SubjectID] = contract
			}
			store := &fakeStateStore{state: tt.state, ok: true}
			if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: tt.object}, tt.job); err != nil {
				t.Fatalf("process replay payload: %v", err)
			}
		})
	}
}

func TestProcessJobWithObjectsFailsSafelyForParserMismatches(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"api"},{"name":"worker"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "tenants/ten_test/payloads/raw-secret-name", "payload_hash": hash},
	}
	state := app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test", ComponentCount: 1},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/raw-secret-name", TenantID: "ten_test", Digest: hash, Bytes: body}
	err := processJobWithObjects(context.Background(), fakeStateLoader{state: state, ok: true}, fakeObjectGetter{object: object}, job)
	if err == nil || !strings.Contains(err.Error(), "replayed sbom payload does not match durable state") {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), "raw-secret-name") || strings.Contains(err.Error(), string(body)) {
		t.Fatalf("error leaked payload details: %v", err)
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

func TestReplayMergeHelpersCoverParserSideEffects(t *testing.T) {
	sbom, changed := mergeReplayedSBOM(domain.SBOM{}, replayedSBOM{
		SpecVersion:    "1.6",
		ComponentCount: 1,
		Components:     []domain.SBOMComponent{{Name: "api"}},
	})
	if !changed || sbom.SpecVersion != "1.6" || sbom.ComponentCount != 1 || len(sbom.Components) != 1 {
		t.Fatalf("merged sbom = %#v changed=%v", sbom, changed)
	}
	if _, changed := mergeReplayedSBOM(sbom, replayedSBOM{SpecVersion: "1.6"}); changed {
		t.Fatal("complete sbom should not be changed")
	}

	scan, changed := mergeReplayedVulnerabilityScan(domain.VulnerabilityScan{}, replayedVulnerabilityScan{
		Scanner:   "grype",
		TargetRef: "pkg:oci/api",
		Summary:   map[string]int{"high": 1},
		Findings:  []domain.VulnerabilityFinding{{ID: "finding_1", Severity: "high"}},
	})
	if !changed || scan.Scanner != "grype" || scan.TargetRef == "" || scan.Summary["high"] != 1 || len(scan.Findings) != 1 {
		t.Fatalf("merged scan = %#v changed=%v", scan, changed)
	}
	scan.Summary["high"] = 2
	if err := verifyReplayedVulnerabilityScan(replayedVulnerabilityScan{Scanner: "grype", TargetRef: "pkg:oci/api", Summary: map[string]int{"high": 1}}, scan); err == nil {
		t.Fatal("expected vulnerability scan summary mismatch")
	}

	vex, changed := mergeReplayedVEX(domain.VEXDocument{}, replayedVEX{Author: "security@example.test", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}})
	if !changed || vex.Author == "" || vex.StatementCount != 1 || vex.StatusSummary["fixed"] != 1 {
		t.Fatalf("merged vex = %#v changed=%v", vex, changed)
	}
	if err := verifyReplayedVEX(replayedVEX{Author: "other", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}}, vex); err == nil {
		t.Fatal("expected vex author mismatch")
	}

	contract, changed := mergeReplayedOpenAPIContract(domain.OpenAPIContract{}, replayedOpenAPIContract{
		PathCount:  1,
		Operations: []domain.OpenAPIOperation{{Path: "/v1/test", Method: "get"}},
	})
	if !changed || contract.PathCount != 1 || len(contract.Operations) != 1 {
		t.Fatalf("merged contract = %#v changed=%v", contract, changed)
	}
	if err := verifyReplayedOpenAPIContract([]byte("raw"), replayedOpenAPIContract{PathCount: 2}, contract); err == nil {
		t.Fatal("expected openapi path-count mismatch")
	}

	raw := dsseEnvelopeForTest(t, "sha256:"+strings.Repeat("a", 64))
	attestation, changed := mergeReplayedAttestation(domain.BuildAttestation{}, replayedAttestation{
		PayloadType:    "application/vnd.in-toto+json",
		PredicateType:  "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{"sha256:" + strings.Repeat("a", 64)},
		SignatureCount: 1,
		BuilderID:      "github-actions",
		BuildType:      "test",
		MaterialsCount: 2,
	}, raw)
	if !changed || attestation.PayloadHash == "" || attestation.PayloadSize == 0 || attestation.PredicateType == "" || len(attestation.SubjectDigests) != 1 || attestation.SignatureCount != 1 || attestation.BuilderID == "" || attestation.BuildType == "" || attestation.MaterialsCount != 2 {
		t.Fatalf("merged attestation = %#v changed=%v", attestation, changed)
	}
	if err := verifyReplayedAttestation(raw, replayedAttestation{PredicateType: "other", SubjectDigests: attestation.SubjectDigests}, attestation); err == nil {
		t.Fatal("expected attestation predicate mismatch")
	}

	if operationForMethod(&openapi3.PathItem{Get: &openapi3.Operation{}}, "get") == nil || operationForMethod(&openapi3.PathItem{Trace: &openapi3.Operation{}}, "trace") == nil || operationForMethod(&openapi3.PathItem{}, "unknown") != nil {
		t.Fatal("operationForMethod did not route methods as expected")
	}
	if cloned := cloneIntMap(map[string]int{"high": 1}); cloned["high"] != 1 {
		t.Fatalf("cloneIntMap = %#v", cloned)
	}
	if cloneIntMap(nil) != nil {
		t.Fatal("nil cloneIntMap should stay nil")
	}
	if got, ok := nestedString(map[string]any{"outer": map[string]any{"inner": "value"}}, "outer", "inner"); !ok || got != "value" {
		t.Fatalf("nestedString = %q %v", got, ok)
	}
	if equalStringSets([]string{"b", "a"}, []string{"a", "b"}) != true || equalStringSets([]string{"a"}, []string{"b"}) != false {
		t.Fatal("equalStringSets mismatch")
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

func TestOpenObjectStoreSelectsFilesystemAndRejectsUnsupportedBackend(t *testing.T) {
	root := t.TempDir()
	t.Setenv("EVYDENCE_OBJECT_STORE", "filesystem")
	t.Setenv("EVYDENCE_OBJECT_DIR", filepath.Join(root, "objects"))
	store, description, err := openObjectStore(context.Background())
	if err != nil {
		t.Fatalf("open filesystem object store: %v", err)
	}
	if store == nil || !strings.Contains(description, "filesystem root") || !strings.Contains(description, "objects") {
		t.Fatalf("filesystem object store description=%q store=%T", description, store)
	}

	t.Setenv("EVYDENCE_OBJECT_STORE", "memory")
	if store, description, err := openObjectStore(context.Background()); err == nil || store != nil || description != "" || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported backend store=%T description=%q err=%v", store, description, err)
	}
}

func TestOpenObjectStoreRejectsIncompleteS3ConfigurationWithoutSecretsInError(t *testing.T) {
	t.Setenv("EVYDENCE_OBJECT_STORE", "s3")
	t.Setenv("EVYDENCE_S3_ENDPOINT", "")
	t.Setenv("EVYDENCE_S3_ACCESS_KEY_ID", "access-key")
	t.Setenv("EVYDENCE_S3_SECRET_ACCESS_KEY", "super-secret")
	t.Setenv("EVYDENCE_S3_BUCKET", "")
	_, _, err := openObjectStore(context.Background())
	if err == nil {
		t.Fatal("expected incomplete S3 configuration to fail")
	}
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), os.Getenv("EVYDENCE_S3_ACCESS_KEY_ID")) {
		t.Fatalf("S3 configuration error leaked credential material: %v", err)
	}
}

func dsseEnvelopeForTest(t *testing.T, digest string) []byte {
	t.Helper()
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": []map[string]any{{
			"name":   "api",
			"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")},
		}},
		"predicate": map[string]any{"builder": map[string]string{"id": "github-actions"}, "buildType": "test", "materials": []any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"sig": "abc"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/wiring"
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
	state               app.PersistedState
	saved               app.PersistedState
	ok                  bool
	err                 error
	dependencyTerminal  bool
	dependencyErr       error
	dependencyChecks    []string
	dependencyCheckHook func()
	loadCalls           int
}

func (f *fakeStateStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	f.loadCalls++
	return f.state, f.ok, f.err
}

func (f *fakeStateStore) SaveState(_ context.Context, state app.PersistedState) error {
	f.saved = state
	return nil
}

func (f *fakeStateStore) HasActiveJobDependency(_ context.Context, tenantID, kind, subjectType, subjectID string) (bool, error) {
	f.dependencyChecks = append(f.dependencyChecks, strings.Join([]string{tenantID, kind, subjectType, subjectID}, ":"))
	if f.dependencyCheckHook != nil {
		hook := f.dependencyCheckHook
		f.dependencyCheckHook = nil
		hook()
	}
	if f.dependencyErr != nil {
		return false, f.dependencyErr
	}
	return !f.dependencyTerminal, nil
}

type fakeReleaseLedgerMutationStore struct {
	state     app.PersistedState
	mutation  app.ReleaseLedgerMutation
	saveCalls int
	ok        bool
	err       error
}

type fakeClaimedReleaseLedgerMutationStore struct {
	state      app.PersistedState
	ok         bool
	jobID      string
	leaseToken string
	mutation   app.ReleaseLedgerMutation
	err        error
}

type fakeFocusedParserStateStore struct {
	state       app.PersistedState
	loadCalls   int
	focusedJobs []postgres.ClaimedJob
	mutation    app.ReleaseLedgerMutation
	jobID       string
	leaseToken  string
}

type fakeFocusedReadOnlyStateStore struct {
	state      app.PersistedState
	loadCalls  int
	focusCalls int
}

func (f *fakeFocusedReadOnlyStateStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	f.loadCalls++
	return app.PersistedState{}, false, errors.New("whole-state load must not be used")
}

func (f *fakeFocusedReadOnlyStateStore) LoadWorkerJobState(context.Context, postgres.ClaimedJob) (app.PersistedState, bool, error) {
	f.focusCalls++
	return f.state, true, nil
}

func (f *fakeFocusedParserStateStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	f.loadCalls++
	return app.PersistedState{}, false, errors.New("whole-state load must not be used")
}

func (f *fakeFocusedParserStateStore) LoadWorkerJobState(_ context.Context, job postgres.ClaimedJob) (app.PersistedState, bool, error) {
	f.focusedJobs = append(f.focusedJobs, job)
	return f.state, true, nil
}

func (f *fakeFocusedParserStateStore) ApplyClaimedReleaseLedgerMutation(_ context.Context, jobID, leaseToken string, mutation app.ReleaseLedgerMutation) error {
	f.jobID, f.leaseToken, f.mutation = jobID, leaseToken, mutation
	return nil
}

func TestProcessParserJobsReadOnlyClaimedSubjectState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind, subjectID string
		state           app.PersistedState
	}{
		{"parse_sbom", "sbom_test", app.PersistedState{SBOMs: map[string]domain.SBOM{"sbom_test": {ID: "sbom_test", TenantID: "ten_test", SpecVersion: "1.6"}}}},
		{"parse_vulnerability_scan", "scan_test", app.PersistedState{Scans: map[string]domain.VulnerabilityScan{"scan_test": {ID: "scan_test", TenantID: "ten_test", Scanner: "scanner", TargetRef: "release", Summary: map[string]int{}}}}},
		{"parse_openapi_contract", "contract_test", app.PersistedState{Contracts: map[string]domain.OpenAPIContract{"contract_test": {ID: "contract_test", TenantID: "ten_test", Operations: []domain.OpenAPIOperation{}, Hash: "sha256:" + strings.Repeat("a", 64)}}}},
		{"verify_attestation", "att_test", app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{"att_test": {ID: "att_test", TenantID: "ten_test", PayloadHash: "sha256:" + strings.Repeat("a", 64), VerificationStatus: "structurally_valid"}}}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			t.Parallel()
			job := postgres.ClaimedJob{ID: "job_test", TenantID: "ten_test", Kind: tc.kind, SubjectID: tc.subjectID, LeaseToken: "lease_test"}
			store := &fakeFocusedParserStateStore{state: tc.state}
			if err := processJobWithObjects(t.Context(), store, nil, job); err != nil {
				t.Fatalf("process focused parser job: %v", err)
			}
			if store.loadCalls != 0 || len(store.focusedJobs) != 1 || store.focusedJobs[0].TenantID != job.TenantID || store.focusedJobs[0].SubjectID != job.SubjectID || store.focusedJobs[0].Kind != job.Kind {
				t.Fatalf("whole loads=%d focused=%#v", store.loadCalls, store.focusedJobs)
			}
		})
	}
}

func TestProcessFocusedParserReplayKeepsClaimedMutationFence(t *testing.T) {
	t.Parallel()
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","version":"1.0.0"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID: "job_test", TenantID: "ten_test", Kind: "parse_sbom", SubjectType: "sbom",
		SubjectID: "sbom_test", LeaseToken: "lease_test",
		Payload: map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	store := &fakeFocusedParserStateStore{state: app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(t.Context(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process focused replay: %v", err)
	}
	if store.loadCalls != 0 || len(store.focusedJobs) != 1 || store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.SBOMs) != 1 || store.mutation.SBOMs[0].SpecVersion != "1.6" {
		t.Fatalf("focused replay loads=%d jobs=%d claimed=%q/%q mutation=%#v", store.loadCalls, len(store.focusedJobs), store.jobID, store.leaseToken, store.mutation)
	}
}

func TestProcessFocusedAttestationReplayKeepsClaimedMutationFence(t *testing.T) {
	t.Parallel()
	body := dsseEnvelopeForTest(t, "sha256:"+strings.Repeat("a", 64))
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID: "job_att", TenantID: "ten_test", Kind: "verify_attestation", SubjectType: "build_attestation",
		SubjectID: "att_test", LeaseToken: "lease_att",
		Payload: map[string]any{"payload_ref": "object://tenants/ten_test/payloads/att.json", "payload_hash": hash},
	}
	store := &fakeFocusedParserStateStore{state: app.PersistedState{BuildAttestations: map[string]domain.BuildAttestation{
		"att_test": {ID: "att_test", TenantID: "ten_test", PayloadHash: hash, VerificationStatus: "accepted"},
	}}}
	object := app.Object{Key: "tenants/ten_test/payloads/att.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(t.Context(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process focused attestation replay: %v", err)
	}
	if store.loadCalls != 0 || len(store.focusedJobs) != 1 || store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.BuildAttestations) != 1 || store.mutation.BuildAttestations[0].PayloadType == "" {
		t.Fatalf("attestation replay loads=%d jobs=%d claimed=%q/%q mutation=%#v", store.loadCalls, len(store.focusedJobs), store.jobID, store.leaseToken, store.mutation)
	}
}

func TestProcessVEXDecisionJobUsesFocusedClaimedState(t *testing.T) {
	t.Parallel()
	job, state := normalizedVEXWorkerFixture(t,
		[]map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")},
		map[string]int{"fixed": 1})
	job.LeaseToken = "lease_vex"
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_test": {ID: "scan_test", TenantID: job.TenantID, ReleaseID: "rel_test", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}}},
	}
	store := &fakeFocusedParserStateStore{state: state}
	if err := processJobWithObjects(t.Context(), store, nil, job); err != nil {
		t.Fatalf("process focused VEX decision job: %v", err)
	}
	if store.loadCalls != 0 || len(store.focusedJobs) < 2 || store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.VulnerabilityDecisions) != 1 || len(store.mutation.VEXImportReports) != 1 || store.mutation.VEXImportReports[0].Status != "parsed" {
		t.Fatalf("focused VEX loads=%d jobs=%d claimed=%q/%q mutation=%#v", store.loadCalls, len(store.focusedJobs), store.jobID, store.leaseToken, store.mutation)
	}
}

func TestProcessVEXObjectFailureUsesFocusedClaimedReportMutation(t *testing.T) {
	t.Parallel()
	job, state := normalizedVEXWorkerFixture(t,
		[]map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")},
		map[string]int{"fixed": 1})
	job.LeaseToken = "lease_vex"
	ref := "object://tenants/ten_test/payloads/vex.json"
	job.Payload["payload_ref"] = ref
	evidence := state.Evidence["ev_vex"]
	evidence.PayloadRef = ref
	state.Evidence[evidence.ID] = evidence
	store := &fakeFocusedParserStateStore{state: state}
	if err := processJobWithObjects(t.Context(), store, fakeObjectGetter{err: errors.New("object unavailable")}, job); err == nil {
		t.Fatal("missing VEX object was accepted")
	}
	if store.loadCalls != 0 || len(store.focusedJobs) < 2 || store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.VEXImportReports) != 1 || store.mutation.VEXImportReports[0].Status != "failed" {
		t.Fatalf("focused VEX failure loads=%d jobs=%d claimed=%q/%q mutation=%#v", store.loadCalls, len(store.focusedJobs), store.jobID, store.leaseToken, store.mutation)
	}
}

func TestProcessFocusedParserRejectsForeignTenantSubject(t *testing.T) {
	t.Parallel()
	job := postgres.ClaimedJob{ID: "job_test", TenantID: "ten_test", Kind: "parse_sbom", SubjectID: "sbom_test", LeaseToken: "lease_test"}
	store := &fakeFocusedParserStateStore{state: app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_other", SpecVersion: "1.6"},
	}}}
	if err := processJobWithObjects(t.Context(), store, nil, job); err == nil || !strings.Contains(err.Error(), "parsed sbom is not available") {
		t.Fatalf("foreign subject error=%v", err)
	}
	if store.loadCalls != 0 || store.jobID != "" {
		t.Fatalf("foreign subject loaded whole state or wrote mutation: loads=%d job=%q", store.loadCalls, store.jobID)
	}
}

func TestProcessReadOnlyJobsUseFocusedSubjectState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		job   postgres.ClaimedJob
		state app.PersistedState
	}{
		{
			name:  "sign bundle",
			job:   postgres.ClaimedJob{ID: "job_bundle", TenantID: "ten_test", Kind: "sign_bundle", SubjectType: "release_bundle", SubjectID: "bundle_test", Payload: map[string]any{"payload_hash": "sha256:manifest"}},
			state: app.PersistedState{Bundles: map[string]domain.ReleaseBundle{"bundle_test": {ID: "bundle_test", TenantID: "ten_test", ManifestHash: "sha256:manifest", SignatureRefs: []string{"sig_test"}}}},
		},
		{
			name:  "verify subject",
			job:   postgres.ClaimedJob{ID: "job_verify", TenantID: "ten_test", Kind: "verify_subject", SubjectType: "release_bundle", SubjectID: "bundle_test", Payload: map[string]any{"result_id": "vr_test"}},
			state: app.PersistedState{Verifications: map[string]domain.VerificationResult{"vr_test": {ID: "vr_test", TenantID: "ten_test", SubjectType: "release_bundle", SubjectID: "bundle_test", Result: "passed"}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeFocusedReadOnlyStateStore{state: tc.state}
			if err := processJobWithObjects(t.Context(), store, nil, tc.job); err != nil {
				t.Fatalf("process focused job: %v", err)
			}
			if store.loadCalls != 0 || store.focusCalls != 1 {
				t.Fatalf("whole loads=%d focused loads=%d", store.loadCalls, store.focusCalls)
			}
		})
	}
}

func TestProcessSignBundleChecksQueuedManifestHash(t *testing.T) {
	t.Parallel()
	for _, value := range []any{"sha256:different", "", 17} {
		store := &fakeFocusedReadOnlyStateStore{state: app.PersistedState{Bundles: map[string]domain.ReleaseBundle{
			"bundle_test": {ID: "bundle_test", TenantID: "ten_test", ManifestHash: "sha256:actual", SignatureRefs: []string{"sig_test"}},
		}}}
		job := postgres.ClaimedJob{
			ID: "job_bundle", TenantID: "ten_test", Kind: "sign_bundle", SubjectType: "release_bundle",
			SubjectID: "bundle_test", Payload: map[string]any{"manifest_hash": value},
		}
		if err := processJobWithObjects(t.Context(), store, nil, job); err == nil || !strings.Contains(err.Error(), "hash") {
			t.Fatalf("invalid queued manifest hash %v error=%v", value, err)
		}
	}
}

func (f *fakeClaimedReleaseLedgerMutationStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	return f.state, f.ok, nil
}

func (f *fakeClaimedReleaseLedgerMutationStore) ApplyClaimedReleaseLedgerMutation(_ context.Context, jobID, leaseToken string, mutation app.ReleaseLedgerMutation) error {
	f.jobID = jobID
	f.leaseToken = leaseToken
	f.mutation = mutation
	return f.err
}

func (f *fakeReleaseLedgerMutationStore) LoadState(context.Context) (app.PersistedState, bool, error) {
	return f.state, f.ok, f.err
}

func (f *fakeReleaseLedgerMutationStore) ApplyReleaseLedgerMutation(_ context.Context, mutation app.ReleaseLedgerMutation) error {
	f.mutation = mutation
	return nil
}

func (f *fakeReleaseLedgerMutationStore) SaveState(context.Context, app.PersistedState) error {
	f.saveCalls++
	return nil
}

func TestPersistParserSideEffectsUsesClaimedMutationBoundary(t *testing.T) {
	t.Parallel()
	job := postgres.ClaimedJob{ID: "job_claimed", TenantID: "ten_claimed", LeaseToken: "lease_claimed"}
	report := domain.VEXImportReport{ID: "report_claimed", TenantID: job.TenantID}
	mutation := app.ReleaseLedgerMutation{VEXImportReports: []domain.VEXImportReport{report}}
	store := &fakeClaimedReleaseLedgerMutationStore{ok: true}
	if err := persistParserSideEffects(context.Background(), store, app.PersistedState{}, job, mutation); err != nil {
		t.Fatalf("persist claimed side effects: %v", err)
	}
	if store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.VEXImportReports) != 1 || store.mutation.VEXImportReports[0].ID != report.ID {
		t.Fatalf("claimed mutation = job %q lease %q mutation %#v", store.jobID, store.leaseToken, store.mutation)
	}

	store.err = app.ErrConflict
	if err := persistParserSideEffects(context.Background(), store, app.PersistedState{}, job, mutation); !errors.Is(err, app.ErrConflict) {
		t.Fatalf("stale claimed mutation error = %v, want conflict", err)
	}
}

type fakeObjectGetter struct {
	object  app.Object
	err     error
	wantKey string
}

type fakePayloadLifecycleState struct {
	fakeStateLoader
	payload app.ObjectPayload
}

func (f *fakePayloadLifecycleState) GetObjectPayload(_ context.Context, tenantID, digest string) (app.ObjectPayload, error) {
	if f.payload.TenantID != tenantID || f.payload.Digest != digest {
		return app.ObjectPayload{}, app.ErrNotFound
	}
	return f.payload, nil
}

func (f *fakePayloadLifecycleState) MarkObjectPayloadFinalized(_ context.Context, payload app.ObjectPayload) error {
	if f.payload.TenantID != payload.TenantID || f.payload.Digest != payload.Digest || f.payload.FinalKey != payload.FinalKey {
		return app.ErrConflict
	}
	f.payload.Status = app.ObjectPayloadFinalized
	return nil
}

func (f *fakePayloadLifecycleState) MarkObjectPayloadFailed(_ context.Context, payload app.ObjectPayload, code string) error {
	if f.payload.TenantID != payload.TenantID || f.payload.Digest != payload.Digest {
		return app.ErrConflict
	}
	f.payload.Status = app.ObjectPayloadFailed
	f.payload.FailureCode = code
	return nil
}

func (f *fakePayloadLifecycleState) MarkObjectPayloadOrphaned(_ context.Context, payload app.ObjectPayload) error {
	if f.payload.TenantID != payload.TenantID || f.payload.Digest != payload.Digest {
		return app.ErrConflict
	}
	f.payload.Status = app.ObjectPayloadOrphaned
	return nil
}

type fakePayloadFinalizer struct {
	objects map[string]app.Object
}

func (f *fakePayloadFinalizer) Put(_ context.Context, object app.Object) error {
	f.objects[object.Key] = object
	return nil
}

func (f *fakePayloadFinalizer) Get(_ context.Context, key string) (app.Object, error) {
	object, ok := f.objects[key]
	if !ok {
		return app.Object{}, app.ErrNotFound
	}
	return object, nil
}

func (f *fakePayloadFinalizer) StagePayload(_ context.Context, payload app.ObjectPayload, reader io.Reader) (app.ObjectPayload, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return app.ObjectPayload{}, err
	}
	payload.Size = int64(len(body))
	f.objects[payload.StagingKey] = app.Object{Key: payload.StagingKey, TenantID: payload.TenantID, Digest: payload.Digest, Bytes: body}
	return payload, nil
}

func (f *fakePayloadFinalizer) FinalizePayload(_ context.Context, payload app.ObjectPayload) (app.Object, error) {
	if object, ok := f.objects[payload.FinalKey]; ok {
		return object, nil
	}
	object, ok := f.objects[payload.StagingKey]
	if !ok {
		return app.Object{}, app.ErrNotFound
	}
	delete(f.objects, payload.StagingKey)
	object.Key = payload.FinalKey
	f.objects[payload.FinalKey] = object
	return object, nil
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
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","version":"1.0.0","purl":"pkg:generic/api@1.0.0"}]}`)
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

func TestProcessJobWithObjectsUsesFocusedReleaseLedgerMutationForParserSideEffects(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api","version":"1.0.0"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload:   map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
	}
	store := &fakeReleaseLedgerMutationStore{
		ok: true,
		state: app.PersistedState{
			Products: map[string]domain.Product{
				"prod_concurrent": {ID: "prod_concurrent", TenantID: "ten_test", Name: "Do not rewrite", Slug: "do-not-rewrite"},
			},
			Evidence: map[string]domain.EvidenceItem{
				"ev_concurrent": {ID: "ev_concurrent", TenantID: "ten_test", Metadata: map[string]any{"revision": "newer"}},
			},
			SBOMs: map[string]domain.SBOM{
				"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
			},
			Decisions: map[string]domain.VulnerabilityDecision{
				"dec_concurrent": {ID: "dec_concurrent", TenantID: "ten_test", FindingID: "finding_concurrent", SupersededBy: "dec_newer"},
			},
		},
	}
	object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process object-backed job: %v", err)
	}
	if store.saveCalls != 0 || len(store.mutation.SBOMs) != 1 {
		t.Fatalf("focused parser persistence save=%d mutation=%#v", store.saveCalls, store.mutation)
	}
	if len(store.mutation.Products) != 0 || len(store.mutation.Projects) != 0 || len(store.mutation.Releases) != 0 || len(store.mutation.Artifacts) != 0 || len(store.mutation.Evidence) != 0 || len(store.mutation.EvidenceLifecycle) != 0 || len(store.mutation.Scans) != 0 || len(store.mutation.Contracts) != 0 || len(store.mutation.VEXDocuments) != 0 || len(store.mutation.VEXImportReports) != 0 || len(store.mutation.BuildAttestations) != 0 || len(store.mutation.VulnerabilityDecisions) != 0 || len(store.mutation.AuditChainEntries) != 0 || len(store.mutation.OutboxJobs) != 0 {
		t.Fatalf("parser mutation included unrelated stale aggregates: %#v", store.mutation)
	}
	updated := store.mutation.SBOMs[0]
	if updated.SpecVersion != "1.6" || updated.ComponentCount != 1 || len(updated.Components) != 1 {
		t.Fatalf("focused sbom mutation = %#v", updated)
	}
}

func TestProcessJobWithObjectsUsesFocusedMutationForAttestationReplay(t *testing.T) {
	body := dsseEnvelopeForTest(t, "sha256:"+strings.Repeat("a", 64))
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "verify_attestation",
		SubjectID: "att_test",
		Payload: map[string]any{
			"payload_ref":    "object://tenants/ten_test/payloads/attestation.json",
			"payload_hash":   hash,
			"parser_version": app.ParserVersionDSSEInTotoJSON,
		},
	}
	store := &fakeReleaseLedgerMutationStore{
		ok: true,
		state: app.PersistedState{
			Products: map[string]domain.Product{
				"prod_concurrent": {ID: "prod_concurrent", TenantID: "ten_test", Name: "Do not rewrite"},
			},
			BuildAttestations: map[string]domain.BuildAttestation{
				"att_test": {ID: "att_test", TenantID: "ten_test", PayloadHash: hash, VerificationStatus: "structurally_valid"},
			},
		},
	}
	object := app.Object{Key: "tenants/ten_test/payloads/attestation.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process attestation replay: %v", err)
	}
	if store.saveCalls != 0 || len(store.mutation.BuildAttestations) != 1 {
		t.Fatalf("focused attestation persistence save=%d mutation=%#v", store.saveCalls, store.mutation)
	}
	if len(store.mutation.Products) != 0 || len(store.mutation.Evidence) != 0 || len(store.mutation.SBOMs) != 0 || len(store.mutation.Scans) != 0 || len(store.mutation.Contracts) != 0 || len(store.mutation.VEXDocuments) != 0 || len(store.mutation.VulnerabilityDecisions) != 0 || len(store.mutation.AuditChainEntries) != 0 {
		t.Fatalf("attestation mutation included unrelated stale aggregates: %#v", store.mutation)
	}
	updated := store.mutation.BuildAttestations[0]
	if updated.PayloadSize != int64(len(body)) || updated.PayloadType == "" || updated.PredicateType == "" || len(updated.SubjectDigests) != 1 {
		t.Fatalf("focused attestation mutation = %#v", updated)
	}
}

func TestProcessJobWithObjectsRequiresWritableStateForParserSideEffects(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api"}]}`)
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
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
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
	if err := processJobWithObjects(context.Background(), &fakeStateStore{state: state, ok: true}, fakeObjectGetter{object: object, wantKey: "tenants/ten_test/payloads/sbom.json"}, job); err != nil {
		t.Fatalf("process object-backed job: %v", err)
	}
}

func TestProcessJobWithObjectsRejectsPayloadUntilLifecycleFinalization(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	digest := digestBytes(body)
	payload := app.ObjectPayload{
		TenantID:   "ten_test",
		Digest:     digest,
		Size:       int64(len(body)),
		StagingKey: "tenants/ten_test/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_test/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	job := postgres.ClaimedJob{
		TenantID:  "ten_test",
		Kind:      "parse_sbom",
		SubjectID: "sbom_test",
		Payload: map[string]any{
			"payload_ref":       "object://" + payload.FinalKey,
			"payload_hash":      digest,
			"payload_lifecycle": app.PayloadLifecycleVersion,
			"payload_digest":    digest,
		},
	}
	state := &fakePayloadLifecycleState{fakeStateLoader: fakeStateLoader{ok: true, state: app.PersistedState{SBOMs: map[string]domain.SBOM{
		"sbom_test": {ID: "sbom_test", TenantID: "ten_test"},
	}}}, payload: payload}
	err := processJobWithObjects(context.Background(), state, fakeObjectGetter{object: app.Object{Key: payload.FinalKey, TenantID: payload.TenantID, Digest: digest, Bytes: body}}, job)
	if err == nil || !strings.Contains(err.Error(), "payload finalization pending") {
		t.Fatalf("staged payload parser error=%v", err)
	}
	failure := classifyWorkerFailure(err)
	if failure.Class != postgres.JobFailureTransient || failure.Code != "payload_finalization_pending" {
		t.Fatalf("staged payload worker failure=%#v", failure)
	}
}

func TestProcessJobFinalizesStagedPayloadIdempotently(t *testing.T) {
	body := []byte("worker finalization payload")
	digest := digestBytes(body)
	payload := app.ObjectPayload{
		TenantID:   "ten_test",
		Digest:     digest,
		Size:       int64(len(body)),
		StagingKey: "tenants/ten_test/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_test/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	state := &fakePayloadLifecycleState{fakeStateLoader: fakeStateLoader{ok: true}, payload: payload}
	objects := &fakePayloadFinalizer{objects: map[string]app.Object{
		payload.StagingKey: {Key: payload.StagingKey, TenantID: payload.TenantID, Digest: payload.Digest, Bytes: body},
	}}
	job := postgres.ClaimedJob{TenantID: payload.TenantID, Kind: "finalize_payload", SubjectType: "object_payload", SubjectID: payload.Digest, Payload: map[string]any{"payload_digest": payload.Digest, "payload_lifecycle": app.PayloadLifecycleVersion}}
	if err := processJobWithObjects(context.Background(), state, objects, job); err != nil {
		t.Fatalf("finalize staged payload: %v", err)
	}
	if state.payload.Status != app.ObjectPayloadFinalized {
		t.Fatalf("payload status after finalization=%q", state.payload.Status)
	}
	if _, err := objects.Get(context.Background(), payload.FinalKey); err != nil {
		t.Fatalf("final object: %v", err)
	}
	if err := processJobWithObjects(context.Background(), state, objects, job); err != nil {
		t.Fatalf("repeat finalization after crash boundary: %v", err)
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
			body: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api"},{"type":"library","name":"worker"}]}`),
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

func TestProcessJobWithObjectsCreatesVEXDecisionsIdempotently(t *testing.T) {
	job, state, object := legacyVEXWorkerFixture(t, 1)
	store := &fakeStateStore{ok: true, state: state}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process vex job: %v", err)
	}
	if len(store.saved.Decisions) != 1 {
		t.Fatalf("decisions = %#v, want one", store.saved.Decisions)
	}
	for _, decision := range store.saved.Decisions {
		if decision.FindingID != "finding_1" || decision.Status != "fixed" || decision.VEXDocumentID != "vex_test" || decision.ApprovedBy != "key_test" || decision.Source != "vex" {
			t.Fatalf("decision = %#v", decision)
		}
	}
	if got := len(store.saved.Chain["ten_test"]); got != 1 {
		t.Fatalf("chain entries = %d, want 1", got)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "parsed" || report.StatementCount != 1 || report.DecisionsCreated != 1 || report.DecisionsSuperseded != 0 {
		t.Fatalf("import report = %#v", report)
	}
	vex := store.saved.VEXDocuments["vex_test"]
	if vex.Author != "security@example.test" || vex.StatementCount != 1 || vex.StatusSummary["fixed"] != 1 {
		t.Fatalf("replayed legacy VEX projection = %#v", vex)
	}

	previous := store.saved
	previous.Scans["scan_competing"] = domain.VulnerabilityScan{
		ID: "scan_competing", TenantID: "ten_test", ReleaseID: "rel_test",
		Findings: []domain.VulnerabilityFinding{{ID: "finding_competing", Vulnerability: "CVE-1", Component: "pkg:oci/api"}},
	}
	store.state = previous
	store.saved = app.PersistedState{}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object unavailable after commit")}, job); err != nil {
		t.Fatalf("reprocess vex job: %v", err)
	}
	if len(store.saved.Decisions) != 0 || len(previous.Decisions) != 1 || len(previous.Chain["ten_test"]) != 1 {
		t.Fatalf("replay duplicated side effects: saved=%#v previous=%#v", store.saved.Decisions, previous.Decisions)
	}
}

func TestLegacyVEXDecisionJobRejectsReplayedStatementCountMismatch(t *testing.T) {
	job, state, object := legacyVEXWorkerFixture(t, 2)
	store := &fakeStateStore{ok: true, state: state}

	err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job)
	if err == nil || !strings.Contains(err.Error(), "durable state") {
		t.Fatalf("error = %v, want replayed statement count mismatch", err)
	}
	if len(store.saved.Decisions) != 0 || len(store.saved.Chain[job.TenantID]) != 0 {
		t.Fatalf("mismatched replay persisted decision side effects: %#v", store.saved)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "failed" || report.FailureCode != "durable_state_mismatch" {
		t.Fatalf("failure report = %#v", report)
	}
}

func TestProcessJobWithObjectsCreatesVEXDecisionsFromNormalizedRequestWithoutObject(t *testing.T) {
	statements := []map[string]any{
		normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed"),
		normalizedVEXTestStatement(2, "CVE-1", "pkg:oci/api", "fixed"),
		normalizedVEXTestStatement(3, "CVE-missing", "pkg:oci/missing", "fixed"),
	}
	job, state := normalizedVEXWorkerFixture(t, statements, map[string]int{"fixed": 3})
	job.Payload["artifact_id"] = ""
	vex := state.VEXDocuments["vex_test"]
	vex.ArtifactID = ""
	state.VEXDocuments[vex.ID] = vex
	reportBefore := state.VEXImportReports["vex_report"]
	reportBefore.ArtifactID = ""
	state.VEXImportReports[reportBefore.ID] = reportBefore
	evidence := state.Evidence["ev_vex"]
	evidence.SubjectRefs = nil
	state.Evidence[evidence.ID] = evidence
	prior := domain.VulnerabilityDecision{
		ID: "decision_prior", TenantID: job.TenantID, FindingID: "finding_1", ScanID: "scan_test",
		ReleaseID: "rel_test", Vulnerability: "CVE-1", Component: "pkg:oci/api", Status: "affected",
	}
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_test": {
			ID: "scan_test", TenantID: job.TenantID, ReleaseID: "rel_test",
			Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}},
		},
	}
	state.Decisions = map[string]domain.VulnerabilityDecision{prior.ID: prior}
	store := &fakeStateStore{ok: true, state: state}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job); err != nil {
		t.Fatalf("process normalized vex decision job: %v", err)
	}
	if len(store.saved.Decisions) != 2 {
		t.Fatalf("decisions = %#v, want prior plus one normalized decision", store.saved.Decisions)
	}
	updatedPrior := store.saved.Decisions[prior.ID]
	if updatedPrior.SupersededBy == "" {
		t.Fatalf("prior decision was not superseded: %#v", updatedPrior)
	}
	created := store.saved.Decisions[updatedPrior.SupersededBy]
	if created.FindingID != "finding_1" || created.Status != "fixed" || created.VEXDocumentID != "vex_test" || created.EvidenceID != "ev_vex" || created.ApprovedBy != "key_test" {
		t.Fatalf("normalized decision = %#v", created)
	}
	if got := len(store.saved.Chain[job.TenantID]); got != 3 {
		t.Fatalf("audit chain entries = %d, want accepted, superseded, and created", got)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "parsed" || report.DecisionsCreated != 1 || report.DecisionsSuperseded != 1 || len(report.MappingFailures) != 1 || report.MappingFailures[0].StatementIndex != 3 || report.MappingFailures[0].Code != "finding_not_found" {
		t.Fatalf("normalized import report = %#v", report)
	}
	if !hasWorkerString(report.Warnings, "Duplicate VEX statements for an already mapped finding were ignored.") {
		t.Fatalf("normalized import report warnings = %#v", report.Warnings)
	}
}

func TestNormalizedVEXDecisionJobReplaysRawPayloadWithoutArtifactScope(t *testing.T) {
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed","impact_statement":"patched","action_statement":"ship"}]}`)
	job, state := normalizedVEXWorkerFixture(t, []map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")}, map[string]int{"fixed": 1})
	payloadHash := digestBytes(body)
	payloadRef := "object://tenants/ten_test/payloads/vex.json"
	job.Payload["payload_hash"] = payloadHash
	job.Payload["payload_ref"] = payloadRef
	job.Payload["artifact_id"] = ""
	vex := state.VEXDocuments["vex_test"]
	vex.ArtifactID = ""
	state.VEXDocuments[vex.ID] = vex
	report := state.VEXImportReports["vex_report"]
	report.ArtifactID = ""
	state.VEXImportReports[report.ID] = report
	evidence := state.Evidence["ev_vex"]
	evidence.PayloadHash = payloadHash
	evidence.PayloadRef = payloadRef
	evidence.SubjectRefs = nil
	state.Evidence[evidence.ID] = evidence
	state.Chain = map[string][]domain.AuditChainEntry{}
	if _, err := app.AppendPersistedChainEntry(&state, vex.CreatedAt, job.TenantID, "vex.accepted", "vex_document", vex.ID, "api_key", "key_test", payloadHash, ""); err != nil {
		t.Fatalf("append accepted VEX audit entry: %v", err)
	}
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_test": {ID: "scan_test", TenantID: job.TenantID, ReleaseID: vex.ReleaseID, Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}}},
	}
	store := &fakeStateStore{ok: true, state: state}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: job.TenantID, Digest: payloadHash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process release-scoped replayed VEX: %v", err)
	}
	if len(store.saved.Decisions) != 1 || store.saved.VEXImportReports[report.ID].Status != "parsed" {
		t.Fatalf("release-scoped replayed VEX state = %#v", store.saved)
	}
}

func TestNormalizedVEXDecisionJobWaitsForPendingScanProjection(t *testing.T) {
	job, state := normalizedVEXWorkerFixture(t, []map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")}, map[string]int{"fixed": 1})
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_pending": {ID: "scan_pending", TenantID: job.TenantID, EvidenceID: "ev_scan", ReleaseID: "rel_test"},
	}
	store := &fakeStateStore{ok: true, state: state}
	err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job)
	if err == nil || !strings.Contains(err.Error(), "prerequisites are pending") {
		t.Fatalf("pending scan error = %v", err)
	}
	failure := classifyWorkerFailure(err)
	if failure.Class != postgres.JobFailureTransient || failure.Code != "dependency_pending" {
		t.Fatalf("pending scan failure classification = %#v", failure)
	}
	if len(store.saved.Decisions) != 0 || len(store.saved.VEXImportReports) != 0 || len(store.saved.Chain) != 0 {
		t.Fatalf("pending scan persisted VEX side effects: %#v", store.saved)
	}

	store.state.Scans["scan_pending"] = domain.VulnerabilityScan{
		ID: "scan_pending", TenantID: job.TenantID, EvidenceID: "ev_scan", ReleaseID: "rel_test",
		Scanner: "grype", Adapter: "grype", AdapterVersion: "grype-json.v1.0.0", SourceSchema: "grype-json", TargetRef: "pkg:oci/api",
		Summary: map[string]int{"high": 1}, Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}},
	}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job); err != nil {
		t.Fatalf("process VEX after scan projection: %v", err)
	}
	if len(store.saved.Decisions) != 1 || store.saved.VEXImportReports["vex_report"].Status != "parsed" {
		t.Fatalf("post-scan VEX state = %#v", store.saved)
	}
}

func TestNormalizedVEXDecisionJobFailsWhenScanParserDependencyIsTerminal(t *testing.T) {
	job, state := normalizedVEXWorkerFixture(t, []map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")}, map[string]int{"fixed": 1})
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_dead_letter": {ID: "scan_dead_letter", TenantID: job.TenantID, EvidenceID: "ev_scan", ReleaseID: "rel_test"},
	}
	store := &fakeStateStore{ok: true, state: state, dependencyTerminal: true}
	err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job)
	if err == nil || !strings.Contains(err.Error(), "prerequisite parser job is terminal") {
		t.Fatalf("terminal scan dependency error = %v", err)
	}
	failure := classifyWorkerFailure(err)
	if failure.Class != postgres.JobFailurePoisoned || failure.Code != "dependency_failed" {
		t.Fatalf("terminal scan dependency classification = %#v", failure)
	}
	wantCheck := job.TenantID + ":parse_vulnerability_scan:vulnerability_scan:scan_dead_letter"
	if got := store.dependencyChecks; len(got) != 2 || got[0] != wantCheck || got[1] != wantCheck {
		t.Fatalf("dependency checks = %#v", got)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "failed" || report.FailureCode != "dependency_failed" {
		t.Fatalf("terminal dependency report = %#v", report)
	}
	if len(store.saved.Decisions) != 0 {
		t.Fatalf("terminal dependency created decisions: %#v", store.saved.Decisions)
	}
}

func TestNormalizedVEXDecisionJobRechecksProjectionAfterDependencyCompletes(t *testing.T) {
	job, state := normalizedVEXWorkerFixture(t, []map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")}, map[string]int{"fixed": 1})
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_racing": {ID: "scan_racing", TenantID: job.TenantID, EvidenceID: "ev_scan", ReleaseID: "rel_test"},
	}
	store := &fakeStateStore{ok: true, state: state, dependencyTerminal: true}
	store.dependencyCheckHook = func() {
		store.state.Scans["scan_racing"] = domain.VulnerabilityScan{
			ID: "scan_racing", TenantID: job.TenantID, EvidenceID: "ev_scan", ReleaseID: "rel_test",
			Scanner: "grype", Adapter: "grype", AdapterVersion: "grype-json.v1.0.0", SourceSchema: "grype-json", TargetRef: "pkg:oci/api",
			Summary: map[string]int{"high": 1}, Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}},
		}
	}

	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job); err != nil {
		t.Fatalf("process VEX after dependency completion race: %v", err)
	}
	if store.loadCalls < 3 {
		t.Fatalf("durable state load calls = %d, want dependency projection recheck", store.loadCalls)
	}
	if len(store.saved.Decisions) != 1 || store.saved.VEXImportReports["vex_report"].Status != "parsed" {
		t.Fatalf("post-race VEX state = %#v", store.saved)
	}
}

func TestNormalizedVEXDecisionJobRejectsBrokenDurableLinkageBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*postgres.ClaimedJob, *app.PersistedState)
	}{
		{name: "missing report", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) { delete(state.VEXImportReports, "vex_report") }},
		{name: "vex map key aliases record id", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			vex := state.VEXDocuments["vex_test"]
			vex.ID = "vex_alias"
			state.VEXDocuments["vex_test"] = vex
			report := state.VEXImportReports["vex_report"]
			report.VEXDocumentID = vex.ID
			state.VEXImportReports["vex_report"] = report
			chain := state.Chain["ten_test"]
			chain[0].SubjectID = vex.ID
			state.Chain["ten_test"] = chain
		}},
		{name: "report map key aliases record id", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.ID = "report_alias"
			state.VEXImportReports["vex_report"] = report
		}},
		{name: "job evidence", mutate: func(job *postgres.ClaimedJob, _ *app.PersistedState) { job.Payload["evidence_id"] = "ev_other" }},
		{name: "report evidence", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.EvidenceID = "ev_other"
			state.VEXImportReports[report.ID] = report
		}},
		{name: "report release", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.ReleaseID = "rel_other"
			state.VEXImportReports[report.ID] = report
		}},
		{name: "report artifact", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.ArtifactID = "art_other"
			state.VEXImportReports[report.ID] = report
		}},
		{name: "report parser", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.ParserVersion = app.ParserVersionCycloneDXVEXJSON
			state.VEXImportReports[report.ID] = report
		}},
		{name: "report statement count", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) {
			report := state.VEXImportReports["vex_report"]
			report.StatementCount++
			state.VEXImportReports[report.ID] = report
		}},
		{name: "missing evidence", mutate: func(_ *postgres.ClaimedJob, state *app.PersistedState) { delete(state.Evidence, "ev_vex") }},
		{name: "payload hash", mutate: func(job *postgres.ClaimedJob, _ *app.PersistedState) {
			job.Payload["payload_hash"] = digestBytes([]byte("other"))
		}},
		{name: "actor", mutate: func(job *postgres.ClaimedJob, _ *app.PersistedState) { job.Payload["actor_id"] = "key_other" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job, state := normalizedVEXWorkerFixture(t, []map[string]any{normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")}, map[string]int{"fixed": 1})
			tt.mutate(&job, &state)
			store := &fakeStateStore{ok: true, state: state}
			err := processJobWithObjects(context.Background(), store, fakeObjectGetter{err: errors.New("object store must not be used")}, job)
			if err == nil || !strings.Contains(err.Error(), "vex decision job") {
				t.Fatalf("error = %v, want fail-closed VEX decision linkage error", err)
			}
			if len(store.saved.Decisions) != 0 || len(store.saved.Chain) != 0 || len(store.saved.VEXImportReports) != 0 {
				t.Fatalf("broken linkage persisted side effects: %#v", store.saved)
			}
		})
	}
}

func TestMalformedNormalizedVEXDecisionRequestFailsReportWithoutDecisionMutation(t *testing.T) {
	statement := normalizedVEXTestStatement(1, "CVE-1", "pkg:oci/api", "fixed")
	statement["unexpected"] = "field"
	job, state := normalizedVEXWorkerFixture(t, []map[string]any{statement}, map[string]int{"fixed": 1})
	state.Scans = map[string]domain.VulnerabilityScan{
		"scan_test": {ID: "scan_test", TenantID: job.TenantID, ReleaseID: "rel_test", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}}},
	}
	store := &fakeStateStore{ok: true, state: state}
	err := processJobWithObjects(context.Background(), store, fakeObjectGetter{}, job)
	if err == nil || !strings.Contains(err.Error(), "normalized vex decision request") {
		t.Fatalf("error = %v, want normalized request failure", err)
	}
	if len(store.saved.Decisions) != 0 || len(store.saved.Chain[job.TenantID]) != 1 {
		t.Fatalf("malformed request mutated decisions or audit chain: %#v", store.saved)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "failed" || report.FailureCode != "durable_state_mismatch" {
		t.Fatalf("failure report = %#v", report)
	}
	failure := classifyWorkerFailure(err)
	if failure.Class != postgres.JobFailurePoisoned || failure.Code != "payload_invariant_failed" {
		t.Fatalf("failure classification = %#v", failure)
	}
}

func TestNormalizedVEXDecisionRequestValidatesDecodedShapeAndBounds(t *testing.T) {
	validDecoded := map[string]any{
		"statement_index": float64(1), "vulnerability": "CVE-1", "products": []any{"pkg:oci/api"}, "status": "fixed",
		"justification": "fixed", "impact_statement": "patched", "action_statement": "ship",
	}
	tests := []struct {
		name       string
		schema     string
		statements any
		vex        domain.VEXDocument
		wantOK     bool
	}{
		{
			name: "database decoded request", schema: "vex-decision-request.v1.0.0", statements: []any{validDecoded},
			vex: domain.VEXDocument{Format: "openvex", Author: "security@example.test", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}}, wantOK: true,
		},
		{
			name: "unsupported schema", schema: "vex-decision-request.v2", statements: []any{validDecoded},
			vex: domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		{
			name: "unknown key", schema: "vex-decision-request.v1.0.0",
			statements: []any{map[string]any{"statement_index": float64(1), "vulnerability": "CVE-1", "products": []any{"pkg:oci/api"}, "status": "fixed", "unexpected": true}},
			vex:        domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		{
			name: "non-integral index", schema: "vex-decision-request.v1.0.0",
			statements: []any{map[string]any{"statement_index": 1.5, "vulnerability": "CVE-1", "products": []any{"pkg:oci/api"}, "status": "fixed"}},
			vex:        domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		{
			name: "duplicate index", schema: "vex-decision-request.v1.0.0",
			statements: []any{
				map[string]any{"statement_index": float64(1), "vulnerability": "CVE-1", "products": []any{"pkg:oci/api"}, "status": "fixed"},
				map[string]any{"statement_index": float64(1), "vulnerability": "CVE-2", "products": []any{"pkg:oci/worker"}, "status": "fixed"},
			},
			vex: domain.VEXDocument{Format: "openvex", StatementCount: 2, StatusSummary: map[string]int{"fixed": 2}},
		},
		{
			name: "duplicate product", schema: "vex-decision-request.v1.0.0",
			statements: []any{map[string]any{"statement_index": float64(1), "vulnerability": "CVE-1", "products": []any{"pkg:oci/api", "pkg:oci/api"}, "status": "fixed"}},
			vex:        domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		{
			name: "oversized string", schema: "vex-decision-request.v1.0.0",
			statements: []any{map[string]any{"statement_index": float64(1), "vulnerability": strings.Repeat("x", (1<<20)+1), "products": []any{"pkg:oci/api"}, "status": "fixed"}},
			vex:        domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		{
			name: "durable summary mismatch", schema: "vex-decision-request.v1.0.0", statements: []any{validDecoded},
			vex: domain.VEXDocument{Format: "openvex", StatementCount: 1, StatusSummary: map[string]int{"affected": 1}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := postgres.ClaimedJob{Payload: map[string]any{"decision_request_schema": tt.schema, "decision_statements": tt.statements}}
			parsed, ok, err := normalizedVEXDecisionRequest(job, tt.vex)
			if tt.wantOK {
				if err != nil || !ok || len(parsed.Statements) != 1 || parsed.Statements[0].StatementIndex != 1 {
					t.Fatalf("normalized request = %#v, %v, %v", parsed, ok, err)
				}
				return
			}
			if err == nil || ok {
				t.Fatalf("normalized request = %#v, %v, %v; want rejection", parsed, ok, err)
			}
		})
	}
}

func normalizedVEXWorkerFixture(t *testing.T, statements []map[string]any, summary map[string]int) (postgres.ClaimedJob, app.PersistedState) {
	t.Helper()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	payloadHash := digestBytes([]byte("normalized-vex-payload"))
	job := postgres.ClaimedJob{
		ID: "job_vex", TenantID: "ten_test", Kind: "parse_vex", SubjectType: "vex_document", SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref": "", "payload_hash": payloadHash, "parser_version": app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true, "decision_request_schema": "vex-decision-request.v1.0.0", "decision_statements": statements,
			"actor_type": "api_key", "actor_id": "key_test", "evidence_id": "ev_vex", "release_id": "rel_test", "artifact_id": "art_test", "import_report_id": "vex_report",
		},
	}
	state := app.PersistedState{
		Evidence: map[string]domain.EvidenceItem{
			"ev_vex": {
				ID: "ev_vex", TenantID: job.TenantID, ReleaseID: "rel_test", Type: "vex", Subtype: "openvex", UploadedBy: "key_test",
				PayloadHash: payloadHash, SubjectRefs: []domain.SubjectRef{{Type: "artifact", ID: "art_test"}},
			},
		},
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {
				ID: "vex_test", TenantID: job.TenantID, EvidenceID: "ev_vex", ReleaseID: "rel_test", ArtifactID: "art_test", Format: "openvex", Author: "security@example.test",
				StatementCount: len(statements), StatusSummary: summary, SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: now,
			},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {
				ID: "vex_report", TenantID: job.TenantID, VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ArtifactID: "art_test",
				ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", StatementCount: len(statements), SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now,
			},
		},
		Scans: map[string]domain.VulnerabilityScan{}, Decisions: map[string]domain.VulnerabilityDecision{}, Chain: map[string][]domain.AuditChainEntry{},
	}
	if _, err := app.AppendPersistedChainEntry(&state, now, job.TenantID, "vex.accepted", "vex_document", "vex_test", "api_key", "key_test", payloadHash, ""); err != nil {
		t.Fatalf("append accepted VEX audit entry: %v", err)
	}
	return job, state
}

func legacyVEXWorkerFixture(t *testing.T, reportStatementCount int) (postgres.ClaimedJob, app.PersistedState, app.Object) {
	t.Helper()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed","impact_statement":"patched","action_statement":"ship"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID: "job_vex", TenantID: "ten_test", Kind: "parse_vex", SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref": "object://tenants/ten_test/payloads/vex.json", "payload_hash": hash, "parser_version": app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true, "actor_type": "api_key", "actor_id": "key_test", "evidence_id": "ev_vex", "import_report_id": "vex_report",
		},
	}
	state := app.PersistedState{
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: job.TenantID, ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex"},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {
				ID: "vex_report", TenantID: job.TenantID, VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test",
				ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", StatementCount: reportStatementCount,
				SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now,
			},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {
				ID: "scan_test", TenantID: job.TenantID, ReleaseID: "rel_test",
				Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api", Severity: "critical", State: "open"}},
			},
		},
		Decisions: map[string]domain.VulnerabilityDecision{}, Chain: map[string][]domain.AuditChainEntry{},
	}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: job.TenantID, Digest: hash, Bytes: body}
	return job, state, object
}

func normalizedVEXTestStatement(index int, vulnerability, product, status string) map[string]any {
	return map[string]any{
		"statement_index": index, "vulnerability": vulnerability, "products": []string{product}, "status": status,
		"justification": "fixed", "impact_statement": "patched", "action_statement": "ship",
	}
}

func TestWorkerVEXStatementAmbiguityScansEveryMatchingFinding(t *testing.T) {
	t.Parallel()

	state := app.PersistedState{Scans: map[string]domain.VulnerabilityScan{
		"scan_a": {
			ID: "scan_a", TenantID: "ten_test", ReleaseID: "rel_test",
			Findings: []domain.VulnerabilityFinding{
				{ID: "finding_without_component", Vulnerability: "CVE-1"},
				{ID: "finding_with_component", Vulnerability: "CVE-1", Component: "pkg:oci/api"},
			},
		},
	}}
	statement := replayedVEXStatement{
		Vulnerability: "CVE-1",
		Products: map[string]struct{}{
			"pkg:oci/api":    {},
			"pkg:oci/worker": {},
		},
	}

	if workerVEXStatementUnambiguous(&state, []string{"scan_a"}, statement) {
		t.Fatal("multiple matches including an empty component must be ambiguous")
	}
}

func TestReclaimedVEXJobProducesRetryStableAuditEntryIDs(t *testing.T) {
	t.Parallel()

	base := app.PersistedState{
		Scans: map[string]domain.VulnerabilityScan{
			"scan_a": {
				ID: "scan_a", TenantID: "ten_test", ReleaseID: "rel_test",
				Findings: []domain.VulnerabilityFinding{{ID: "finding_a", Vulnerability: "CVE-1", Component: "pkg:oci/api"}},
			},
		},
		Decisions: map[string]domain.VulnerabilityDecision{
			"decision_prior": {ID: "decision_prior", TenantID: "ten_test", FindingID: "finding_a", ScanID: "scan_a"},
		},
		Chain: map[string][]domain.AuditChainEntry{},
	}
	job := postgres.ClaimedJob{ID: "job_vex", TenantID: "ten_test"}
	vex := domain.VEXDocument{ID: "vex_a", TenantID: "ten_test", ReleaseID: "rel_test"}
	parsed := replayedVEX{Format: "openvex", Statements: []replayedVEXStatement{{
		Vulnerability: "CVE-1", Status: "fixed", Justification: "fixed",
		Products: map[string]struct{}{"pkg:oci/api": {}},
	}}}

	first, second := base, base
	if _, _, _, _, err := applyReplayedVEXDecisions(&first, job, vex, parsed, "sha256:payload"); err != nil {
		t.Fatalf("first stale worker: %v", err)
	}
	if _, _, _, _, err := applyReplayedVEXDecisions(&second, job, vex, parsed, "sha256:payload"); err != nil {
		t.Fatalf("second stale worker: %v", err)
	}
	firstEntries, secondEntries := first.Chain[job.TenantID], second.Chain[job.TenantID]
	if len(firstEntries) != 2 || len(secondEntries) != 2 {
		t.Fatalf("audit entry counts = %d/%d, want 2/2", len(firstEntries), len(secondEntries))
	}
	for index := range firstEntries {
		if firstEntries[index].ID != secondEntries[index].ID {
			t.Fatalf("audit entry %d IDs differ across stale workers: %q / %q", index, firstEntries[index].ID, secondEntries[index].ID)
		}
	}
}

func TestProcessJobWithObjectsPersistsOnlyFocusedVEXSideEffects(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID:        "job_vex",
		TenantID:  "ten_test",
		Kind:      "parse_vex",
		SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":             "object://tenants/ten_test/payloads/vex.json",
			"payload_hash":            hash,
			"parser_version":          app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true,
			"actor_type":              "api_key",
			"actor_id":                "key_test",
			"evidence_id":             "ev_vex",
			"import_report_id":        "vex_report",
		},
	}
	prior := domain.VulnerabilityDecision{ID: "decision_prior", TenantID: "ten_test", FindingID: "finding_1", ScanID: "scan_test", ReleaseID: "rel_test", Status: "affected"}
	store := &fakeReleaseLedgerMutationStore{ok: true, state: app.PersistedState{
		Products: map[string]domain.Product{
			"prod_concurrent": {ID: "prod_concurrent", TenantID: "ten_test", Name: "Do not rewrite"},
		},
		Evidence: map[string]domain.EvidenceItem{
			"ev_concurrent": {ID: "ev_concurrent", TenantID: "ten_test", Metadata: map[string]any{"revision": "newer"}},
		},
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex"},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {ID: "scan_test", TenantID: "ten_test", ReleaseID: "rel_test", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}}},
		},
		Decisions: map[string]domain.VulnerabilityDecision{prior.ID: prior},
		Chain:     map[string][]domain.AuditChainEntry{},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process focused vex replay: %v", err)
	}
	mutation := store.mutation
	if store.saveCalls != 0 || len(mutation.VEXDocuments) != 1 || len(mutation.VEXImportReports) != 1 || len(mutation.VulnerabilityDecisions) != 2 || len(mutation.AuditChainEntries) != 2 {
		t.Fatalf("focused vex mutation save=%d mutation=%#v", store.saveCalls, mutation)
	}
	if len(mutation.Products) != 0 || len(mutation.Evidence) != 0 || len(mutation.Scans) != 0 || len(mutation.SBOMs) != 0 || len(mutation.Contracts) != 0 || len(mutation.BuildAttestations) != 0 || len(mutation.OutboxJobs) != 0 {
		t.Fatalf("vex mutation included unrelated stale aggregates: %#v", mutation)
	}
	priorFound := false
	newFound := false
	for _, decision := range mutation.VulnerabilityDecisions {
		switch decision.ID {
		case prior.ID:
			priorFound = decision.SupersededBy != ""
		default:
			newFound = decision.FindingID == "finding_1" && decision.Supersedes == prior.ID && decision.Status == "fixed"
		}
	}
	if !priorFound || !newFound {
		t.Fatalf("focused vex decisions = %#v", mutation.VulnerabilityDecisions)
	}
}

func TestVEXDecisionAuditFailurePersistsOnlyFailedImportReport(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID:        "job_vex",
		TenantID:  "ten_test",
		Kind:      "parse_vex",
		SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":             "tenants/ten_test/payloads/vex.json",
			"payload_hash":            hash,
			"parser_version":          app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true,
			"evidence_id":             "ev_vex",
			"import_report_id":        "vex_report",
		},
	}
	prior := domain.VulnerabilityDecision{ID: "decision_prior", TenantID: "ten_test", FindingID: "finding_1", Status: "affected"}
	snapshot := app.PersistedState{
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex", Author: "security@example.test", StatementCount: 1, StatusSummary: map[string]int{"fixed": 1}},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {ID: "scan_test", TenantID: "ten_test", ReleaseID: "rel_test", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-1", Component: "pkg:oci/api"}}},
		},
		Decisions: map[string]domain.VulnerabilityDecision{prior.ID: prior},
		Chain:     map[string][]domain.AuditChainEntry{},
	}
	parsed, err := parseReplayedVEX(body)
	if err != nil {
		t.Fatalf("parse vex fixture: %v", err)
	}
	appendCalls := 0
	appendChainEntry := func(state *app.PersistedState, now time.Time, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef string) (domain.AuditChainEntry, error) {
		appendCalls++
		if appendCalls == 2 {
			return domain.AuditChainEntry{}, errors.New("forced audit append failure")
		}
		return app.AppendPersistedChainEntry(state, now, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef)
	}
	_, _, _, _, err = applyReplayedVEXDecisionsWithAppender(&snapshot, job, snapshot.VEXDocuments["vex_test"], parsed, hash, appendChainEntry)
	if err == nil || !strings.Contains(err.Error(), "append replayed vex decision audit entry") {
		t.Fatalf("err=%v, want safe audit append failure", err)
	}
	if appendCalls != 2 {
		t.Fatalf("audit append calls = %d, want failure after one successful append", appendCalls)
	}
	store := &fakeStateStore{ok: true}
	err = failVEXImportReportWithSnapshot(context.Background(), store, &snapshot, job, snapshot.VEXDocuments["vex_test"], err)
	if err == nil || !strings.Contains(err.Error(), "append replayed vex decision audit entry") {
		t.Fatalf("failure report err=%v, want original audit append failure", err)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "failed" || report.FailureCode != "parser_failed" {
		t.Fatalf("report = %#v, want failed parser report", report)
	}
	if len(store.saved.Decisions) != 1 {
		t.Fatalf("decisions = %#v, want only prior decision", store.saved.Decisions)
	}
	if savedPrior := store.saved.Decisions[prior.ID]; savedPrior.SupersededBy != "" {
		t.Fatalf("prior decision was partially superseded: %#v", savedPrior)
	}
	if len(store.saved.Chain["ten_test"]) != 0 {
		t.Fatalf("audit chain = %#v, want unchanged", store.saved.Chain["ten_test"])
	}

	focusedSnapshot := snapshot
	focusedReport := focusedSnapshot.VEXImportReports["vex_report"]
	focusedReport.Status = "accepted"
	focusedReport.FailureCode = ""
	focusedReport.FailureDetail = ""
	focusedSnapshot.VEXImportReports = map[string]domain.VEXImportReport{"vex_report": focusedReport}
	focusedStore := &fakeReleaseLedgerMutationStore{ok: true}
	err = failVEXImportReportWithSnapshot(context.Background(), focusedStore, &focusedSnapshot, job, focusedSnapshot.VEXDocuments["vex_test"], err)
	if err == nil || !strings.Contains(err.Error(), "append replayed vex decision audit entry") {
		t.Fatalf("focused failure report err=%v, want original audit append failure", err)
	}
	if len(focusedStore.mutation.VEXImportReports) != 1 || len(focusedStore.mutation.VulnerabilityDecisions) != 0 || len(focusedStore.mutation.AuditChainEntries) != 0 || len(focusedStore.mutation.VEXDocuments) != 0 {
		t.Fatalf("focused failure mutation = %#v, want only failed report", focusedStore.mutation)
	}
}

func TestProcessJobWithObjectsRecordsVEXImportReportFailure(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	validBody := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed"}]}`)
	baseJob := postgres.ClaimedJob{
		ID:        "job_vex",
		TenantID:  "ten_test",
		Kind:      "parse_vex",
		SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":      "object://tenants/ten_test/payloads/vex.json",
			"payload_hash":     digestBytes(validBody),
			"parser_version":   app.ParserVersionOpenVEXJSON,
			"import_report_id": "vex_report",
		},
	}
	baseState := func() app.PersistedState {
		return app.PersistedState{
			VEXDocuments: map[string]domain.VEXDocument{
				"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex"},
			},
			VEXImportReports: map[string]domain.VEXImportReport{
				"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now},
			},
		}
	}
	tests := []struct {
		name        string
		object      fakeObjectGetter
		payloadHash string
		want        string
		noLeak      string
		wantErr     string
	}{
		{
			name:        "malformed payload",
			object:      fakeObjectGetter{object: app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: digestBytes([]byte(`{"not":"vex"}`)), Bytes: []byte(`{"not":"vex"}`)}},
			payloadHash: digestBytes([]byte(`{"not":"vex"}`)),
			want:        "payload_invalid",
			noLeak:      `{"not":"vex"}`,
			wantErr:     "replayed vex payload is invalid",
		},
		{
			name:    "missing object",
			object:  fakeObjectGetter{err: errors.New("backend leaked secret")},
			want:    "payload_read_failed",
			noLeak:  "backend leaked secret",
			wantErr: "read outbox payload object",
		},
		{
			name:    "digest mismatch",
			object:  fakeObjectGetter{object: app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: digestBytes([]byte("other")), Bytes: []byte("other")}},
			want:    "payload_digest_mismatch",
			noLeak:  "other",
			wantErr: "metadata digest mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStateStore{ok: true, state: baseState()}
			job := baseJob
			if tt.payloadHash != "" {
				payload := map[string]any{}
				for key, value := range baseJob.Payload {
					payload[key] = value
				}
				payload["payload_hash"] = tt.payloadHash
				job.Payload = payload
			}
			err := processJobWithObjects(context.Background(), store, tt.object, job)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want %q", err, tt.wantErr)
			}
			report := store.saved.VEXImportReports["vex_report"]
			if report.Status != "failed" || report.FailureCode != tt.want || report.FailureDetail == "" {
				t.Fatalf("saved report = %#v", report)
			}
			text := report.FailureDetail + strings.Join(report.Warnings, "\n")
			if strings.Contains(text, tt.noLeak) || strings.Contains(text, "vex.json") {
				t.Fatalf("failure report leaked unsafe details: %#v", report)
			}
		})
	}
}

func TestProcessJobWithObjectsRecordsVEXMappingFailure(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-missing"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID:        "job_vex",
		TenantID:  "ten_test",
		Kind:      "parse_vex",
		SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":             "object://tenants/ten_test/payloads/vex.json",
			"payload_hash":            hash,
			"parser_version":          app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true,
			"actor_type":              "api_key",
			"actor_id":                "key_test",
			"evidence_id":             "ev_vex",
			"import_report_id":        "vex_report",
		},
	}
	store := &fakeStateStore{ok: true, state: app.PersistedState{
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex"},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now},
		},
		Scans:     map[string]domain.VulnerabilityScan{},
		Decisions: map[string]domain.VulnerabilityDecision{},
		Chain:     map[string][]domain.AuditChainEntry{},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process vex job: %v", err)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "parsed" || report.DecisionsCreated != 0 || len(report.MappingFailures) != 1 || report.MappingFailures[0].Code != "finding_not_found" {
		t.Fatalf("report = %#v", report)
	}
}

func TestProcessJobWithObjectsRejectsAmbiguousVEXMappingAfterEmptyComponent(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-ambiguous"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed","justification":"fixed"}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID: "job_vex", TenantID: "ten_test", Kind: "parse_vex", SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":             "object://tenants/ten_test/payloads/vex.json",
			"payload_hash":            hash,
			"parser_version":          app.ParserVersionOpenVEXJSON,
			"worker_create_decisions": true,
			"evidence_id":             "ev_vex",
			"import_report_id":        "vex_report",
		},
	}
	store := &fakeStateStore{ok: true, state: app.PersistedState{
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "openvex"},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ParserVersion: app.ParserVersionOpenVEXJSON, Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {
				ID: "scan_test", TenantID: "ten_test", ReleaseID: "rel_test",
				Findings: []domain.VulnerabilityFinding{
					{ID: "finding_empty", Vulnerability: "CVE-ambiguous"},
					{ID: "finding_scoped", Vulnerability: "CVE-ambiguous", Component: "pkg:oci/api"},
				},
			},
		},
		Decisions: map[string]domain.VulnerabilityDecision{},
		Chain:     map[string][]domain.AuditChainEntry{},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process ambiguous vex job: %v", err)
	}
	if len(store.saved.Decisions) != 0 {
		t.Fatalf("decisions = %#v, want none for ambiguous statement", store.saved.Decisions)
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.Status != "parsed" || report.DecisionsCreated != 0 || len(report.MappingFailures) != 1 || report.MappingFailures[0].Code != "ambiguous_finding" {
		t.Fatalf("report = %#v", report)
	}
}

func TestParseReplayedVEXSupportsCycloneDX(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-2001","affects":[{"ref":"pkg:oci/api"}],"analysis":{"state":"resolved","justification":"code_not_reachable","detail":"patched in release artifact","response":["update"]}},{"id":"CVE-2026-2999","analysis":{"state":"unknown"}}]}`)
	parsed, err := parseReplayedVEX(body)
	if err != nil {
		t.Fatalf("parse cyclonedx vex replay: %v", err)
	}
	if parsed.Format != "cyclonedx" || parsed.Author != "cyclonedx" || parsed.StatementCount != 2 || parsed.StatusSummary["fixed"] != 1 {
		t.Fatalf("parsed cyclonedx vex summary = %#v", parsed)
	}
	if len(parsed.Statements) != 1 {
		t.Fatalf("statements = %#v, want one valid statement", parsed.Statements)
	}
	statement := parsed.Statements[0]
	if statement.StatementIndex != 1 || statement.Vulnerability != "CVE-2026-2001" || statement.Status != "fixed" || statement.Justification != "code_not_reachable" || statement.ImpactStatement != "patched in release artifact" || statement.ActionStatement != "update" {
		t.Fatalf("statement = %#v", statement)
	}
	if _, ok := statement.Products["pkg:oci/api"]; !ok {
		t.Fatalf("products = %#v, want affected ref", statement.Products)
	}
	if len(parsed.InvalidStatements) != 1 || parsed.InvalidStatements[0].StatementIndex != 2 || parsed.InvalidStatements[0].Code != "unsupported_analysis_state" {
		t.Fatalf("invalid statements = %#v", parsed.InvalidStatements)
	}
}

func TestProcessJobWithObjectsValidatesVEXParserVersionFormatAndBodyAgreement(t *testing.T) {
	openVEXBody := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-05-28T12:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-1"},"products":[{"@id":"pkg:oci/api"}],"status":"fixed"}]}`)
	cycloneDXBody := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"resolved"}}]}`)
	tests := []struct {
		name          string
		durableFormat string
		parserVersion string
		body          []byte
		wantErr       string
		wantCode      string
	}{
		{
			name:          "parser version disagrees with durable and body formats",
			durableFormat: "openvex",
			parserVersion: app.ParserVersionCycloneDXVEXJSON,
			body:          openVEXBody,
			wantErr:       "parser version does not match",
			wantCode:      "unsupported_parser_version",
		},
		{
			name:          "body format disagrees with durable and parser formats",
			durableFormat: "openvex",
			parserVersion: app.ParserVersionOpenVEXJSON,
			body:          cycloneDXBody,
			wantErr:       "replayed vex payload does not match durable state",
			wantCode:      "durable_state_mismatch",
		},
		{
			name:          "legacy job without parser version remains accepted",
			durableFormat: "cyclonedx",
			body:          cycloneDXBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := digestBytes(tt.body)
			payload := map[string]any{
				"payload_ref":      "tenants/ten_test/payloads/vex.json",
				"payload_hash":     hash,
				"import_report_id": "vex_report",
			}
			if tt.parserVersion != "" {
				payload["parser_version"] = tt.parserVersion
			}
			job := postgres.ClaimedJob{ID: "job_vex", TenantID: "ten_test", Kind: "parse_vex", SubjectID: "vex_test", Payload: payload}
			store := &fakeStateStore{ok: true, state: app.PersistedState{
				VEXDocuments: map[string]domain.VEXDocument{
					"vex_test": {ID: "vex_test", TenantID: "ten_test", Format: tt.durableFormat},
				},
				VEXImportReports: map[string]domain.VEXImportReport{
					"vex_report": {ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", Status: "accepted", SchemaVersion: domain.VEXImportReportSchemaVersion},
				},
			}}
			object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: hash, Bytes: tt.body}
			err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("process legacy vex job: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want %q", err, tt.wantErr)
			}
			if report := store.saved.VEXImportReports["vex_report"]; report.Status != "failed" || report.FailureCode != tt.wantCode {
				t.Fatalf("report = %#v, want failed with code %q", report, tt.wantCode)
			}
		})
	}
}

func TestProcessJobWithObjectsPreservesCycloneDXVEXReportDetailsAndSource(t *testing.T) {
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","x-vendor":true,"vulnerabilities":[{"id":"CVE-invalid","analysis":{"state":"unknown"}},{"id":"CVE-match","affects":[{"ref":"pkg:oci/api"}],"analysis":{"state":"resolved"}},{"id":"CVE-missing","analysis":{"state":"not_affected"}},{"id":"CVE-match","affects":[{"ref":"pkg:oci/api"}],"analysis":{"state":"resolved"}}]}`)
	hash := digestBytes(body)
	job := postgres.ClaimedJob{
		ID:        "job_vex",
		TenantID:  "ten_test",
		Kind:      "parse_vex",
		SubjectID: "vex_test",
		Payload: map[string]any{
			"payload_ref":             "tenants/ten_test/payloads/vex.json",
			"payload_hash":            hash,
			"parser_version":          app.ParserVersionCycloneDXVEXJSON,
			"worker_create_decisions": true,
			"evidence_id":             "ev_vex",
			"import_report_id":        "vex_report",
		},
	}
	store := &fakeStateStore{ok: true, state: app.PersistedState{
		VEXDocuments: map[string]domain.VEXDocument{
			"vex_test": {ID: "vex_test", TenantID: "ten_test", ReleaseID: "rel_test", EvidenceID: "ev_vex", Format: "cyclonedx"},
		},
		VEXImportReports: map[string]domain.VEXImportReport{
			"vex_report": {
				ID: "vex_report", TenantID: "ten_test", VEXDocumentID: "vex_test", EvidenceID: "ev_vex", ReleaseID: "rel_test", ParserVersion: app.ParserVersionCycloneDXVEXJSON, Status: "accepted",
				Warnings:          []string{"accepted warning"},
				InvalidStatements: []domain.VEXImportIssue{{StatementIndex: 99, Code: "accepted_issue", Detail: "Preserve this issue."}},
				SchemaVersion:     domain.VEXImportReportSchemaVersion, CreatedAt: now, UpdatedAt: now,
			},
		},
		Scans: map[string]domain.VulnerabilityScan{
			"scan_test": {ID: "scan_test", TenantID: "ten_test", ReleaseID: "rel_test", Findings: []domain.VulnerabilityFinding{{ID: "finding_1", Vulnerability: "CVE-match", Component: "pkg:oci/api"}}},
		},
		Decisions: map[string]domain.VulnerabilityDecision{},
		Chain:     map[string][]domain.AuditChainEntry{},
	}}
	object := app.Object{Key: "tenants/ten_test/payloads/vex.json", TenantID: "ten_test", Digest: hash, Bytes: body}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("process cyclonedx vex job: %v", err)
	}
	if len(store.saved.Decisions) != 1 {
		t.Fatalf("decisions = %#v, want one", store.saved.Decisions)
	}
	for _, decision := range store.saved.Decisions {
		if decision.Source != "cyclonedx_vex" {
			t.Fatalf("decision source = %q, want cyclonedx_vex", decision.Source)
		}
	}
	report := store.saved.VEXImportReports["vex_report"]
	if report.StatementCount != 4 || report.DecisionsCreated != 1 {
		t.Fatalf("report counts = %#v", report)
	}
	if !hasWorkerString(report.Warnings, "accepted warning") || !hasWorkerString(report.Warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.") || !containsWorkerString(report.Warnings, "x-vendor") {
		t.Fatalf("report warnings = %#v", report.Warnings)
	}
	if countWorkerString(report.Warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.") != 1 {
		t.Fatalf("duplicate warning was not idempotent: %#v", report.Warnings)
	}
	if !hasVEXImportIssue(report.InvalidStatements, 99, "accepted_issue") || !hasVEXImportIssue(report.InvalidStatements, 1, "unsupported_analysis_state") {
		t.Fatalf("invalid statements = %#v", report.InvalidStatements)
	}
	if len(report.MappingFailures) != 1 || report.MappingFailures[0].StatementIndex != 3 || report.MappingFailures[0].Code != "finding_not_found" {
		t.Fatalf("mapping failures = %#v", report.MappingFailures)
	}

	previous := store.saved
	store.state = previous
	store.saved = app.PersistedState{}
	if err := processJobWithObjects(context.Background(), store, fakeObjectGetter{object: object}, job); err != nil {
		t.Fatalf("reprocess cyclonedx vex job: %v", err)
	}
	if len(store.saved.Decisions) != 0 || len(previous.Decisions) != 1 || countWorkerString(previous.VEXImportReports["vex_report"].Warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.") != 1 {
		t.Fatalf("replay duplicated side effects: saved=%#v previous=%#v", store.saved.Decisions, previous.Decisions)
	}
}

func hasWorkerString(values []string, want string) bool {
	return countWorkerString(values, want) > 0
}

func containsWorkerString(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func countWorkerString(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

func hasVEXImportIssue(issues []domain.VEXImportIssue, index int, code string) bool {
	for _, issue := range issues {
		if issue.StatementIndex == index && issue.Code == code {
			return true
		}
	}
	return false
}

func TestProcessJobWithObjectsFailsSafelyForParserMismatches(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"api"},{"type":"library","name":"worker"}]}`)
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
	if !changed || attestation.PayloadHash == "" || attestation.PayloadSize == 0 || attestation.PredicateType == "" || len(attestation.SubjectDigests) != 1 || attestation.SignatureCount != 1 || attestation.BuilderID == "" || attestation.BuildType == "" || attestation.MaterialsCount != 2 || attestation.VerificationStatus != "structurally_valid" {
		t.Fatalf("merged attestation = %#v changed=%v", attestation, changed)
	}
	accepted, changed := mergeReplayedAttestation(domain.BuildAttestation{VerificationStatus: "accepted"}, replayedAttestation{}, raw)
	if !changed || accepted.VerificationStatus != "structurally_valid" {
		t.Fatalf("accepted attestation status was not completed: %#v changed=%v", accepted, changed)
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
	if err := runWithArgs([]string{"healthcheck"}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
	if err := runWithArgs([]string{"--healthcheck"}); err != nil {
		t.Fatalf("--healthcheck: %v", err)
	}
	if err := runWithArgs([]string{"unexpected"}); err == nil || !strings.Contains(err.Error(), "unsupported worker command") {
		t.Fatalf("unexpected command err=%v", err)
	}
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
		t.Fatalf("missing database err=%v", err)
	}
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://invalid-host.invalid/evydence")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_SKIP_MIGRATIONS", "true")
	if err := run(); err == nil {
		t.Fatal("expected postgres open failure")
	}
}

func TestWorkerRejectsLocalMemoryProfileBeforeOpeningStorage(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://operator:private-password@127.0.0.1:1/evydence?connect_timeout=1")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "EVYDENCE_RUNTIME_PROFILE") || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("worker profile error = %v", err)
	}
}

func TestWorkerOperatorCommandsRejectLocalMemoryProfileBeforeOpeningStorage(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "local_memory")
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://operator:private-password@127.0.0.1:1/evydence?connect_timeout=1")
	commands := []struct {
		name string
		run  func() error
	}{
		{"parser replay", func() error {
			return runParserReplay([]string{"--tenant", "ten_1", "--evidence", "ev_1", "--parser-version", "v1", "--actor", "operator", "--apply"})
		}},
		{"reconciliation", func() error {
			return runObjectReconciliation([]string{"--tenant", "ten_1"})
		}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			if err := command.run(); err == nil || !strings.Contains(err.Error(), "EVYDENCE_RUNTIME_PROFILE") || strings.Contains(err.Error(), "private-password") {
				t.Fatalf("unsafe operator profile error = %v", err)
			}
		})
	}
}

func TestParseObjectReconciliationArgsDefaultsToDryRunAndRequiresSafeApplyThreshold(t *testing.T) {
	request, err := parseObjectReconciliationArgs([]string{"--tenant", "ten_reconcile", "--metadata-cursor", "2", "--provider-cursor", "3", "--limit", "10", "--provider-limit", "20"})
	if err != nil || request.Apply || request.TenantID != "ten_reconcile" || request.MetadataCursor != 2 || request.ProviderCursor != 3 || request.Limit != 10 || request.ProviderInventoryLimit != 20 {
		t.Fatalf("dry-run reconciliation request=%#v err=%v", request, err)
	}
	request, err = parseObjectReconciliationArgs([]string{"--tenant", "ten_reconcile", "--apply", "--orphan-staged-after", "2h"})
	if err != nil || !request.Apply || request.OrphanStagedAfter != 2*time.Hour {
		t.Fatalf("apply reconciliation request=%#v err=%v", request, err)
	}
	for _, args := range [][]string{
		{},
		{"--tenant", "ten_reconcile", "--apply"},
		{"--tenant", "ten_reconcile", "--unknown"},
	} {
		if _, err := parseObjectReconciliationArgs(args); err == nil {
			t.Fatalf("unsafe reconciliation args %q were accepted", args)
		}
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

func TestClassifyWorkerFailureUsesStableSafeCodes(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		class postgres.JobFailureClass
		code  string
	}{
		{name: "interrupted", err: context.Canceled, class: postgres.JobFailureTransient, code: "worker_interrupted"},
		{name: "unsupported parser", err: errors.New("unsupported outbox parser version secret-value"), class: postgres.JobFailurePoisoned, code: "payload_invariant_failed"},
		{name: "object unavailable", err: errors.New("read outbox payload object: https://secret.example.test/token"), class: postgres.JobFailureTransient, code: "payload_store_unavailable"},
		{name: "unknown", err: errors.New("postgres://user:super-secret@database.internal failed"), class: postgres.JobFailureTransient, code: "worker_processing_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failure := classifyWorkerFailure(tt.err)
			if failure.Class != tt.class || failure.Code != tt.code {
				t.Fatalf("failure=%#v, want class=%q code=%q", failure, tt.class, tt.code)
			}
			if strings.Contains(failure.Code, "secret") || strings.Contains(failure.Code, "database") {
				t.Fatalf("failure code leaked source error: %#v", failure)
			}
		})
	}
}

func TestPrioritizePayloadFinalizationKeepsOtherJobsStable(t *testing.T) {
	jobs := []postgres.ClaimedJob{
		{ID: "parse-first", Kind: "parse_sbom"},
		{ID: "finalize-first", Kind: "finalize_payload"},
		{ID: "parse-second", Kind: "parse_vulnerability_scan"},
		{ID: "finalize-second", Kind: "finalize_payload"},
	}
	prioritizePayloadFinalization(jobs)
	got := []string{jobs[0].ID, jobs[1].ID, jobs[2].ID, jobs[3].ID}
	want := []string{"finalize-first", "finalize-second", "parse-first", "parse-second"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("prioritized jobs=%v, want %v", got, want)
	}
}

func TestParserReplayRequiresExplicitScopedApply(t *testing.T) {
	for _, args := range [][]string{{}, {"--tenant", "ten_test", "--evidence", "ev_test", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator"}} {
		if err := runParserReplay(args); err == nil || !strings.Contains(err.Error(), "requires --tenant") {
			t.Fatalf("runParserReplay(%q) err=%v", args, err)
		}
	}
	t.Setenv("EVYDENCE_DATABASE_URL", "")
	args := []string{"--tenant", "ten_test", "--evidence", "ev_test", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator", "--apply"}
	if err := runParserReplay(args); err == nil || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
		t.Fatalf("runParserReplay valid args without database err=%v", err)
	}
}

func TestRunParserReplayRejectsUnsafeObjectStoreBeforeDatabaseOpen(t *testing.T) {
	t.Setenv("ENV", "")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	t.Setenv("EVYDENCE_POSTGRES_LOAD_MODE", "relational_only")
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://operator:private-password@127.0.0.1:1/evydence?connect_timeout=1")
	t.Setenv("EVYDENCE_OBJECT_STORE", "unsupported")
	args := []string{"--tenant", "ten_test", "--evidence", "ev_test", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator", "--apply"}
	if err := runParserReplay(args); err == nil || !strings.Contains(err.Error(), "EVYDENCE_OBJECT_STORE") || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("unsafe parser-replay storage selection err=%v", err)
	}
}

func TestParseParserReplayArgsRejectsUnsafeInputAndNormalizesScope(t *testing.T) {
	request, err := parseParserReplayArgs([]string{"--tenant", " ten_test ", "--evidence", " ev_test ", "--parser-version", " " + app.ParserVersionSPDXJSON + " ", "--actor", " operator ", "--apply"})
	if err != nil || request.TenantID != "ten_test" || request.EvidenceID != "ev_test" || request.ParserVersion != app.ParserVersionSPDXJSON || request.ActorID != "operator" {
		t.Fatalf("parser replay request=%#v err=%v", request, err)
	}
	for _, args := range [][]string{
		{"--tenant", "ten_test", "--evidence", "ev_test", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator"},
		{"--tenant", "ten_test", "--evidence", "ev_test", "--parser-version", app.ParserVersionSPDXJSON, "--actor", "operator", "--apply", "unexpected"},
		{"--tenant", "ten_test", "--unknown", "value", "--apply"},
	} {
		if _, err := parseParserReplayArgs(args); err == nil {
			t.Fatalf("unsafe parser replay arguments were accepted: %q", args)
		}
	}
}

type replayStoreStub struct {
	state            app.PersistedState
	saved            int
	broadSaves       int
	focusedMutations int
	applyCalls       int
	applyErr         error
	afterLoad        func(*app.PersistedState)
	closed           bool
}

func (s *replayStoreStub) Close()                                                   { s.closed = true }
func (s *replayStoreStub) ApplyMigrations(context.Context, string) (int, error)     { return 0, nil }
func (s *replayStoreStub) RequireNoPendingMigrations(context.Context, string) error { return nil }
func (s *replayStoreStub) LoadState(context.Context) (app.PersistedState, bool, error) {
	body, err := json.Marshal(s.state)
	if err != nil {
		return app.PersistedState{}, false, err
	}
	var snapshot app.PersistedState
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return app.PersistedState{}, false, err
	}
	if s.afterLoad != nil {
		afterLoad := s.afterLoad
		s.afterLoad = nil
		afterLoad(&s.state)
	}
	return snapshot, true, nil
}
func (s *replayStoreStub) SaveState(_ context.Context, state app.PersistedState) error {
	s.state, s.saved, s.broadSaves = state, s.saved+1, s.broadSaves+1
	return nil
}

func (s *replayStoreStub) ApplyParserReplay(_ context.Context, request app.ParserReplayRequest, mutation app.ReleaseLedgerMutation) (string, bool, error) {
	s.applyCalls++
	if s.applyErr != nil {
		return "", false, s.applyErr
	}
	for _, item := range s.state.Evidence {
		parser, _ := item.Metadata["parser"].(map[string]any)
		version, _ := parser["version"].(string)
		replayOf, _ := item.Metadata["replay_of"].(string)
		if item.TenantID == request.TenantID && item.Type == "parser_normalization" && replayOf == request.EvidenceID && version == request.ParserVersion {
			return item.ID, false, nil
		}
	}
	if len(mutation.Evidence) != 1 {
		return "", false, errors.New("invalid focused parser replay mutation")
	}
	if s.state.Evidence == nil {
		s.state.Evidence = map[string]domain.EvidenceItem{}
	}
	if s.state.Chain == nil {
		s.state.Chain = map[string][]domain.AuditChainEntry{}
	}
	for _, item := range mutation.Evidence {
		s.state.Evidence[item.ID] = item
	}
	for _, entry := range mutation.AuditChainEntries {
		s.state.Chain[entry.TenantID] = append(s.state.Chain[entry.TenantID], entry)
	}
	s.saved++
	s.focusedMutations++
	return mutation.Evidence[0].ID, true, nil
}

type replayObjectStoreStub struct{ object app.Object }

func (s replayObjectStoreStub) Put(context.Context, app.Object) error           { return nil }
func (s replayObjectStoreStub) Get(context.Context, string) (app.Object, error) { return s.object, nil }

func useParserReplayRuntimeStub(t *testing.T, store *replayStoreStub, object app.Object) {
	t.Helper()
	previous := openParserReplayRuntime
	t.Cleanup(func() { openParserReplayRuntime = previous })
	openParserReplayRuntime = func(context.Context, wiring.RuntimeConfig) (parserReplayRuntime, error) {
		return parserReplayRuntime{store: store, objects: replayObjectStoreStub{object: object}, close: store.Close}, nil
	}
}

func TestRunParserReplayAppendsVerifiedDerivedRecordAndIsIdempotent(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	digest := digestBytes(raw)
	stub := &replayStoreStub{state: app.PersistedState{Evidence: map[string]domain.EvidenceItem{"ev_source": {ID: "ev_source", TenantID: "ten_test", Type: "vulnerability_scan", PayloadHash: digest, PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: time.Now().UTC()}}, Chain: map[string][]domain.AuditChainEntry{}}}
	useParserReplayRuntimeStub(t, stub, app.Object{Key: "tenants/ten_test/payloads/source", TenantID: "ten_test", Digest: digest, Bytes: raw})
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://test")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	args := []string{"--tenant", "ten_test", "--evidence", "ev_source", "--parser-version", app.ParserVersionScannerAdaptersJSON, "--actor", "operator", "--apply"}
	if err := runParserReplay(args); err != nil || stub.saved != 1 || stub.focusedMutations != 1 || stub.broadSaves != 0 || len(stub.state.Evidence) != 2 || !stub.closed {
		t.Fatalf("first replay err=%v saved=%d state=%#v closed=%v", err, stub.saved, stub.state, stub.closed)
	}
	if err := runParserReplay(args); err != nil || stub.saved != 1 {
		t.Fatalf("idempotent replay err=%v saved=%d", err, stub.saved)
	}
	if stub.applyCalls != 2 {
		t.Fatalf("durable parser replay applications=%d, want 2", stub.applyCalls)
	}
}

func TestRunParserReplayRoutesExistingMarkerThroughDurableValidation(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	digest := digestBytes(raw)
	stub := &replayStoreStub{
		state: app.PersistedState{Evidence: map[string]domain.EvidenceItem{
			"ev_source": {
				ID: "ev_source", TenantID: "ten_test", Type: "vulnerability_scan", PayloadHash: digest,
				PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: time.Now().UTC(),
			},
			"ev_forged": {
				ID: "ev_forged", TenantID: "ten_test", Type: "parser_normalization",
				Metadata: map[string]any{
					"replay_of": "ev_source",
					"parser":    map[string]any{"version": app.ParserVersionScannerAdaptersJSON},
				},
			},
		}, Chain: map[string][]domain.AuditChainEntry{}},
		applyErr: errors.New("invalid durable parser replay marker"),
	}
	useParserReplayRuntimeStub(t, stub, app.Object{Key: "tenants/ten_test/payloads/source", TenantID: "ten_test", Digest: digest, Bytes: raw})
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://test")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	args := []string{"--tenant", "ten_test", "--evidence", "ev_source", "--parser-version", app.ParserVersionScannerAdaptersJSON, "--actor", "operator", "--apply"}

	if err := runParserReplay(args); err == nil || !strings.Contains(err.Error(), "could not persist") {
		t.Fatalf("runParserReplay error=%v, want durable validation failure", err)
	}
	if stub.applyCalls != 1 || stub.saved != 0 || stub.focusedMutations != 0 {
		t.Fatalf("durable validation path was bypassed: %#v", stub)
	}
}

func TestRunParserReplayDoesNotOverwriteConcurrentWorkerProjection(t *testing.T) {
	raw := []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
	digest := digestBytes(raw)
	stub := &replayStoreStub{state: app.PersistedState{
		Evidence: map[string]domain.EvidenceItem{"ev_source": {
			ID: "ev_source", TenantID: "ten_test", Type: "vulnerability_scan", PayloadHash: digest,
			PayloadRef: "object://tenants/ten_test/payloads/source", CreatedAt: time.Now().UTC(),
		}},
		Scans: map[string]domain.VulnerabilityScan{"scan_worker": {
			ID: "scan_worker", TenantID: "ten_test", EvidenceID: "ev_source", Scanner: "accepted",
			CreatedAt: time.Now().UTC(),
		}},
		Chain: map[string][]domain.AuditChainEntry{},
	}}
	stub.afterLoad = func(state *app.PersistedState) {
		scan := state.Scans["scan_worker"]
		scan.Scanner = "worker-hydrated"
		scan.TargetRef = "pkg:oci/api"
		scan.Summary = map[string]int{}
		state.Scans[scan.ID] = scan
	}
	useParserReplayRuntimeStub(t, stub, app.Object{Key: "tenants/ten_test/payloads/source", TenantID: "ten_test", Digest: digest, Bytes: raw})
	t.Setenv("EVYDENCE_DATABASE_URL", "postgres://test")
	t.Setenv("EVYDENCE_RUNTIME_PROFILE", "postgres")
	args := []string{"--tenant", "ten_test", "--evidence", "ev_source", "--parser-version", app.ParserVersionScannerAdaptersJSON, "--actor", "operator", "--apply"}
	if err := runParserReplay(args); err != nil {
		t.Fatalf("runParserReplay: %v", err)
	}
	if got := stub.state.Scans["scan_worker"].Scanner; got != "worker-hydrated" {
		t.Fatalf("concurrent worker projection scanner = %q, want worker-hydrated", got)
	}
	if stub.focusedMutations != 1 || stub.broadSaves != 0 {
		t.Fatalf("focused mutations=%d broad saves=%d", stub.focusedMutations, stub.broadSaves)
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

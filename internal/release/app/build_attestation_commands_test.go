package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestBuildAttestationCommandsValidateDependencies(t *testing.T) {
	f, tx, _, raw := focusedAttestationFixture(t)
	config := focusedAttestationConfig(f, tx)
	for _, name := range []string{"reader", "transactions", "authorizer", "parser", "stager", "clock", "ids"} {
		t.Run(name, func(t *testing.T) {
			missing := config
			switch name {
			case "reader":
				missing.Reader = nil
			case "transactions":
				missing.Transactions = nil
			case "authorizer":
				missing.Authorizer = nil
			case "parser":
				missing.AttestationParser = nil
			case "stager":
				missing.PayloadStager = nil
			case "clock":
				missing.Clock = nil
			case "ids":
				missing.IDs = nil
			}
			if command, err := NewBuildAttestationCommands(missing); command != nil || !errors.Is(err, ErrValidation) {
				t.Fatalf("missing %s: command=%v err=%v", name, command, err)
			}
		})
	}
	var command *BuildAttestationCommands
	if v, err := command.UploadBuildAttestation(context.Background(), f.actor, "build_1", raw); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(v, releasedomain.BuildAttestation{}) {
		t.Fatalf("nil command: value=%#v err=%v", v, err)
	}
}

func TestBuildAttestationCommandsUseOnlyFocusedPortsAndPreserveWorkerOwnership(t *testing.T) {
	for _, status := range []string{"inline", "staged", "finalized"} {
		t.Run(status, func(t *testing.T) {
			f, tx, build, raw := focusedAttestationFixture(t)
			if status != "inline" {
				f.payloadStager.result = StagedBuildAttestationPayload{
					TenantID: f.actor.TenantID, Digest: testAttestationDigest(raw), Size: int64(len(raw)),
					MediaType: BuildAttestationMediaType, Status: status, StagingKey: "staging",
					FinalKey: "tenants/ten_1/payload", Reference: "object://tenants/ten_1/payload",
				}
			}
			config := focusedAttestationConfig(f, tx)
			config.WorkerOwnedParsers = true
			command, err := NewBuildAttestationCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := command.UploadBuildAttestation(context.Background(), f.actor, build.ID, raw)
			if err != nil {
				t.Fatal(err)
			}
			if result.EvidenceID != "ev_1" || result.BuildID != build.ID || result.VerificationStatus != "structurally_valid" || result.BuilderID != "builder" || result.SignatureCount != 1 {
				t.Fatalf("parsed response: %#v", result)
			}
			if tx.commits != 1 || tx.rollbacks != 0 || tx.calls != 1 || len(tx.state.evidence) != 1 || len(tx.state.attestations) != 1 || len(tx.state.audit) != 1 || len(tx.state.outbox) != 1 {
				t.Fatalf("effects: tx=%#v", tx)
			}
			stored := tx.state.attestations[result.ID]
			action := "build_attestation.created"
			if status == "inline" {
				if !reflect.DeepEqual(stored, result) {
					t.Fatalf("inline projection=%#v, response=%#v", stored, result)
				}
			} else {
				action = "build_attestation.accepted"
				if stored.VerificationStatus != "accepted" || stored.PayloadType != "" || stored.PredicateType != "" || stored.SubjectDigests != nil || stored.BuilderID != "" || stored.BuildType != "" || stored.MaterialsCount != 0 || stored.SignatureCount != 0 || stored.EvidenceID != result.EvidenceID || stored.PayloadHash != result.PayloadHash {
					t.Fatalf("worker-owned projection=%#v", stored)
				}
			}
			input := tx.state.evidence[0].input
			if input.BuildID != build.ID || input.ProjectID != build.ProjectID || input.ReleaseID != build.ReleaseID || input.ProductID != "prod_1" || input.PayloadHash != testAttestationDigest(raw) || input.PayloadSize != int64(len(raw)) || input.ParserVersion != BuildAttestationParserVersion || !reflect.DeepEqual(input.SourceIdentity, build.SourceIdentity) || !reflect.DeepEqual(input.Subjects, buildAttestationEvidenceSubjects(build.Outputs)) {
				t.Fatalf("evidence input=%#v", input)
			}
			if tx.state.audit[0].EntryType != action || tx.state.audit[0].PayloadHash != result.PayloadHash {
				t.Fatalf("audit=%#v", tx.state.audit)
			}
			job := tx.state.outbox[0]
			if job.Kind != "verify_attestation" || job.SubjectID != result.ID || job.Payload["parser_version"] != BuildAttestationParserVersion || job.Payload["payload_hash"] != result.PayloadHash {
				t.Fatalf("job=%#v", job)
			}
			_, managed := job.Payload["payload_lifecycle"]
			if managed != (status == "staged") {
				t.Fatalf("managed payload marker: %#v", job.Payload)
			}
			if len(f.authorizer.requests) != 3 || !f.authorizer.requests[0].ScopeOnly || f.attestationParser.authorizerCallsAtParse != 3 || f.payloadStager.authorizerCallsAtStage != 3 {
				t.Fatalf("authorization order=%#v", f.authorizer.requests)
			}
		})
	}
}

func TestBuildAttestationCommandsReturnNoResultOnEveryFailedEffectOrCommit(t *testing.T) {
	for _, step := range []string{"evidence", "empty receipt", "attestation", "audit", "outbox", "commit"} {
		t.Run(step, func(t *testing.T) {
			f, tx, build, raw := focusedAttestationFixture(t)
			failure := errors.New("injected " + step)
			switch step {
			case "evidence":
				tx.evidenceErr = failure
			case "empty receipt":
				tx.emptyReceipt = true
				failure = ErrConflict
			case "attestation":
				tx.buildAttestationErr = failure
			case "audit":
				tx.auditErr = failure
			case "outbox":
				tx.outboxErr = failure
			case "commit":
				tx.commitErr = failure
			}
			command, err := NewBuildAttestationCommands(focusedAttestationConfig(f, tx))
			if err != nil {
				t.Fatal(err)
			}
			result, err := command.UploadBuildAttestation(context.Background(), f.actor, build.ID, raw)
			if !errors.Is(err, failure) || !reflect.DeepEqual(result, releasedomain.BuildAttestation{}) {
				t.Fatalf("result=%#v err=%v, want zero and %v", result, err, failure)
			}
			assertFocusedAttestationRollback(t, tx)
		})
	}
}

func TestBuildAttestationCommandsRevalidateAllCoordinates(t *testing.T) {
	for _, resource := range []string{"project", "release", "build", "artifact"} {
		t.Run(resource, func(t *testing.T) {
			f, tx, build, raw := focusedAttestationFixture(t)
			tx.beforeCommand = func(state *fakeState) {
				switch resource {
				case "project":
					v := state.projects[build.ProjectID]
					v.ProductID = "changed"
					state.projects[v.ID] = v
				case "release":
					v := state.releases[build.ReleaseID]
					v.Version = "changed"
					state.releases[v.ID] = v
				case "build":
					v := state.builds[build.ID]
					v.SourceIdentity = map[string]any{"provider": "changed"}
					state.builds[v.ID] = v
				case "artifact":
					v := state.artifacts[build.Outputs[0].ArtifactID]
					v.Digest = "sha256:" + strings.Repeat("b", 64)
					state.artifacts[v.ID] = v
				}
			}
			command, err := NewBuildAttestationCommands(focusedAttestationConfig(f, tx))
			if err != nil {
				t.Fatal(err)
			}
			result, err := command.UploadBuildAttestation(context.Background(), f.actor, build.ID, raw)
			if !errors.Is(err, ErrConflict) || !reflect.DeepEqual(result, releasedomain.BuildAttestation{}) {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			assertFocusedAttestationRollback(t, tx)
		})
	}
}

func TestBuildAttestationCommandsRejectUnauthorizedOrMalformedScopeBeforePayload(t *testing.T) {
	for _, name := range []string{"scope", "build grant", "artifact grant", "foreign build", "foreign project", "foreign release", "foreign artifact", "product mismatch", "artifact digest", "output digest", "empty build", "nil context", "cancelled context", "empty source", "oversized source"} {
		t.Run(name, func(t *testing.T) {
			f, tx, build, raw := focusedAttestationFixture(t)
			ctx := context.Background()
			source := BytesBuildAttestationPayloadSource(raw)
			want := ErrNotFound
			switch name {
			case "scope", "build grant", "artifact grant":
				want = application.ErrForbidden
				f.authorizer.authorize = func(request application.AuthorizationRequest) error {
					if name == "scope" && request.ScopeOnly || name == "build grant" && request.Resources.BuildID != "" || name == "artifact grant" && request.Resources.ArtifactID != "" {
						return application.ErrForbidden
					}
					return nil
				}
			case "foreign build":
				build.TenantID = "other"
				f.reader.builds[build.ID] = build
			case "foreign project", "product mismatch":
				v := f.reader.projects[build.ProjectID]
				if name == "foreign project" {
					v.TenantID = "other"
				} else {
					v.ProductID = "other"
				}
				f.reader.projects[v.ID] = v
			case "foreign release":
				v := f.reader.releases[build.ReleaseID]
				v.TenantID = "other"
				f.reader.releases[v.ID] = v
			case "foreign artifact", "artifact digest":
				v := f.reader.artifacts[build.Outputs[0].ArtifactID]
				if name == "foreign artifact" {
					v.TenantID = "other"
				} else {
					v.Digest = "sha256:" + strings.Repeat("b", 64)
					want = ErrValidation
				}
				f.reader.artifacts[v.ID] = v
			case "output digest":
				build.Outputs = []releasedomain.BuildOutput{{Digest: "not-a-digest"}}
				f.reader.builds[build.ID] = build
				want = ErrValidation
			case "empty build":
				build.ID = " "
			case "nil context":
				ctx = nil
				want = ErrValidation
			case "cancelled context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "empty source":
				source.Open = nil
				want = ErrValidation
			case "oversized source":
				source.Size = buildAttestationPayloadLimit + 1
				want = ErrValidation
			}
			command, err := NewBuildAttestationCommands(focusedAttestationConfig(f, tx))
			if err != nil {
				t.Fatal(err)
			}
			v, err := command.UploadBuildAttestationPayload(ctx, f.actor, build.ID, source)
			if !errors.Is(err, want) || !reflect.DeepEqual(v, releasedomain.BuildAttestation{}) || f.attestationParser.calls != 0 || f.payloadStager.calls != 0 || tx.calls != 0 {
				t.Fatalf("value=%#v err=%v want=%v parser=%d stager=%d tx=%d", v, err, want, f.attestationParser.calls, f.payloadStager.calls, tx.calls)
			}
		})
	}
}

func TestBuildAttestationCommandsValidateParserAndStagerBindings(t *testing.T) {
	for _, name := range []string{"parser error", "parser digest", "parser size", "parser version", "unbound subjects", "negative signatures", "stager error", "stager tenant", "stager digest", "stager size", "stager media", "stager reference", "stager status", "missing staging key"} {
		t.Run(name, func(t *testing.T) {
			f, tx, build, raw := focusedAttestationFixture(t)
			f.payloadStager.result = StagedBuildAttestationPayload{TenantID: f.actor.TenantID, Digest: testAttestationDigest(raw), Size: int64(len(raw)), MediaType: BuildAttestationMediaType, Status: "staged", StagingKey: "staging", FinalKey: "payload", Reference: "object://payload"}
			want := ErrValidation
			switch name {
			case "parser error":
				want = errors.New("parser unavailable")
				f.attestationParser.err = want
			case "parser digest":
				f.attestationParser.result.PayloadHash = "sha256:" + strings.Repeat("b", 64)
			case "parser size":
				f.attestationParser.result.PayloadSize++
			case "parser version":
				f.attestationParser.result.ParserVersion = "unknown"
			case "unbound subjects":
				f.attestationParser.result.SubjectDigests = []string{"sha256:" + strings.Repeat("b", 64)}
			case "negative signatures":
				f.attestationParser.result.SignatureCount = -1
			case "stager error":
				want = errors.New("storage unavailable")
				f.payloadStager.err = want
			case "stager tenant":
				f.payloadStager.result.TenantID = "other"
			case "stager digest":
				f.payloadStager.result.Digest = "sha256:" + strings.Repeat("b", 64)
			case "stager size":
				f.payloadStager.result.Size++
			case "stager media":
				f.payloadStager.result.MediaType = "text/plain"
			case "stager reference":
				f.payloadStager.result.Reference = "object://wrong"
			case "stager status":
				f.payloadStager.result.Status = "orphaned"
			case "missing staging key":
				f.payloadStager.result.StagingKey = ""
			}
			command, err := NewBuildAttestationCommands(focusedAttestationConfig(f, tx))
			if err != nil {
				t.Fatal(err)
			}
			v, err := command.UploadBuildAttestation(context.Background(), f.actor, build.ID, raw)
			wantStages := 1
			if strings.HasPrefix(name, "parser") || name == "unbound subjects" || name == "negative signatures" {
				wantStages = 0
			}
			if !errors.Is(err, want) || !reflect.DeepEqual(v, releasedomain.BuildAttestation{}) || f.attestationParser.calls != 1 || f.payloadStager.calls != wantStages || tx.calls != 0 {
				t.Fatalf("value=%#v err=%v want=%v parser=%d stager=%d want-stager=%d tx=%d", v, err, want, f.attestationParser.calls, f.payloadStager.calls, wantStages, tx.calls)
			}
		})
	}
}

func focusedAttestationFixture(t *testing.T) (*serviceFixture, *focusedAttestationTransactions, releasedomain.BuildRun, []byte) {
	t.Helper()
	f := newServiceFixture(t)
	build, artifact := seedBuildAttestationFixture(f)
	raw := []byte(`{"payload":"attestation"}`)
	f.attestationParser.result = ParsedBuildAttestation{
		PayloadHash: testAttestationDigest(raw), PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
		PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{artifact.Digest}, BuilderID: "builder", BuildType: "build-type", MaterialsCount: 2, SignatureCount: 1,
	}
	return f, &focusedAttestationTransactions{state: f.transactions.state.clone()}, build, raw
}

func focusedAttestationConfig(f *serviceFixture, tx *focusedAttestationTransactions) BuildAttestationCommandConfig {
	return BuildAttestationCommandConfig{
		Reader: focusedAttestationReader{f.reader}, Transactions: tx, Authorizer: f.authorizer,
		AttestationParser: f.attestationParser, PayloadStager: f.payloadStager,
		Clock: f.service.clock, IDs: f.service.ids,
	}
}

// This reader deliberately exposes no product/candidate/list methods.
type focusedAttestationReader struct{ reader *fakeReader }

func (r focusedAttestationReader) GetProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	return r.reader.GetProject(ctx, tenant, id)
}
func (r focusedAttestationReader) GetRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	return r.reader.GetRelease(ctx, tenant, id)
}
func (r focusedAttestationReader) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	return r.reader.GetArtifact(ctx, tenant, id)
}
func (r focusedAttestationReader) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	return r.reader.GetBuildRun(ctx, tenant, id)
}

type focusedAttestationTransactions struct {
	state                                                            fakeState
	calls, commits, rollbacks                                        int
	beforeCommand                                                    func(*fakeState)
	evidenceErr, buildAttestationErr, auditErr, outboxErr, commitErr error
	emptyReceipt                                                     bool
}

func (r *focusedAttestationTransactions) ExecuteBuildAttestation(ctx context.Context, fn func(context.Context, BuildAttestationTransaction) error) error {
	r.calls++
	pending := r.state.clone()
	if r.beforeCommand != nil {
		r.beforeCommand(&pending)
	}
	tx := focusedAttestationTransaction{state: &pending, runner: r}
	if err := fn(ctx, tx); err != nil {
		r.rollbacks++
		return err
	}
	if r.commitErr != nil {
		r.rollbacks++
		return r.commitErr
	}
	r.state = pending
	r.commits++
	return nil
}

// No Catalog/Builds/Audit/Outbox service-locator methods are available here.
type focusedAttestationTransaction struct {
	state  *fakeState
	runner *focusedAttestationTransactions
}

func (t focusedAttestationTransaction) GetProject(ctx context.Context, tenant, id string) (releasedomain.Project, error) {
	return (fakeCatalog{state: t.state}).GetProject(ctx, tenant, id)
}
func (t focusedAttestationTransaction) GetRelease(ctx context.Context, tenant, id string) (releasedomain.Release, error) {
	return (fakeCatalog{state: t.state}).GetRelease(ctx, tenant, id)
}
func (t focusedAttestationTransaction) GetArtifact(ctx context.Context, tenant, id string) (releasedomain.Artifact, error) {
	return (fakeCatalog{state: t.state}).GetArtifact(ctx, tenant, id)
}
func (t focusedAttestationTransaction) GetBuildRun(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	return (fakeBuildRepository{state: t.state}).GetBuildRun(ctx, tenant, id)
}
func (t focusedAttestationTransaction) WriteBuildAttestationEvidence(ctx context.Context, actor identitydomain.Actor, input BuildAttestationEvidenceInput) (BuildAttestationEvidenceReceipt, error) {
	if t.runner.emptyReceipt {
		return BuildAttestationEvidenceReceipt{}, nil
	}
	return (fakeBuildAttestationEvidenceWriter{state: t.state, err: t.runner.evidenceErr}).WriteBuildAttestationEvidence(ctx, actor, input)
}
func (t focusedAttestationTransaction) InsertBuildAttestation(ctx context.Context, value releasedomain.BuildAttestation) error {
	return (fakeBuildRepository{state: t.state, attestationErr: t.runner.buildAttestationErr}).InsertBuildAttestation(ctx, value)
}
func (t focusedAttestationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return (fakeAudit{state: t.state, err: t.runner.auditErr}).AppendAudit(ctx, event)
}
func (t focusedAttestationTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	return (fakeOutbox{state: t.state, err: t.runner.outboxErr}).EnqueueOutbox(ctx, event)
}

func assertFocusedAttestationRollback(t *testing.T, tx *focusedAttestationTransactions) {
	t.Helper()
	if tx.commits != 0 || tx.rollbacks != 1 || len(tx.state.evidence) != 0 || len(tx.state.attestations) != 0 || len(tx.state.audit) != 0 || len(tx.state.outbox) != 0 {
		t.Fatalf("failed command leaked effects: %#v", tx)
	}
}

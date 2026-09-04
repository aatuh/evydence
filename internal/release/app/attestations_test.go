package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestUploadBuildAttestationPayloadValidatesScopeBeforePayloadAndCommitsOneTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	build, artifact := seedBuildAttestationFixture(fixture)
	fixture.actor = identitydomain.Actor{TenantID: "ten_1", UserID: "usr_1", SessionID: "sess_1", Scopes: []string{"*"}}
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)
	fixture.attestationParser.result = ParsedBuildAttestation{
		PayloadHash: digest, PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
		PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{artifact.Digest}, BuilderID: "builder", BuildType: "build-type",
		MaterialsCount: 2, SignatureCount: 1,
	}
	fixture.payloadStager.result = StagedBuildAttestationPayload{
		TenantID: fixture.actor.TenantID, Digest: digest, Size: int64(len(raw)),
		MediaType: BuildAttestationMediaType, Reference: "object://tenants/ten_1/payloads/attestation",
		Status: "staged", StagingKey: "staging", FinalKey: "tenants/ten_1/payloads/attestation",
	}

	attestation, err := fixture.service.UploadBuildAttestationPayload(
		context.Background(), fixture.actor, build.ID,
		BuildAttestationPayloadSource{Digest: digest, Size: int64(len(raw)), Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(string(raw))), nil
		}},
	)
	if err != nil {
		t.Fatalf("UploadBuildAttestationPayload: %v", err)
	}
	if fixture.attestationParser.calls != 1 || fixture.payloadStager.calls != 1 {
		t.Fatalf("payload work parser=%d stager=%d, want one each", fixture.attestationParser.calls, fixture.payloadStager.calls)
	}
	if fixture.attestationParser.authorizerCallsAtParse < 3 || fixture.payloadStager.authorizerCallsAtStage < 3 {
		t.Fatalf("payload work ran before resource authorization: parser=%d stager=%d", fixture.attestationParser.authorizerCallsAtParse, fixture.payloadStager.authorizerCallsAtStage)
	}
	if len(fixture.authorizer.requests) != 3 || !fixture.authorizer.requests[0].ScopeOnly {
		t.Fatalf("authorization requests = %#v", fixture.authorizer.requests)
	}
	wantBuildResources := application.ResourceReferences{ProductID: "prod_1", ProjectID: build.ProjectID, ReleaseID: build.ReleaseID, BuildID: build.ID}
	if fixture.authorizer.requests[1].Scope != ScopeBuildWrite || fixture.authorizer.requests[1].Resources != wantBuildResources {
		t.Fatalf("build authorization = %#v, want %#v", fixture.authorizer.requests[1], wantBuildResources)
	}
	wantArtifactResources := application.ResourceReferences{ArtifactID: artifact.ID}
	if fixture.authorizer.requests[2].Scope != ScopeBuildWrite || fixture.authorizer.requests[2].Resources != wantArtifactResources {
		t.Fatalf("artifact authorization = %#v, want %#v", fixture.authorizer.requests[2], wantArtifactResources)
	}
	if fixture.transactions.calls != 1 || fixture.transactions.commits != 1 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
	if attestation.BuildID != build.ID || attestation.EvidenceID != "ev_1" || attestation.PayloadHash != digest || attestation.VerificationStatus != "structurally_valid" {
		t.Fatalf("attestation = %#v", attestation)
	}
	stored, ok := fixture.transactions.state.attestations[attestation.ID]
	if !ok || stored.EvidenceID != "ev_1" || stored.VerificationStatus != "structurally_valid" {
		t.Fatalf("stored attestation = %#v, ok=%t", stored, ok)
	}
	if len(fixture.transactions.state.evidence) != 1 {
		t.Fatalf("evidence commands = %#v", fixture.transactions.state.evidence)
	}
	evidence := fixture.transactions.state.evidence[0]
	if evidence.input.BuildID != build.ID || evidence.input.ProjectID != build.ProjectID || evidence.input.ReleaseID != build.ReleaseID || evidence.actor.UserID != fixture.actor.UserID {
		t.Fatalf("evidence command = %#v", evidence)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	audit := fixture.transactions.state.audit[0]
	if audit.EntryType != "build_attestation.created" || audit.ActorType != "human_user" || audit.ActorID != fixture.actor.UserID {
		t.Fatalf("audit = %#v", audit)
	}
	if len(fixture.transactions.state.outbox) != 1 || fixture.transactions.state.outbox[0].Kind != "verify_attestation" {
		t.Fatalf("outbox = %#v", fixture.transactions.state.outbox)
	}
	if got := fixture.transactions.state.outbox[0].Payload["parser_version"]; got != BuildAttestationParserVersion {
		t.Fatalf("parser_version = %#v", got)
	}
}

func TestUploadBuildAttestationPayloadRejectsResourceBeforePayloadWork(t *testing.T) {
	fixture := newServiceFixture(t)
	build, _ := seedBuildAttestationFixture(fixture)
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.BuildID != "" {
			return errDenied
		}
		return nil
	}
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)

	_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BuildAttestationPayloadSource{
		Digest: digest, Size: int64(len(raw)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(raw))), nil },
	})
	if !errors.Is(err, errDenied) {
		t.Fatalf("error = %v, want denied", err)
	}
	if fixture.attestationParser.calls != 0 || fixture.payloadStager.calls != 0 || fixture.transactions.calls != 0 {
		t.Fatalf("denied command touched parser=%d stager=%d transactions=%d", fixture.attestationParser.calls, fixture.payloadStager.calls, fixture.transactions.calls)
	}
}

func TestUploadBuildAttestationPayloadRequiresArtifactOnlyAuthorizationBeforePayloadWork(t *testing.T) {
	fixture := newServiceFixture(t)
	build, artifact := seedBuildAttestationFixture(fixture)
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: artifact.ID}) {
			return errDenied
		}
		return nil
	}
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)

	_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BuildAttestationPayloadSource{
		Digest: digest, Size: int64(len(raw)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(raw))), nil },
	})
	if !errors.Is(err, errDenied) {
		t.Fatalf("error = %v, want denied", err)
	}
	if fixture.attestationParser.calls != 0 || fixture.payloadStager.calls != 0 || fixture.transactions.calls != 0 {
		t.Fatalf("denied command touched parser=%d stager=%d transactions=%d", fixture.attestationParser.calls, fixture.payloadStager.calls, fixture.transactions.calls)
	}
}

func TestUploadBuildAttestationPayloadRejectsForeignTenantReferencesBeforePayloadWork(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*serviceFixture, releasedomain.BuildRun, releasedomain.Artifact)
	}{
		{name: "build", corrupt: func(fixture *serviceFixture, build releasedomain.BuildRun, _ releasedomain.Artifact) {
			build.TenantID = "ten_other"
			fixture.reader.builds[build.ID] = build
		}},
		{name: "artifact", corrupt: func(fixture *serviceFixture, _ releasedomain.BuildRun, artifact releasedomain.Artifact) {
			artifact.TenantID = "ten_other"
			fixture.reader.artifacts[artifact.ID] = artifact
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			build, artifact := seedBuildAttestationFixture(fixture)
			test.corrupt(fixture, build, artifact)
			raw := []byte(`{"payload":"attestation"}`)

			_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BytesBuildAttestationPayloadSource(raw))
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want not found", err)
			}
			if fixture.attestationParser.calls != 0 || fixture.payloadStager.calls != 0 || fixture.transactions.calls != 0 {
				t.Fatalf("foreign reference touched parser=%d stager=%d transactions=%d", fixture.attestationParser.calls, fixture.payloadStager.calls, fixture.transactions.calls)
			}
		})
	}
}

func TestUploadBuildAttestationPayloadRevalidatesBuildAndArtifactInsideTransaction(t *testing.T) {
	fixture := newServiceFixture(t)
	build, artifact := seedBuildAttestationFixture(fixture)
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)
	fixture.attestationParser.result = ParsedBuildAttestation{
		PayloadHash: digest, PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
		PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{artifact.Digest}, SignatureCount: 1,
	}
	fixture.payloadStager.result = StagedBuildAttestationPayload{TenantID: fixture.actor.TenantID, Digest: digest, Size: int64(len(raw)), MediaType: BuildAttestationMediaType, Reference: "object://payload", FinalKey: "payload", Status: "finalized"}
	fixture.transactions.beforeCommand = func(state *fakeState) {
		changed := state.artifacts[artifact.ID]
		changed.Digest = "sha256:" + strings.Repeat("b", 64)
		state.artifacts[artifact.ID] = changed
	}

	_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BytesBuildAttestationPayloadSource(raw))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.attestations) != 0 || len(fixture.transactions.state.evidence) != 0 || len(fixture.transactions.state.audit) != 0 || len(fixture.transactions.state.outbox) != 0 {
		t.Fatalf("transaction leaked effects: %#v state=%#v", fixture.transactions, fixture.transactions.state)
	}
}

func TestUploadBuildAttestationPayloadRollsBackEveryEffectOnMutationFailure(t *testing.T) {
	tests := []struct {
		name string
		set  func(*fakeTransactions, error)
	}{
		{name: "evidence", set: func(tx *fakeTransactions, err error) { tx.evidenceErr = err }},
		{name: "attestation", set: func(tx *fakeTransactions, err error) { tx.buildAttestationErr = err }},
		{name: "audit", set: func(tx *fakeTransactions, err error) { tx.auditErr = err }},
		{name: "outbox", set: func(tx *fakeTransactions, err error) { tx.outboxErr = err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			build, artifact := seedBuildAttestationFixture(fixture)
			raw := []byte(`{"payload":"attestation"}`)
			digest := testAttestationDigest(raw)
			fixture.attestationParser.result = ParsedBuildAttestation{
				PayloadHash: digest, PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
				PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
				SubjectDigests: []string{artifact.Digest}, SignatureCount: 1,
			}
			fixture.payloadStager.result = StagedBuildAttestationPayload{TenantID: fixture.actor.TenantID, Digest: digest, Size: int64(len(raw)), MediaType: BuildAttestationMediaType, Reference: "object://payload", FinalKey: "payload", Status: "finalized"}
			failure := errors.New("injected " + test.name + " failure")
			test.set(fixture.transactions, failure)

			_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BytesBuildAttestationPayloadSource(raw))
			if !errors.Is(err, failure) {
				t.Fatalf("error = %v, want %v", err, failure)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.attestations) != 0 || len(fixture.transactions.state.evidence) != 0 || len(fixture.transactions.state.audit) != 0 || len(fixture.transactions.state.outbox) != 0 {
				t.Fatalf("transaction leaked effects: %#v state=%#v", fixture.transactions, fixture.transactions.state)
			}
		})
	}
}

func TestUploadBuildAttestationPayloadRejectsParserDigestMismatchBeforeStaging(t *testing.T) {
	fixture := newServiceFixture(t)
	build, artifact := seedBuildAttestationFixture(fixture)
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)
	fixture.attestationParser.result = ParsedBuildAttestation{
		PayloadHash: "sha256:" + strings.Repeat("f", 64), PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
		PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{artifact.Digest}, SignatureCount: 1,
	}

	_, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BuildAttestationPayloadSource{
		Digest: digest, Size: int64(len(raw)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(raw))), nil },
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
	if fixture.attestationParser.calls != 1 || fixture.payloadStager.calls != 0 || fixture.transactions.calls != 0 {
		t.Fatalf("mismatch touched parser=%d stager=%d transactions=%d", fixture.attestationParser.calls, fixture.payloadStager.calls, fixture.transactions.calls)
	}
}

func TestWorkerOwnedBuildAttestationWithoutReplayableObjectKeepsParsedProjection(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.service.workerOwnedParsers = true
	build, artifact := seedBuildAttestationFixture(fixture)
	raw := []byte(`{"payload":"attestation"}`)
	digest := testAttestationDigest(raw)
	fixture.attestationParser.result = ParsedBuildAttestation{
		PayloadHash: digest, PayloadSize: int64(len(raw)), ParserVersion: BuildAttestationParserVersion,
		PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1",
		SubjectDigests: []string{artifact.Digest}, BuilderID: "builder", BuildType: "build-type",
		MaterialsCount: 2, SignatureCount: 1,
	}
	fixture.payloadStager.result = StagedBuildAttestationPayload{}

	attestation, err := fixture.service.UploadBuildAttestationPayload(context.Background(), fixture.actor, build.ID, BytesBuildAttestationPayloadSource(raw))
	if err != nil {
		t.Fatalf("UploadBuildAttestationPayload: %v", err)
	}
	persisted := fixture.transactions.state.attestations[attestation.ID]
	if !reflect.DeepEqual(persisted, attestation) {
		t.Fatalf("non-replayable persistence = %#v, want parsed response %#v", persisted, attestation)
	}
	if persisted.VerificationStatus != "structurally_valid" || persisted.PredicateType == "" || len(persisted.SubjectDigests) != 1 || persisted.SignatureCount != 1 {
		t.Fatalf("non-replayable projection was blanked: %#v", persisted)
	}
	if len(fixture.transactions.state.audit) != 1 || fixture.transactions.state.audit[0].EntryType != "build_attestation.created" {
		t.Fatalf("audit = %#v, want parsed creation", fixture.transactions.state.audit)
	}
}

func seedBuildAttestationFixture(fixture *serviceFixture) (releasedomain.BuildRun, releasedomain.Artifact) {
	product := releasedomain.Product{ID: "prod_1", TenantID: fixture.actor.TenantID, Name: "Product", Slug: "product", CreatedAt: fixture.now}
	project := releasedomain.Project{ID: "proj_1", TenantID: fixture.actor.TenantID, ProductID: product.ID, Name: "Project", CreatedAt: fixture.now}
	state, _ := releasedomain.ParseReleaseState(releasedomain.ReleaseStateDraftValue)
	release := releasedomain.Release{ID: "rel_1", TenantID: fixture.actor.TenantID, ProductID: product.ID, Version: "1.0.0", Revision: 1, State: state, CreatedAt: fixture.now}
	artifact := releasedomain.Artifact{ID: "art_1", TenantID: fixture.actor.TenantID, Name: "artifact", Digest: "sha256:" + strings.Repeat("a", 64), CreatedAt: fixture.now}
	build := releasedomain.BuildRun{
		ID: "build_1", TenantID: fixture.actor.TenantID, ProjectID: project.ID, ReleaseID: release.ID,
		Provider: "github_actions", CommitSHA: strings.Repeat("1", 40), Status: "passed",
		SourceIdentity: map[string]any{"provider": "github_actions"},
		Outputs:        []releasedomain.BuildOutput{{ArtifactID: artifact.ID, Digest: artifact.Digest}}, CreatedAt: fixture.now,
	}
	fixture.reader.products[product.ID] = product
	fixture.reader.projects[project.ID] = project
	fixture.reader.releases[release.ID] = release
	fixture.reader.artifacts[artifact.ID] = artifact
	fixture.reader.builds[build.ID] = build
	fixture.transactions.state.products[product.ID] = product
	fixture.transactions.state.projects[project.ID] = project
	fixture.transactions.state.releases[release.ID] = release
	fixture.transactions.state.artifacts[artifact.ID] = artifact
	fixture.transactions.state.builds[build.ID] = build
	return build, artifact
}

func testAttestationDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type fakeBuildAttestationParser struct {
	calls                  int
	result                 ParsedBuildAttestation
	err                    error
	authorizer             *fakeAuthorizer
	authorizerCallsAtParse int
}

func (f *fakeBuildAttestationParser) ParseBuildAttestation(context.Context, BuildAttestationPayloadSource) (ParsedBuildAttestation, error) {
	f.calls++
	f.authorizerCallsAtParse = f.authorizer.calls
	return f.result, f.err
}

type fakeBuildAttestationPayloadStager struct {
	calls                  int
	result                 StagedBuildAttestationPayload
	err                    error
	authorizer             *fakeAuthorizer
	authorizerCallsAtStage int
}

func (f *fakeBuildAttestationPayloadStager) StageBuildAttestationPayload(context.Context, string, BuildAttestationPayloadSource) (StagedBuildAttestationPayload, error) {
	f.calls++
	f.authorizerCallsAtStage = f.authorizer.calls
	return f.result, f.err
}

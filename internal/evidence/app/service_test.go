package app

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var (
	errAuditFailure         = errors.New("audit failed")
	errAuthorizationFailure = errors.New("authorization failed")
)

func TestCreateEvidenceCommitsPayloadOutboxAuditAndRecordTogether(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	staged := StagedPayload{
		TenantID: fixture.actor.TenantID, Digest: testDigest('a'), Size: 42,
		MediaType: "application/json", StagingKey: "staging/key", FinalKey: "final/key",
		Status: PayloadStatusStaged, CreatedAt: fixture.now, UpdatedAt: fixture.now,
	}
	item, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		ProductID: "prod_1", ReleaseID: "rel_1", Type: "build", Title: " Build evidence ",
		PayloadRef: "object://final/key", PayloadHash: staged.Digest, PayloadMediaType: staged.MediaType,
		PayloadSize: staged.Size, StagedPayload: staged, Tags: []string{" z ", "a"},
	})
	if err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}
	if item.ID != "ev_1" || item.ChainEntryID != "ace_1" || item.CanonicalHash != testDigest('c') || item.Title != "Build evidence" {
		t.Fatalf("item = %#v", item)
	}
	if !reflect.DeepEqual(item.Tags, []string{"a", "z"}) {
		t.Fatalf("tags = %#v", item.Tags)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 1 || len(state.payloads) != 1 || len(state.outbox) != 1 || len(state.audit) != 1 || fixture.transactions.commits != 1 {
		t.Fatalf("state=%#v transactions=%#v", state, fixture.transactions)
	}
	if state.outbox[0].Kind != "finalize_payload" || state.outbox[0].SubjectID != staged.Digest || state.outbox[0].Payload["payload_digest"] != staged.Digest {
		t.Fatalf("outbox = %#v", state.outbox)
	}
	if fixture.objects.calls != 1 || fixture.canonicalizer.calls != 1 {
		t.Fatalf("objects=%d canonicalizer=%d", fixture.objects.calls, fixture.canonicalizer.calls)
	}
}

func TestCreateEvidenceRollsBackEveryEffectWhenAuditFails(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.transactions.auditErr = errAuditFailure
	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{Type: "build", Title: "Build", PayloadHash: testDigest('a')})
	if !errors.Is(err, errAuditFailure) {
		t.Fatalf("CreateEvidence error = %v", err)
	}
	state := fixture.transactions.state
	if len(state.evidence) != 0 || len(state.payloads) != 0 || len(state.outbox) != 0 || len(state.audit) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state after rollback: %#v", state)
	}
}

func TestCreateEvidenceUsesHumanAuditIdentityAndAuthorizesBuildDeploymentScope(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.actor.KeyID = ""
	fixture.actor.UserID = "usr_1"
	item, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "build_1", DeploymentID: "dep_1",
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('a'),
	})
	if err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}
	if item.BuildID != "build_1" || item.DeploymentID != "dep_1" {
		t.Fatalf("item scope = %#v", item)
	}
	if len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("audit = %#v", fixture.transactions.state.audit)
	}
	if audit := fixture.transactions.state.audit[0]; audit.ActorType != "human_user" || audit.ActorID != fixture.actor.UserID {
		t.Fatalf("audit actor = %#v", audit)
	}
	wantResources := application.ResourceReferences{
		ProductID: "prod_1", ProjectID: "proj_1", ReleaseID: "rel_1", BuildID: "build_1", DeploymentID: "dep_1",
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, wantResources) {
		t.Fatalf("complete resource authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestCreateEvidenceRejectsUnauthorizedArtifactSubjectBeforeCanonicalizationOrTransaction(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactDigests["art_1"] = testDigest('a')
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources == (application.ResourceReferences{ArtifactID: "art_1"}) {
			return errAuthorizationFailure
		}
		return nil
	}

	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		ReleaseID: "rel_1", Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "art_1", Digest: testDigest('a')}},
	})
	if !errors.Is(err, errAuthorizationFailure) {
		t.Fatalf("CreateEvidence error = %v, want authorization failure", err)
	}
	if fixture.canonicalizer.calls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("denied artifact reached canonicalization or transaction: canonicalizer=%d transactions=%#v", fixture.canonicalizer.calls, fixture.transactions)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) {
		t.Fatalf("artifact-only authorization missing: %#v", fixture.authorizer.requests)
	}
}

func TestCreateEvidenceCanonicalizesAndSeparatelyAuthorizesRecognizedSubjectRefs(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactDigests["art_1"] = testDigest('a')

	item, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{
			{Type: " artifact ", ID: " art_1 ", Digest: " " + strings.ToUpper(testDigest('a')) + " "},
			{Type: " product ", ID: " prod_1 "},
			{Type: "project", ID: "proj_1"},
			{Type: "release", ID: "rel_1"},
			{Type: "build", ID: "build_1"},
			{Type: "deployment", ID: "dep_1"},
		},
	})
	if err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}
	wantSubjects := []evidencedomain.SubjectRef{
		{Type: "artifact", ID: "art_1", Digest: strings.ToUpper(testDigest('a'))},
		{Type: "product", ID: "prod_1"},
		{Type: "project", ID: "proj_1"},
		{Type: "release", ID: "rel_1"},
		{Type: "build", ID: "build_1"},
		{Type: "deployment", ID: "dep_1"},
	}
	if !reflect.DeepEqual(item.SubjectRefs, wantSubjects) {
		t.Fatalf("subject refs = %#v, want %#v", item.SubjectRefs, wantSubjects)
	}
	for _, resources := range []application.ResourceReferences{
		{ArtifactID: "art_1"},
		{ProductID: "prod_1"},
		{ProjectID: "proj_1"},
		{ReleaseID: "rel_1"},
		{BuildID: "build_1"},
		{DeploymentID: "dep_1"},
	} {
		if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, resources) {
			t.Fatalf("separate subject authorization %v missing: %#v", resources, fixture.authorizer.requests)
		}
	}
	if got := fixture.transactions.validatedArtifacts; len(got) != 1 || got[0] != "art_1" {
		t.Fatalf("transaction artifact rechecks = %#v", got)
	}
}

func TestCreateEvidenceRejectsMismatchedArtifactSubjectDigest(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')

	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "art_1", Digest: testDigest('c')}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateEvidence error = %v, want not found", err)
	}
	if !containsAuthorizationRequest(fixture.authorizer.requests, ScopeEvidenceWrite, application.ResourceReferences{ArtifactID: "art_1"}) || fixture.canonicalizer.calls != 0 || fixture.transactions.commits != 0 {
		t.Fatalf("mismatched artifact digest bypassed authorization or reached effects: authorizer=%#v canonicalizer=%d transactions=%#v", fixture.authorizer.requests, fixture.canonicalizer.calls, fixture.transactions)
	}
}

func TestCreateEvidenceRejectsForeignArtifactSubjectBeforeCanonicalizationOrTransaction(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_foreign"] = "ten_other"
	fixture.reader.artifactDigests["art_foreign"] = testDigest('a')

	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "art_foreign", Digest: testDigest('a')}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateEvidence error = %v, want not found", err)
	}
	if fixture.canonicalizer.calls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("foreign artifact reached effects: canonicalizer=%d transactions=%#v", fixture.canonicalizer.calls, fixture.transactions)
	}
}

func TestCreateEvidenceRejectsArtifactDigestDriftInsideTransaction(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	fixture.reader.artifacts["art_1"] = fixture.actor.TenantID
	fixture.reader.artifactDigests["art_1"] = testDigest('a')
	fixture.transactions.state.artifactTenants["art_1"] = fixture.actor.TenantID
	fixture.transactions.state.artifactDigests["art_1"] = testDigest('c')

	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "art_1", Digest: testDigest('a')}},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateEvidence error = %v, want not found", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.evidence) != 0 || len(fixture.transactions.state.audit) != 0 {
		t.Fatalf("drifted artifact digest was published: %#v", fixture.transactions)
	}
}

func TestCreateEvidencePreservesOpaqueAndDigestOnlySubjectRefsWithoutResourceAuthority(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	refs := []evidencedomain.SubjectRef{
		{Type: " incident ", ID: " inc_1 ", Digest: " provider:digest "},
		{Type: " artifact ", Digest: " " + testDigest('a') + " "},
		{Type: " Artifact ", ID: " art_opaque ", Digest: testDigest('b')},
		{Type: "release", Digest: "opaque-release-digest"},
	}
	item, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('c'), SubjectRefs: refs,
	})
	if err != nil {
		t.Fatalf("CreateEvidence: %v", err)
	}
	want := []evidencedomain.SubjectRef{
		{Type: "incident", ID: "inc_1", Digest: "provider:digest"},
		{Type: "artifact", Digest: testDigest('a')},
		{Type: "Artifact", ID: "art_opaque", Digest: testDigest('b')},
		{Type: "release", Digest: "opaque-release-digest"},
	}
	if !reflect.DeepEqual(item.SubjectRefs, want) {
		t.Fatalf("subject refs = %#v, want %#v", item.SubjectRefs, want)
	}
	for _, request := range fixture.authorizer.requests {
		if request.Resources.ArtifactID != "" || request.Resources.ReleaseID != "" {
			t.Fatalf("opaque or digest-only reference became an authorization coordinate: %#v", fixture.authorizer.requests)
		}
	}
}

func TestCreateEvidenceRejectsSubjectRefWithoutType(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: "build", Title: "Build evidence", PayloadHash: testDigest('b'),
		SubjectRefs: []evidencedomain.SubjectRef{{Type: " ", ID: "opaque"}},
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("CreateEvidence error = %v, want validation", err)
	}
	if fixture.canonicalizer.calls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
		t.Fatalf("invalid subject reached effects: canonicalizer=%d transactions=%#v", fixture.canonicalizer.calls, fixture.transactions)
	}
}

func TestCreateEvidenceRejectsGenericPendingDeploymentEvent(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		ProductID: "prod_1", ReleaseID: "rel_1", DeploymentID: "dep_pending",
		Type: "deployment", Subtype: "event", Title: "Forged deployment event", PayloadHash: testDigest('a'),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("CreateEvidence error = %v, want validation", err)
	}
	if len(fixture.reader.scopes) != 0 || fixture.transactions.commits != 0 || len(fixture.transactions.state.evidence) != 0 {
		t.Fatalf("generic deployment event reached persistence: reader=%#v transactions=%#v", fixture.reader, fixture.transactions)
	}
}

func TestCreateEvidenceRejectsReservedParserNormalizationType(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	_, err := fixture.service.CreateEvidence(context.Background(), fixture.actor, CreateEvidenceInput{
		Type: " parser_normalization ", Title: "Forged parser replay", PayloadHash: testDigest('a'),
		Metadata: map[string]any{
			"replay_of": "ev_source",
			"parser":    map[string]any{"version": "scanner-adapters-json.v1"},
		},
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("CreateEvidence error = %v, want validation", err)
	}
	if len(fixture.reader.scopes) != 0 || fixture.canonicalizer.calls != 0 || fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 || len(fixture.transactions.state.evidence) != 0 {
		t.Fatalf("reserved parser normalization reached trusted processing: reader=%#v canonicalizer=%d transactions=%#v", fixture.reader, fixture.canonicalizer.calls, fixture.transactions)
	}
}

func TestGetEvidenceRejectsCorruptAdapterIdentityAndCoordinates(t *testing.T) {
	tests := []struct {
		name string
		item evidencedomain.EvidenceItem
	}{
		{name: "wrong tenant", item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_other"}},
		{name: "wrong id", item: evidencedomain.EvidenceItem{ID: "ev_other", TenantID: "ten_1"}},
		{name: "noncanonical product coordinate", item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", ProductID: " prod_1"}},
		{name: "noncanonical release coordinate", item: evidencedomain.EvidenceItem{ID: "ev_1", TenantID: "ten_1", ReleaseID: "rel_1 "}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			fixture.reader.evidenceResult = &test.item
			if _, err := fixture.service.GetEvidence(context.Background(), fixture.actor, "ev_1"); !errors.Is(err, ErrConflict) {
				t.Fatalf("GetEvidence error = %v, want conflict", err)
			}
			if fixture.authorizer.calls != 1 {
				t.Fatalf("resource authorization used corrupt coordinates: %#v", fixture.authorizer.requests)
			}
		})
	}
}

func TestGetEvidenceValidatesReturnedCoordinatesBeforeAuthorization(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := evidencedomain.EvidenceItem{ID: "ev_1", TenantID: fixture.actor.TenantID, ProductID: "prod_missing"}
	fixture.reader.evidenceResult = &item
	fixture.reader.scopeErr = ErrNotFound

	if _, err := fixture.service.GetEvidence(context.Background(), fixture.actor, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEvidence error = %v, want not found", err)
	}
	if fixture.authorizer.calls != 1 || len(fixture.reader.scopes) != 1 {
		t.Fatalf("coordinate validation order: authorizer=%#v scopes=%#v", fixture.authorizer.requests, fixture.reader.scopes)
	}
}

func TestListEvidencePropagatesPerResourceCancellation(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := fixture.mutableEvidence("ev_1", "prod_1", testDigest('1'))
	fixture.reader.evidence[item.ID] = item
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID != "" {
			return context.Canceled
		}
		return nil
	}

	if _, err := fixture.service.ListEvidence(context.Background(), fixture.actor, "", ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListEvidence error = %v, want cancellation", err)
	}
}

func TestListEvidenceFiltersCanonicalResourceDenial(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := fixture.mutableEvidence("ev_1", "prod_1", testDigest('1'))
	fixture.reader.evidence[item.ID] = item
	fixture.authorizer.authorize = func(request application.AuthorizationRequest) error {
		if request.Resources.ProductID != "" {
			return ErrForbidden
		}
		return nil
	}

	items, err := fixture.service.ListEvidence(context.Background(), fixture.actor, "", "")
	if err != nil || len(items) != 0 {
		t.Fatalf("ListEvidence = (%#v, %v), want filtered result", items, err)
	}
}

func TestRelationshipCommandsRejectWorkerOwnedEvidence(t *testing.T) {
	for _, evidenceType := range []string{
		parserNormalizationType,
		"sbom",
		"vulnerability_scan",
		"openapi_contract",
		"vex",
		"build_attestation",
	} {
		t.Run(evidenceType+"_link", func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			derived := fixture.mutableEvidence("ev_worker_owned", "prod_1", testDigest('1'))
			derived.Type = evidenceType
			fixture.reader.evidence[derived.ID] = derived
			fixture.transactions.state.evidence[derived.ID] = derived

			if _, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, derived.ID, "product", "prod_2"); !errors.Is(err, ErrConflict) {
				t.Fatalf("LinkEvidence error = %v, want conflict", err)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
				t.Fatalf("worker-owned evidence reached transaction: %#v", fixture.transactions)
			}
		})

		for _, derivedRole := range []string{"original", "replacement"} {
			t.Run(evidenceType+"_supersede_"+derivedRole, func(t *testing.T) {
				fixture := newEvidenceServiceFixture(t)
				original := fixture.mutableEvidence("ev_original", "prod_1", testDigest('1'))
				replacement := fixture.mutableEvidence("ev_replacement", "prod_1", testDigest('2'))
				if derivedRole == "original" {
					original.Type = evidenceType
				} else {
					replacement.Type = evidenceType
				}
				fixture.reader.evidence[original.ID] = original
				fixture.reader.evidence[replacement.ID] = replacement
				fixture.transactions.state.evidence[original.ID] = original
				fixture.transactions.state.evidence[replacement.ID] = replacement

				if _, err := fixture.service.SupersedeEvidence(context.Background(), fixture.actor, original.ID, replacement.ID, "replace"); !errors.Is(err, ErrConflict) {
					t.Fatalf("SupersedeEvidence error = %v, want conflict", err)
				}
				if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 0 {
					t.Fatalf("worker-owned evidence reached transaction: %#v", fixture.transactions)
				}
			})
		}
	}
}

func TestSupersedeEvidenceAuthorizesBothRecordsAndCommitsTogether(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	first := fixture.mutableEvidence("ev_first", "prod_1", testDigest('1'))
	replacement := fixture.mutableEvidence("ev_replacement", "prod_1", testDigest('2'))
	fixture.reader.evidence[first.ID] = first
	fixture.reader.evidence[replacement.ID] = replacement
	fixture.transactions.state.evidence[first.ID] = first
	fixture.transactions.state.evidence[replacement.ID] = replacement

	updated, err := fixture.service.SupersedeEvidence(context.Background(), fixture.actor, first.ID, replacement.ID, " corrected ")
	if err != nil {
		t.Fatalf("SupersedeEvidence: %v", err)
	}
	if updated.SupersededBy != replacement.ID || fixture.transactions.state.evidence[replacement.ID].Supersedes != first.ID {
		t.Fatalf("supersession state = %#v", fixture.transactions.state.evidence)
	}
	assertRelationshipPairAuthorization(t, fixture.authorizer.requests, evidenceReferences(first), evidenceReferences(replacement))
	if len(fixture.transactions.state.lifecycle) != 1 {
		t.Fatalf("supersession lifecycle = %#v", fixture.transactions.state.lifecycle)
	}
	event := fixture.transactions.state.lifecycle[0]
	if event.EvidenceID != first.ID || event.ReplacementID != replacement.ID || event.Reason != "[redacted]" || event.Details["safe"] != true {
		t.Fatalf("supersession lifecycle = %#v", event)
	}
	if fixture.sanitizer.lastReason != "corrected" || fixture.sanitizer.lastDetails["operation"] != "supersede" || fixture.sanitizer.lastDetails["replacement_evidence_id"] != replacement.ID {
		t.Fatalf("unsanitized supersession history was not supplied to sanitizer: %#v", fixture.sanitizer)
	}
}

func TestSupersedeEvidenceRejectsAuthorizationScopeDrift(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	first := fixture.mutableEvidence("ev_first", "prod_authorized", testDigest('1'))
	replacement := fixture.mutableEvidence("ev_replacement", "prod_authorized", testDigest('2'))
	fixture.reader.evidence[first.ID] = first
	fixture.reader.evidence[replacement.ID] = replacement
	first.ProductID = "prod_drifted"
	fixture.transactions.state.evidence[first.ID] = first
	fixture.transactions.state.evidence[replacement.ID] = replacement

	if _, err := fixture.service.SupersedeEvidence(context.Background(), fixture.actor, first.ID, replacement.ID, "replace"); !errors.Is(err, ErrConflict) {
		t.Fatalf("SupersedeEvidence error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
}

func TestLinkEvidenceRejectsAuthorizationScopeDrift(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	visible := fixture.mutableEvidence("ev_1", "prod_authorized", testDigest('1'))
	fixture.reader.evidence[visible.ID] = visible
	drifted := visible
	drifted.ProductID = "prod_drifted"
	fixture.transactions.state.evidence[drifted.ID] = drifted

	if _, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, visible.ID, "release", "rel_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("LinkEvidence error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
}

func TestLinkEvidenceRejectsConcurrentLinkStateChange(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	visible := fixture.mutableEvidence("ev_1", "", testDigest('1'))
	fixture.reader.evidence[visible.ID] = visible
	fixture.transactions.state.evidence[visible.ID] = visible
	fixture.transactions.beforeLinkCAS = func(state *fakeEvidenceState) {
		concurrent := state.evidence[visible.ID]
		concurrent.ProductID = "prod_concurrent"
		concurrent.RelatedEvidenceRefs = []evidencedomain.EvidenceRef{{Type: "product", ID: concurrent.ProductID, Relationship: "linked_to"}}
		state.evidence[visible.ID] = concurrent
	}

	if _, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, visible.ID, "release", "rel_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("LinkEvidence error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("transactions = %#v", fixture.transactions)
	}
}

func TestLegacyEvidenceLinkPersistsCanonicalOriginWithoutRewritingHash(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	legacy := fixture.mutableEvidence("ev_legacy", "", testDigest('1'))
	legacy.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
	fixture.reader.evidence[legacy.ID] = legacy
	fixture.transactions.state.evidence[legacy.ID] = legacy

	linked, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, legacy.ID, "release", "rel_1")
	if err != nil {
		t.Fatalf("LinkEvidence: %v", err)
	}
	if linked.CanonicalHash != legacy.CanonicalHash || len(fixture.transactions.state.lifecycle) != 1 {
		t.Fatalf("legacy link rewrote canonical history or omitted origin: linked=%#v lifecycle=%#v", linked, fixture.transactions.state.lifecycle)
	}
	rawOrigin, ok := fixture.transactions.state.lifecycle[0].Details[legacyCanonicalOriginDetail]
	if !ok {
		t.Fatalf("legacy canonical origin missing: %#v", fixture.transactions.state.lifecycle[0])
	}
	origin, err := decodeCanonicalRelationshipOrigin(rawOrigin)
	if err != nil {
		t.Fatalf("decode origin: %v", err)
	}
	if origin.ReleaseID != "" || len(origin.RelatedEvidenceRefs) != 0 {
		t.Fatalf("origin = %#v", origin)
	}
}

func TestLegacyEvidenceMutationRejectsUnverifiableCurrentOrigin(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	legacy := fixture.mutableEvidence("ev_legacy", "", testDigest('1'))
	legacy.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
	legacy.CanonicalHash = testDigest('d')
	fixture.reader.evidence[legacy.ID] = legacy
	fixture.transactions.state.evidence[legacy.ID] = legacy

	if _, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, legacy.ID, "release", "rel_1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("LinkEvidence error = %v, want conflict", err)
	}
	if fixture.transactions.commits != 0 || len(fixture.transactions.state.lifecycle) != 0 {
		t.Fatalf("unverifiable legacy origin was persisted: %#v", fixture.transactions)
	}
}

func TestEvidenceMutationsRejectCorruptDurableAdapterIdentity(t *testing.T) {
	tests := []struct {
		name string
		run  func(*evidenceServiceFixture) error
	}{
		{
			name: "supersede",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.SupersedeEvidence(context.Background(), fixture.actor, "ev_first", "ev_replacement", "corrected")
				return err
			},
		},
		{
			name: "link",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, "ev_first", "release", "rel_1")
				return err
			},
		},
		{
			name: "lifecycle",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.RecordLifecycleEvent(context.Background(), fixture.actor, "ev_first", RecordLifecycleInput{Action: evidencedomain.EvidenceLifecycleAcceptedValue, Reason: "accepted"})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			first := fixture.mutableEvidence("ev_first", "prod_1", testDigest('1'))
			replacement := fixture.mutableEvidence("ev_replacement", "prod_1", testDigest('2'))
			fixture.reader.evidence[first.ID] = first
			fixture.reader.evidence[replacement.ID] = replacement
			corrupt := first
			corrupt.ID = "ev_wrong"
			fixture.transactions.state.evidence[first.ID] = corrupt
			fixture.transactions.state.evidence[replacement.ID] = replacement

			if err := test.run(fixture); !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want conflict", err)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.state.audit) != 0 || len(fixture.transactions.state.lifecycle) != 0 {
				t.Fatalf("corrupt durable record was published: %#v", fixture.transactions)
			}
		})
	}
}

func TestEvidenceMutationsRevalidateDurableCoordinates(t *testing.T) {
	tests := []struct {
		name string
		run  func(*evidenceServiceFixture) error
	}{
		{
			name: "supersede",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.SupersedeEvidence(context.Background(), fixture.actor, "ev_first", "ev_replacement", "corrected")
				return err
			},
		},
		{
			name: "link",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, "ev_first", "release", "rel_1")
				return err
			},
		},
		{
			name: "lifecycle",
			run: func(fixture *evidenceServiceFixture) error {
				_, err := fixture.service.RecordLifecycleEvent(context.Background(), fixture.actor, "ev_first", RecordLifecycleInput{Action: evidencedomain.EvidenceLifecycleAcceptedValue, Reason: "accepted"})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			first := fixture.mutableEvidence("ev_first", "prod_1", testDigest('1'))
			replacement := fixture.mutableEvidence("ev_replacement", "prod_1", testDigest('2'))
			fixture.reader.evidence[first.ID] = first
			fixture.reader.evidence[replacement.ID] = replacement
			fixture.transactions.state.evidence[first.ID] = first
			fixture.transactions.state.evidence[replacement.ID] = replacement
			fixture.transactions.scopeValidator = func(EvidenceScope) error { return ErrNotFound }

			if err := test.run(fixture); !errors.Is(err, ErrNotFound) {
				t.Fatalf("error = %v, want not found", err)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 {
				t.Fatalf("invalid durable coordinates were published: %#v", fixture.transactions)
			}
		})
	}
}

func TestLinkEvidenceRejectsIncoherentCompleteScopeBeforeUpdate(t *testing.T) {
	tests := []struct {
		name       string
		item       evidencedomain.EvidenceItem
		targetType string
		targetID   string
		wantScope  EvidenceScope
	}{
		{
			name:       "product conflicts with retained project and build",
			item:       evidencedomain.EvidenceItem{ID: "ev_1", ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_a", BuildID: "build_a"},
			targetType: "product", targetID: "prod_b",
			wantScope: EvidenceScope{ProductID: "prod_b", ProjectID: "proj_a", ReleaseID: "rel_a", BuildID: "build_a"},
		},
		{
			name:       "release conflicts with retained project and build",
			item:       evidencedomain.EvidenceItem{ID: "ev_1", ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_a", BuildID: "build_a"},
			targetType: "release", targetID: "rel_b",
			wantScope: EvidenceScope{ProductID: "prod_a", ProjectID: "proj_a", ReleaseID: "rel_b", BuildID: "build_a"},
		},
		{
			name:       "release conflicts with retained deployment",
			item:       evidencedomain.EvidenceItem{ID: "ev_1", ProductID: "prod_a", ReleaseID: "rel_a", DeploymentID: "dep_a"},
			targetType: "release", targetID: "rel_b",
			wantScope: EvidenceScope{ProductID: "prod_a", ReleaseID: "rel_b", DeploymentID: "dep_a"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newEvidenceServiceFixture(t)
			test.item.TenantID = fixture.actor.TenantID
			test.item.Type = "build"
			test.item.Title = "evidence"
			test.item.PayloadHash = testDigest('a')
			test.item.CanonicalHash = testDigest('c')
			test.item.Canonicalization = evidencedomain.EvidenceCanonicalizationProfileVersion
			fixture.reader.evidence[test.item.ID] = test.item
			fixture.transactions.state.evidence[test.item.ID] = test.item
			fixture.transactions.scopeValidator = func(scope EvidenceScope) error {
				if scope == test.wantScope {
					return ErrNotFound
				}
				return nil
			}

			_, err := fixture.service.LinkEvidence(context.Background(), fixture.actor, test.item.ID, test.targetType, test.targetID)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("LinkEvidence error = %v", err)
			}
			if fixture.transactions.commits != 0 || fixture.transactions.rollbacks != 1 || len(fixture.transactions.validatedScopes) != 2 || fixture.transactions.validatedScopes[1] != test.wantScope {
				t.Fatalf("transactions = %#v", fixture.transactions)
			}
			if stored := fixture.transactions.state.evidence[test.item.ID]; stored.ProductID != test.item.ProductID || stored.ReleaseID != test.item.ReleaseID || len(stored.RelatedEvidenceRefs) != 0 {
				t.Fatalf("incoherent link was published: %#v", stored)
			}
		})
	}
}

func TestRecordLifecycleEventSanitizesAndCommitsAuditAtomically(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := evidencedomain.EvidenceItem{ID: "ev_1", TenantID: fixture.actor.TenantID, ProductID: "prod_1", Type: "build", Title: "build", PayloadHash: testDigest('1'), CreatedAt: fixture.now}
	replacement := evidencedomain.EvidenceItem{ID: "ev_2", TenantID: fixture.actor.TenantID, ProductID: "prod_1", Type: "build", Title: "replacement", PayloadHash: testDigest('2'), CreatedAt: fixture.now}
	fixture.reader.evidence[item.ID] = item
	fixture.reader.evidence[replacement.ID] = replacement
	fixture.transactions.state.evidence[item.ID] = item
	fixture.transactions.state.evidence[replacement.ID] = replacement

	event, err := fixture.service.RecordLifecycleEvent(context.Background(), fixture.actor, item.ID, RecordLifecycleInput{
		Action: evidencedomain.EvidenceLifecycleRedactionValue, Reason: " secret reason ", ReplacementID: replacement.ID,
		Details: map[string]any{"token": "secret"},
	})
	if err != nil {
		t.Fatalf("RecordLifecycleEvent: %v", err)
	}
	if event.ID != "elc_1" || event.ActorID != fixture.actor.KeyID || event.Reason != "[redacted]" || event.Action.String() != evidencedomain.EvidenceLifecycleRedactionValue {
		t.Fatalf("event = %#v", event)
	}
	if len(event.Details) != 1 || event.Details["safe"] != true {
		t.Fatalf("details = %#v", event.Details)
	}
	assertRelationshipPairAuthorization(t, fixture.authorizer.requests, evidenceReferences(item), evidenceReferences(replacement))
	if fixture.sanitizer.calls != 1 || len(fixture.transactions.state.lifecycle) != 1 || len(fixture.transactions.state.audit) != 1 || fixture.transactions.commits != 1 {
		t.Fatalf("sanitizer=%d state=%#v transactions=%#v", fixture.sanitizer.calls, fixture.transactions.state, fixture.transactions)
	}
	if audit := fixture.transactions.state.audit[0]; audit.ActorType != "api_key" || audit.ActorID != fixture.actor.KeyID {
		t.Fatalf("audit actor = %#v", audit)
	}
}

func TestRecordLifecycleEventRollsBackWhenAuditFails(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := evidencedomain.EvidenceItem{ID: "ev_1", TenantID: fixture.actor.TenantID, Type: "build", Title: "build", PayloadHash: testDigest('1'), CreatedAt: fixture.now}
	fixture.reader.evidence[item.ID] = item
	fixture.transactions.state.evidence[item.ID] = item
	fixture.transactions.auditErr = errAuditFailure

	_, err := fixture.service.RecordLifecycleEvent(context.Background(), fixture.actor, item.ID, RecordLifecycleInput{Action: evidencedomain.EvidenceLifecycleAcceptedValue, Reason: "accepted"})
	if !errors.Is(err, errAuditFailure) {
		t.Fatalf("RecordLifecycleEvent error = %v, want audit failure", err)
	}
	if len(fixture.transactions.state.lifecycle) != 0 || len(fixture.transactions.state.audit) != 0 || fixture.transactions.rollbacks != 1 {
		t.Fatalf("partial state after rollback: %#v", fixture.transactions.state)
	}
}

func TestRecordLifecycleEventRejectsReservedCanonicalOriginDetails(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	_, err := fixture.service.RecordLifecycleEvent(context.Background(), fixture.actor, "ev_1", RecordLifecycleInput{
		Action:  evidencedomain.EvidenceLifecycleAmendmentValue,
		Reason:  "spoof",
		Details: map[string]any{legacyCanonicalOriginDetail: map[string]any{"release_id": "rel_spoof"}},
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("RecordLifecycleEvent error = %v, want validation", err)
	}
	if fixture.authorizer.calls != 1 || fixture.transactions.commits != 0 {
		t.Fatalf("reserved details reached resource lookup or persistence: %#v", fixture)
	}
}

func TestListLifecycleEventsFailsClosedOnCorruptAdapterEvent(t *testing.T) {
	fixture := newEvidenceServiceFixture(t)
	item := fixture.mutableEvidence("ev_1", "prod_1", testDigest('1'))
	fixture.reader.evidence[item.ID] = item
	fixture.reader.lifecycle = []evidencedomain.EvidenceLifecycleEvent{{
		ID: "elc_1", TenantID: "ten_other", EvidenceID: item.ID,
		Action: mustLifecycleState(t, evidencedomain.EvidenceLifecycleAcceptedValue), Reason: "accepted",
		ActorID: "key_1", SchemaVersion: evidencedomain.EvidenceLifecycleSchemaVersion, CreatedAt: fixture.now,
	}}

	if _, err := fixture.service.ListLifecycleEvents(context.Background(), fixture.actor, item.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("ListLifecycleEvents error = %v, want conflict", err)
	}
}

type evidenceServiceFixture struct {
	service         *Service
	actor           identitydomain.Actor
	now             time.Time
	reader          *fakeEvidenceReader
	authorizer      *fakeEvidenceAuthorizer
	transactions    *fakeEvidenceTransactions
	objects         *fakeObjectIngestion
	parser          *fakeEvidenceParser
	scanScopeProber *fakeVulnerabilityScanScopeProber
	canonicalizer   *fakeCanonicalizer
	sanitizer       *fakeLifecycleSanitizer
}

func newEvidenceServiceFixture(t *testing.T) *evidenceServiceFixture {
	t.Helper()
	now := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	reader := &fakeEvidenceReader{
		evidence: map[string]evidencedomain.EvidenceItem{}, sboms: map[string]evidencedomain.SBOM{},
		contracts: map[string]evidencedomain.OpenAPIContract{}, artifacts: map[string]string{}, artifactDigests: map[string]string{},
	}
	transactions := &fakeEvidenceTransactions{state: fakeEvidenceState{
		evidence: map[string]evidencedomain.EvidenceItem{}, artifactTenants: map[string]string{}, artifactDigests: map[string]string{}, sboms: map[string]evidencedomain.SBOM{}, contracts: map[string]evidencedomain.OpenAPIContract{}, scans: map[string]evidencedomain.VulnerabilityScan{},
		vexDocuments: map[string]evidencedomain.VEXDocument{}, vexImportReports: map[string]evidencedomain.VEXImportReport{},
		securityScans: map[string]evidencedomain.SecurityScan{}, manualDocs: map[string]evidencedomain.ManualSecurityDocument{},
		sbomDiffs: map[string]evidencedomain.SBOMDiff{}, contractDiffs: map[string]evidencedomain.ContractDiff{},
	}}
	authorizer := &fakeEvidenceAuthorizer{}
	transactions.authorizer = authorizer
	objects := &fakeObjectIngestion{stageNow: now}
	parser := &fakeEvidenceParser{}
	scanScopeProber := &fakeVulnerabilityScanScopeProber{scope: VulnerabilityScanScope{ReleaseID: "rel_1"}}
	canonicalizer := &fakeCanonicalizer{hash: testDigest('c')}
	sanitizer := &fakeLifecycleSanitizer{}
	idCounters := map[string]int{}
	service, err := NewService(Config{
		Reader: reader, Transactions: transactions, Authorizer: authorizer, Objects: objects, SourceObjects: objects, Parser: parser,
		VulnerabilityScanScopeProber: scanScopeProber,
		Canonicalizer:                canonicalizer, LifecycleSanitizer: sanitizer, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock: application.ClockFunc(func() time.Time { return now }),
		IDs: application.IDGeneratorFunc(func(prefix string) string {
			idCounters[prefix]++
			return prefix + "_" + strconv.Itoa(idCounters[prefix])
		}),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &evidenceServiceFixture{service: service, actor: identitydomain.Actor{TenantID: "ten_1", KeyID: "key_1", Scopes: []string{"*"}}, now: now, reader: reader, authorizer: authorizer, transactions: transactions, objects: objects, parser: parser, scanScopeProber: scanScopeProber, canonicalizer: canonicalizer, sanitizer: sanitizer}
}

func (f *evidenceServiceFixture) mutableEvidence(id, productID, payloadHash string) evidencedomain.EvidenceItem {
	return evidencedomain.EvidenceItem{
		ID: id, TenantID: f.actor.TenantID, ProductID: productID, Type: "build", Title: id,
		PayloadHash: payloadHash, CanonicalHash: testDigest('c'), Canonicalization: evidencedomain.EvidenceCanonicalizationProfileVersion,
		CreatedAt: f.now,
	}
}

func mustLifecycleState(t *testing.T, value string) evidencedomain.EvidenceLifecycleState {
	t.Helper()
	state, err := evidencedomain.ParseEvidenceLifecycleState(value)
	if err != nil {
		t.Fatalf("ParseEvidenceLifecycleState(%q): %v", value, err)
	}
	return state
}

type fakeEvidenceAuthorizer struct {
	calls     int
	err       error
	errAt     int
	authorize func(application.AuthorizationRequest) error
	requests  []application.AuthorizationRequest
	events    *[]string
}

func (f *fakeEvidenceAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, request application.AuthorizationRequest) error {
	f.calls++
	f.requests = append(f.requests, request)
	if f.events != nil {
		event := "authorize_scope"
		if request.Resources == (application.ResourceReferences{}) {
			event = "authorize_base"
		}
		*f.events = append(*f.events, event)
	}
	if f.authorize != nil {
		if err := f.authorize(request); err != nil {
			return err
		}
	}
	if f.errAt == 0 || f.calls == f.errAt {
		return f.err
	}
	return nil
}

type fakeEvidenceReader struct {
	evidence        map[string]evidencedomain.EvidenceItem
	evidenceResult  *evidencedomain.EvidenceItem
	sboms           map[string]evidencedomain.SBOM
	contracts       map[string]evidencedomain.OpenAPIContract
	artifacts       map[string]string
	artifactDigests map[string]string
	lifecycle       []evidencedomain.EvidenceLifecycleEvent
	scopes          []EvidenceScope
	scopeErr        error
	events          *[]string
}

func (f *fakeEvidenceReader) ValidateScope(_ context.Context, _ string, scope EvidenceScope) error {
	f.scopes = append(f.scopes, scope)
	if f.events != nil {
		*f.events = append(*f.events, "validate_scope")
	}
	return f.scopeErr
}
func (f *fakeEvidenceReader) ValidateLinkTarget(context.Context, string, string, string) error {
	return nil
}
func (f *fakeEvidenceReader) GetEvidence(_ context.Context, tenantID, id string) (evidencedomain.EvidenceItem, error) {
	if f.evidenceResult != nil {
		return cloneEvidence(*f.evidenceResult), nil
	}
	value, ok := f.evidence[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.EvidenceItem{}, ErrNotFound
	}
	return cloneEvidence(value), nil
}
func (f *fakeEvidenceReader) ListEvidence(_ context.Context, tenantID, releaseID, evidenceType string) ([]evidencedomain.EvidenceItem, error) {
	result := []evidencedomain.EvidenceItem{}
	for _, value := range f.evidence {
		if value.TenantID == tenantID && (releaseID == "" || value.ReleaseID == releaseID) && (evidenceType == "" || value.Type == evidenceType) {
			result = append(result, cloneEvidence(value))
		}
	}
	return result, nil
}
func (f *fakeEvidenceReader) ListLifecycleEvents(_ context.Context, tenantID, evidenceID string) ([]evidencedomain.EvidenceLifecycleEvent, error) {
	result := make([]evidencedomain.EvidenceLifecycleEvent, 0, len(f.lifecycle))
	for _, event := range f.lifecycle {
		result = append(result, cloneLifecycleEvent(event))
	}
	return result, nil
}

func (f *fakeEvidenceReader) ValidateArtifactReference(_ context.Context, tenantID, artifactID, digest string) error {
	if strings.TrimSpace(artifactID) == "" {
		return nil
	}
	if f.artifacts[artifactID] != tenantID || (digest != "" && !strings.EqualFold(f.artifactDigests[artifactID], digest)) {
		return ErrNotFound
	}
	return nil
}

func (f *fakeEvidenceReader) GetSBOM(_ context.Context, tenantID, id string) (evidencedomain.SBOM, error) {
	value, ok := f.sboms[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.SBOM{}, ErrNotFound
	}
	return cloneSBOM(value), nil
}

func (f *fakeEvidenceReader) GetOpenAPIContract(_ context.Context, tenantID, id string) (evidencedomain.OpenAPIContract, error) {
	value, ok := f.contracts[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.OpenAPIContract{}, ErrNotFound
	}
	return cloneOpenAPIContract(value), nil
}

type fakeObjectIngestion struct {
	calls            int
	stageCalls       int
	sourceStageCalls int
	err              error
	stageErr         error
	stageNow         time.Time
	noObject         bool
}

func (f *fakeObjectIngestion) StagePayloadSource(_ context.Context, tenantID, mediaType string, source PayloadSource) (StagedPayload, error) {
	f.sourceStageCalls++
	if f.stageErr != nil {
		return StagedPayload{}, f.stageErr
	}
	if f.noObject {
		return StagedPayload{}, nil
	}
	return StagedPayload{
		TenantID: tenantID, Digest: source.Digest, Size: source.Size, MediaType: mediaType,
		StagingKey: "tenants/" + tenantID + "/staging/" + strings.TrimPrefix(source.Digest, "sha256:"),
		FinalKey:   "tenants/" + tenantID + "/objects/" + strings.TrimPrefix(source.Digest, "sha256:"),
		Status:     PayloadStatusStaged, CreatedAt: f.stageNow, UpdatedAt: f.stageNow,
	}, nil
}

func (f *fakeObjectIngestion) ValidateStagedPayload(context.Context, StagedPayload) error {
	f.calls++
	return f.err
}

func (f *fakeObjectIngestion) StagePayload(_ context.Context, tenantID, mediaType, digest string, raw []byte) (StagedPayload, error) {
	f.stageCalls++
	if f.stageErr != nil {
		return StagedPayload{}, f.stageErr
	}
	return StagedPayload{
		TenantID: tenantID, Digest: digest, Size: int64(len(raw)), MediaType: mediaType,
		StagingKey: "tenants/" + tenantID + "/staging/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/" + tenantID + "/objects/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     PayloadStatusStaged, CreatedAt: f.stageNow, UpdatedAt: f.stageNow,
	}, nil
}

type fakeCanonicalizer struct {
	calls int
	hash  string
	err   error
}

type fakeLifecycleSanitizer struct {
	calls       int
	lastReason  string
	lastDetails map[string]any
}

func (f *fakeLifecycleSanitizer) SanitizeLifecycle(_ context.Context, reason string, details map[string]any) (string, map[string]any, error) {
	f.calls++
	f.lastReason = reason
	f.lastDetails = cloneMap(details)
	return "[redacted]", map[string]any{"safe": true}, nil
}

func (f *fakeCanonicalizer) HashEvidence(_ context.Context, _ evidencedomain.EvidenceItem) (string, error) {
	f.calls++
	return f.hash, f.err
}

type fakeEvidenceState struct {
	evidence         map[string]evidencedomain.EvidenceItem
	artifactTenants  map[string]string
	artifactDigests  map[string]string
	sboms            map[string]evidencedomain.SBOM
	contracts        map[string]evidencedomain.OpenAPIContract
	scans            map[string]evidencedomain.VulnerabilityScan
	vexDocuments     map[string]evidencedomain.VEXDocument
	vexImportReports map[string]evidencedomain.VEXImportReport
	securityScans    map[string]evidencedomain.SecurityScan
	manualDocs       map[string]evidencedomain.ManualSecurityDocument
	sbomDiffs        map[string]evidencedomain.SBOMDiff
	contractDiffs    map[string]evidencedomain.ContractDiff
	payloads         []StagedPayload
	outbox           []application.OutboxEvent
	audit            []application.AuditEvent
	lifecycle        []evidencedomain.EvidenceLifecycleEvent
}

func (s fakeEvidenceState) clone() fakeEvidenceState {
	result := fakeEvidenceState{
		evidence: map[string]evidencedomain.EvidenceItem{}, artifactTenants: map[string]string{}, artifactDigests: map[string]string{}, sboms: map[string]evidencedomain.SBOM{}, contracts: map[string]evidencedomain.OpenAPIContract{}, scans: map[string]evidencedomain.VulnerabilityScan{},
		vexDocuments: map[string]evidencedomain.VEXDocument{}, vexImportReports: map[string]evidencedomain.VEXImportReport{},
		securityScans: map[string]evidencedomain.SecurityScan{}, manualDocs: map[string]evidencedomain.ManualSecurityDocument{},
		sbomDiffs: map[string]evidencedomain.SBOMDiff{}, contractDiffs: map[string]evidencedomain.ContractDiff{},
		payloads: append([]StagedPayload(nil), s.payloads...), outbox: append([]application.OutboxEvent(nil), s.outbox...), audit: append([]application.AuditEvent(nil), s.audit...), lifecycle: append([]evidencedomain.EvidenceLifecycleEvent(nil), s.lifecycle...),
	}
	for key, value := range s.evidence {
		result.evidence[key] = cloneEvidence(value)
	}
	for key, value := range s.artifactTenants {
		result.artifactTenants[key] = value
	}
	for key, value := range s.artifactDigests {
		result.artifactDigests[key] = value
	}
	for key, value := range s.sboms {
		result.sboms[key] = cloneSBOM(value)
	}
	for key, value := range s.contracts {
		result.contracts[key] = cloneOpenAPIContract(value)
	}
	for key, value := range s.scans {
		result.scans[key] = cloneVulnerabilityScan(value)
	}
	for key, value := range s.vexDocuments {
		result.vexDocuments[key] = cloneVEXDocument(value)
	}
	for key, value := range s.vexImportReports {
		result.vexImportReports[key] = cloneVEXImportReport(value)
	}
	for key, value := range s.securityScans {
		result.securityScans[key] = cloneSecurityScan(value)
	}
	for key, value := range s.manualDocs {
		result.manualDocs[key] = value
	}
	for key, value := range s.sbomDiffs {
		result.sbomDiffs[key] = cloneSBOMDiff(value)
	}
	for key, value := range s.contractDiffs {
		result.contractDiffs[key] = cloneContractDiff(value)
	}
	return result
}

type fakeEvidenceTransactions struct {
	commitErr          error
	authorizer         *fakeEvidenceAuthorizer
	beforeExecute      func()
	emptyAuditReceipt  bool
	state              fakeEvidenceState
	auditErr           error
	auditFailAt        int
	ingestionWriteErr  error
	scopeValidator     func(EvidenceScope) error
	validatedScopes    []EvidenceScope
	validatedArtifacts []string
	beforeLinkCAS      func(*fakeEvidenceState)
	commits            int
	rollbacks          int
}

func (f *fakeEvidenceTransactions) Execute(ctx context.Context, command TransactionCommand) error {
	if f.beforeExecute != nil {
		f.beforeExecute()
	}
	pending := f.state.clone()
	tx := &fakeEvidenceTransaction{
		authorizer: f.authorizer, emptyAuditReceipt: f.emptyAuditReceipt,
		state: &pending, auditErr: f.auditErr, auditFailAt: f.auditFailAt,
		ingestionWriteErr: f.ingestionWriteErr, scopeValidator: f.scopeValidator,
		beforeLinkCAS: f.beforeLinkCAS,
	}
	if err := command(ctx, tx); err != nil {
		f.validatedScopes = append(f.validatedScopes, tx.validatedScopes...)
		f.validatedArtifacts = append(f.validatedArtifacts, tx.validatedArtifacts...)
		f.rollbacks++
		return err
	}
	f.validatedScopes = append(f.validatedScopes, tx.validatedScopes...)
	f.validatedArtifacts = append(f.validatedArtifacts, tx.validatedArtifacts...)
	if f.commitErr != nil {
		f.rollbacks++
		return f.commitErr
	}
	f.state = pending
	f.commits++
	return nil
}

type fakeEvidenceTransaction struct {
	authorizer         *fakeEvidenceAuthorizer
	emptyAuditReceipt  bool
	state              *fakeEvidenceState
	auditErr           error
	auditFailAt        int
	auditCalls         int
	ingestionWriteErr  error
	scopeValidator     func(EvidenceScope) error
	validatedScopes    []EvidenceScope
	validatedArtifacts []string
	beforeLinkCAS      func(*fakeEvidenceState)
}

func (f *fakeEvidenceTransaction) Evidence() Repository {
	return fakeEvidenceRepository{tx: f}
}

func (f *fakeEvidenceTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.authorizer.Authorize(ctx, actor, request)
}
func (f *fakeEvidenceTransaction) Payloads() PayloadRecorder {
	return fakePayloadRecorder{state: f.state}
}
func (f *fakeEvidenceTransaction) Outbox() application.OutboxEnqueuer {
	return fakeEvidenceOutbox{state: f.state}
}
func (f *fakeEvidenceTransaction) Audit() application.AuditAppender {
	return fakeEvidenceAudit{tx: f}
}

func (f *fakeEvidenceTransaction) Ingestion() IngestionRepository {
	return fakeIngestionRepository{tx: f}
}

type fakeEvidenceRepository struct{ tx *fakeEvidenceTransaction }

func (f fakeEvidenceRepository) ValidateScope(_ context.Context, _ string, scope EvidenceScope) error {
	f.tx.validatedScopes = append(f.tx.validatedScopes, scope)
	if f.tx.scopeValidator != nil {
		return f.tx.scopeValidator(scope)
	}
	return nil
}
func (f fakeEvidenceRepository) ValidateLinkTarget(context.Context, string, string, string) error {
	return nil
}
func (f fakeEvidenceRepository) GetEvidence(_ context.Context, tenantID, id string) (evidencedomain.EvidenceItem, error) {
	value, ok := f.tx.state.evidence[id]
	if !ok || value.TenantID != tenantID {
		return evidencedomain.EvidenceItem{}, ErrNotFound
	}
	return cloneEvidence(value), nil
}
func (f fakeEvidenceRepository) InsertEvidence(_ context.Context, value evidencedomain.EvidenceItem) error {
	f.tx.state.evidence[value.ID] = cloneEvidence(value)
	return nil
}
func (f fakeEvidenceRepository) RecordSupersession(_ context.Context, first, replacement evidencedomain.EvidenceItem) error {
	f.tx.state.evidence[first.ID] = cloneEvidence(first)
	f.tx.state.evidence[replacement.ID] = cloneEvidence(replacement)
	return nil
}
func (f fakeEvidenceRepository) CompareAndSwapEvidenceLinks(_ context.Context, expected, replacement evidencedomain.EvidenceItem) error {
	if f.tx.beforeLinkCAS != nil {
		f.tx.beforeLinkCAS(f.tx.state)
		f.tx.beforeLinkCAS = nil
	}
	stored, ok := f.tx.state.evidence[expected.ID]
	if !ok || stored.TenantID != expected.TenantID || stored.ProductID != expected.ProductID || stored.ProjectID != expected.ProjectID || stored.ReleaseID != expected.ReleaseID || stored.BuildID != expected.BuildID || stored.DeploymentID != expected.DeploymentID || !reflect.DeepEqual(stored.RelatedEvidenceRefs, expected.RelatedEvidenceRefs) {
		return ErrConflict
	}
	f.tx.state.evidence[replacement.ID] = cloneEvidence(replacement)
	return nil
}
func (f fakeEvidenceRepository) AppendLifecycle(_ context.Context, value evidencedomain.EvidenceLifecycleEvent) error {
	f.tx.state.lifecycle = append(f.tx.state.lifecycle, cloneLifecycleEvent(value))
	return nil
}

type fakePayloadRecorder struct{ state *fakeEvidenceState }

func (f fakePayloadRecorder) RecordStagedPayload(_ context.Context, value StagedPayload) error {
	f.state.payloads = append(f.state.payloads, value)
	return nil
}

type fakeEvidenceOutbox struct{ state *fakeEvidenceState }

func (f fakeEvidenceOutbox) EnqueueOutbox(_ context.Context, value application.OutboxEvent) error {
	f.state.outbox = append(f.state.outbox, value)
	return nil
}

type fakeEvidenceAudit struct{ tx *fakeEvidenceTransaction }

func (f fakeEvidenceAudit) AppendAudit(_ context.Context, value application.AuditEvent) (application.AuditReceipt, error) {
	f.tx.auditCalls++
	if f.tx.auditErr != nil || (f.tx.auditFailAt > 0 && f.tx.auditCalls == f.tx.auditFailAt) {
		return application.AuditReceipt{}, errAuditFailure
	}
	f.tx.state.audit = append(f.tx.state.audit, value)
	if f.tx.emptyAuditReceipt {
		return application.AuditReceipt{}, nil
	}
	return application.AuditReceipt{ID: value.ID}, nil
}

func testDigest(character rune) string {
	result := "sha256:"
	for range 64 {
		result += string(character)
	}
	return result
}

package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type creationGuardTransaction struct {
	EvidenceCreationTransaction // Every unsupported operation panics.
	scopes                      []EvidenceScope
	artifacts                   []string
	authorizations              []application.ResourceReferences
	denied                      bool
}

func (f *creationGuardTransaction) ValidateScope(_ context.Context, _ string, s EvidenceScope) error {
	f.scopes = append(f.scopes, s)
	return nil
}
func (f *creationGuardTransaction) ValidateArtifactIdentity(_ context.Context, _ string, id string) error {
	f.artifacts = append(f.artifacts, id)
	return nil
}
func (f *creationGuardTransaction) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.authorizations = append(f.authorizations, r.Resources)
	if f.denied {
		return application.ErrForbidden
	}
	return nil
}
func (f *creationGuardTransaction) ExecuteEvidenceCreation(ctx context.Context, fn func(context.Context, EvidenceCreationTransaction) error) error {
	return fn(ctx, f)
}

type panicCreationReader struct{}

func (panicCreationReader) ValidateScope(context.Context, string, EvidenceScope) error {
	panic("guard used nontransactional reader")
}
func (panicCreationReader) ValidateArtifactReference(context.Context, string, string, string) error {
	panic("guard inspected declared digest")
}

type panicCreationPayloadValidator struct{}

func (panicCreationPayloadValidator) ValidateStagedPayload(context.Context, StagedPayload) error {
	panic("guard inspected payload")
}

func TestEvidenceCreationGuardReadsOnlyCurrentCoordinatesAndGrants(t *testing.T) {
	f := newEvidenceServiceFixture(t)
	tx := &creationGuardTransaction{}
	config := creationConfig(f)
	config.Reader = panicCreationReader{}
	config.Transactions = tx
	config.Payloads = panicCreationPayloadValidator{}
	config.Clock = application.ClockFunc(func() time.Time { panic("guard used clock") })
	config.IDs = application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })
	config.Canonicalizer = creationCanonicalizerFunc(func(context.Context, evidencedomain.EvidenceItem) (string, error) { panic("guard hashed evidence") })
	c, err := NewEvidenceCreationCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	in := CreateEvidenceInput{BuildID: " build ", Type: "manual", Title: "Evidence", PayloadHash: testDigest('a'), StagedPayload: StagedPayload{Status: PayloadStatusStaged}, SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: testDigest('b')}, {Type: "release", ID: "release"}, {Type: "opaque", ID: "label"}, {Type: "artifact", Digest: testDigest('b')}}}
	if err := c.AuthorizeEvidenceCreation(t.Context(), f.actor, in); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.scopes, []EvidenceScope{{BuildID: "build"}, {ReleaseID: "release"}}) || !reflect.DeepEqual(tx.artifacts, []string{"artifact"}) || !reflect.DeepEqual(tx.authorizations, []application.ResourceReferences{{BuildID: "build"}, {ArtifactID: "artifact"}, {ReleaseID: "release"}}) {
		t.Fatal("guard omitted current coordinates or inspected opaque labels", tx)
	}
	tx.denied = true
	if err := c.AuthorizeEvidenceCreation(t.Context(), f.actor, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant retained replay", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.AuthorizeEvidenceCreation(canceled, f.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("guard ignored cancellation", err)
	}
	if len(f.transactions.state.evidence) != 0 || len(f.transactions.state.audit) != 0 || len(f.transactions.state.payloads) != 0 || len(f.transactions.state.outbox) != 0 {
		t.Fatal("guard wrote effects")
	}
}

package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type candidateGuardFake struct{ candidateCreationFake }

func (f *candidateGuardFake) ExecuteCandidateCreation(ctx context.Context, fn func(context.Context, CandidateCreationTransaction) error) error {
	f.runs++
	return fn(ctx, f)
}
func (*candidateGuardFake) InsertCandidate(context.Context, releasedomain.ReleaseCandidate) error {
	panic("guard created snapshot")
}
func (*candidateGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard appended audit")
}

type candidateGuardPanicCanonicalizer struct{}

func (candidateGuardPanicCanonicalizer) HashReleaseCandidate(context.Context, releasedomain.ReleaseCandidate) (string, error) {
	panic("guard hashed snapshot")
}

func TestCandidateCreationGuardPreservesReferenceDuplicatesWithoutHashingOrWrites(t *testing.T) {
	f := &candidateGuardFake{candidateCreationFake: candidateCreationFake{parent: CandidateReleaseCoordinates{ID: "release", TenantID: "tenant", ProductID: "product"}}}
	s, err := NewCandidateCommands(CandidateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Canonicalizer: candidateGuardPanicCanonicalizer{}, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	in := CreateReleaseCandidateInput{ReleaseID: "release", Name: "Snapshot", BuildIDs: []string{" build2 ", "build", "build"}, ArtifactIDs: []string{"artifact", " artifact "}}
	if err := s.AuthorizeCandidateCreation(t.Context(), a, in); err != nil || f.runs != 1 || f.reads != 1 || f.refCalls != 1 || !reflect.DeepEqual(f.refs.BuildIDs, []string{"build", "build", "build2"}) || !reflect.DeepEqual(f.refs.ArtifactIDs, []string{"artifact", "artifact"}) || len(f.requests) != 2 {
		t.Fatal("guard omitted ownership/grants or altered snapshot references", err, f)
	}
	in.BuildIDs[0] = "mutated"
	if f.refs.BuildIDs[2] != "build2" {
		t.Fatal("caller retained reference ownership")
	}
	f.authErr = application.ErrForbidden
	before := f.refCalls
	if err := s.AuthorizeCandidateCreation(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.refCalls != before {
		t.Fatal("denied parent reached references", err, f)
	}
	f.authErr = nil
	f.refsErr = ErrNotFound
	if err := s.AuthorizeCandidateCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing reference retained replay", err)
	}
	f.refsErr = nil
	f.parent.TenantID = "foreign"
	if err := s.AuthorizeCandidateCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign parent retained replay", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before = f.runs
	if err := s.AuthorizeCandidateCreation(ctx, a, in); !errors.Is(err, context.Canceled) || f.runs != before {
		t.Fatal("cancelled guard opened transaction", err, f)
	}
}

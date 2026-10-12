package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStateTransitionsRejectRawBudgetsBeforeReadsOrWrites(t *testing.T) {
	f := newServiceFixture(t)
	r, err := NewReleaseStateCommands(ReleaseStateCommandConfig{Reader: legacyReleaseStateReader{source: f.reader}, Authorizer: f.authorizer, Transactions: releaseStateTransactions{runner: f.transactions}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "id" })})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("release ID", func(t *testing.T) {
		if _, err := r.FreezeRelease(t.Context(), f.actor, strings.Repeat(" ", 1024)+"release", 1); !errors.Is(err, ErrValidation) || f.reader.calls != 0 {
			t.Fatal("raw release ID reached read", err, f.reader.calls)
		}
	})
	state, _ := releasedomain.ParseReleaseCandidateState("open")
	for _, kind := range []string{"id", "reason", "state"} {
		t.Run(kind, func(t *testing.T) {
			f := &candidateStateFake{row: CandidateStateRow{Candidate: releasedomain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "release", State: state, Revision: 1}, ProductID: "product"}}
			s, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
			if err != nil {
				t.Fatal(err)
			}
			id, target, reason := "candidate", "promoted", "Reviewed"
			switch kind {
			case "id":
				id = strings.Repeat(" ", 1024) + id
			case "reason":
				reason = strings.Repeat(" ", 65536) + reason
			case "state":
				target = strings.Repeat(" ", 32) + target
			}
			if _, err := s.UpdateReleaseCandidateState(t.Context(), identitydomain.Actor{TenantID: "tenant"}, id, target, reason, 1); !errors.Is(err, ErrValidation) || f.runs != 0 {
				t.Fatal("raw candidate input reached transaction", kind, err, f.runs)
			}
		})
	}
}

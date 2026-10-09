package app

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCandidateCreationRejectsRawBudgetsBeforeTrimmingOrTransaction(t *testing.T) {
	for _, kind := range []string{"parent", "name", "reference", "combined references"} {
		t.Run(kind, func(t *testing.T) {
			f := &candidateCreationFake{parent: CandidateReleaseCoordinates{ID: "release", TenantID: "tenant", ProductID: "product"}}
			s, err := NewCandidateCommands(CandidateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Canonicalizer: &fakeReleaseCandidateCanonicalizer{hash: testSHA256('c')}, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_1" })})
			if err != nil {
				t.Fatal(err)
			}
			in := CreateReleaseCandidateInput{ReleaseID: "release", Name: "Candidate"}
			switch kind {
			case "parent":
				in.ReleaseID = strings.Repeat(" ", 1024) + "release"
			case "name":
				in.Name = strings.Repeat(" ", 65536) + "Candidate"
			case "reference":
				in.BuildIDs = []string{strings.Repeat(" ", 1024) + "build"}
			case "combined references":
				in.BuildIDs = make([]string, 65)
				for n := range in.BuildIDs {
					in.BuildIDs[n] = strings.Repeat(" ", 1023) + "b"
				}
			}
			if _, err := s.CreateReleaseCandidate(t.Context(), identitydomain.Actor{TenantID: "tenant"}, in); !errors.Is(err, ErrValidation) || f.runs != 0 {
				t.Fatal("raw budget reached transaction", err, f.runs)
			}
		})
	}
}

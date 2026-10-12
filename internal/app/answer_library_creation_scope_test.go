package app

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestAnswerLibraryLocalCreationRejectsStaleParentsAndMutableAliases(t *testing.T) {
	for _, kind := range []string{"project", "release", "build", "deployment", "framework", "answer", "alias"} {
		t.Run(kind, func(t *testing.T) {
			l := newLegacyLedgerFixture(Config{})
			l.tenants["tenant"] = domain.Tenant{ID: "tenant"}
			l.products["product"] = domain.Product{ID: "product", TenantID: "tenant"}
			l.releases["release"] = domain.Release{ID: "release", TenantID: "tenant", ProductID: "product"}
			l.frameworks["framework"] = domain.ControlFramework{ID: "framework", TenantID: "tenant"}
			l.controls["control"] = domain.SecurityControl{ID: "control", TenantID: "tenant", FrameworkID: "framework"}
			item := domain.EvidenceItem{ID: "evidence", TenantID: "tenant", ProductID: "product", ReleaseID: "release"}
			in := CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q", ControlID: "control", ProductID: "product", ReleaseID: "release", Answer: "Draft", EvidenceIDs: []string{"evidence"}}
			want := ErrNotFound
			switch kind {
			case "project":
				item.ProjectID = "missing"
			case "release":
				item.ReleaseID = "missing"
				in.ReleaseID = ""
			case "build":
				item.BuildID = "missing"
			case "deployment":
				item.DeploymentID = "missing"
			case "framework":
				l.controls["control"] = domain.SecurityControl{ID: "control", TenantID: "tenant", FrameworkID: "foreign"}
			case "answer":
				in.Answer = strings.Repeat("a", 65537)
				want = ErrValidation
			}
			l.evidence[item.ID] = item
			v, err := l.CreateQuestionnaireAnswerLibraryEntry(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, in)
			if kind == "alias" {
				if err != nil {
					t.Fatal(err)
				}
				v.EvidenceIDs[0] = "mutated"
				v.Limitations[0] = "mutated"
				if l.answerLibrary[v.ID].EvidenceIDs[0] != "evidence" || l.answerLibrary[v.ID].Limitations[0] == "mutated" {
					t.Fatal("immutable stored entry aliases returned slices")
				}
				return
			}
			if !errors.Is(err, want) || v.ID != "" || len(l.answerLibrary)+len(l.chain["tenant"]) != 0 {
				t.Fatal("unsafe local answer published", kind, v.ID, err)
			}
		})
	}
}

func TestAnswerLibraryLocalCreationBoundsSelectedCitationCoordinates(t *testing.T) {
	l := newLegacyLedgerFixture(Config{})
	l.tenants["tenant"] = domain.Tenant{ID: "tenant"}
	p, j, r := strings.Repeat("p", 1024), strings.Repeat("j", 1024), strings.Repeat("r", 1024)
	l.products[p] = domain.Product{ID: p, TenantID: "tenant"}
	l.projects[j] = domain.Project{ID: j, TenantID: "tenant", ProductID: p}
	l.releases[r] = domain.Release{ID: r, TenantID: "tenant", ProductID: p}
	ids := make([]string, 1500)
	for i := range ids {
		id := fmt.Sprintf("e-%d", i)
		ids[i] = id
		l.evidence[id] = domain.EvidenceItem{ID: id, TenantID: "tenant", ProductID: p, ProjectID: j, ReleaseID: r}
	}
	v, err := l.CreateQuestionnaireAnswerLibraryEntry(t.Context(), domain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: "q", Answer: "Draft", EvidenceIDs: ids})
	if !errors.Is(err, ErrValidation) || v.ID != "" || len(l.answerLibrary)+len(l.chain["tenant"]) != 0 {
		t.Fatal("oversized selected coordinates published", v.ID, err)
	}
}

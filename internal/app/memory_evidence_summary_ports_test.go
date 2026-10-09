package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type memoryEvidenceSummaryPorts interface {
	packageapp.EvidenceSummaryReader
	InsertFocusedEvidenceSummary(context.Context, packagedomain.EvidenceSummary) error
}

func memoryEvidenceSummaryFixture(t *testing.T) (*memoryUnitOfWork, memoryEvidenceSummaryPorts) {
	t.Helper()
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Future.(memoryEvidenceSummaryPorts)
	if !ok {
		t.Fatal("memory future repository lacks focused evidence-summary ports")
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Type, e.Title, e.CanonicalHash, e.PayloadRef = "build", "Recorded build", "canonical", "private-payload"
	e.ProjectID = "tenant-project"
	tx.state.Evidence[e.ID] = e
	return tx, r
}

func TestMemoryEvidenceSummaryItemsKeepRawSelectionAndBoundMetadata(t *testing.T) {
	tx, r := memoryEvidenceSummaryFixture(t)
	e := tx.state.Evidence["tenant-evidence"]
	// A project-only raw root resolves a product for authorization, but must not
	// silently narrow the automatic evidence selector to stored product IDs.
	e.ProductID, e.ReleaseID = "", ""
	tx.state.Evidence[e.ID] = e
	s, err := r.ReadEvidenceSummaryScope(t.Context(), "tenant", "evidence", e.ID)
	if err != nil || s.Filter.ProductID != "" || s.Resources.ProductID != "tenant-product" {
		t.Fatal("scope lost raw versus inferred coordinates", s, err)
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	want := []packageapp.EvidenceSummaryItem{{ID: e.ID, TenantID: e.TenantID, Type: e.Type, Title: e.Title, CanonicalHash: e.CanonicalHash, Resources: application.ResourceReferences{ProjectID: e.ProjectID}}}
	for _, ids := range [][]string{nil, {e.ID}} {
		got, err := r.ReadEvidenceSummaryItems(t.Context(), s, ids)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("summary metadata widened, omitted fields or changed raw selectors", got, err)
		}
	}
	got, err := r.ReadEvidenceSummaryItems(t.Context(), s, []string{"foreign-evidence"})
	if err != nil || len(got) != 0 {
		t.Fatal("explicit citation crossed tenant", got, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("summary metadata reads changed storage")
	}
	e.Title = strings.Repeat("x", packageapp.MaxEvidenceSummaryTitleBytes+1)
	tx.state.Evidence[e.ID] = e
	if got, err := r.ReadEvidenceSummaryItems(t.Context(), s, []string{e.ID}); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("oversized citation exposed a partial projection", got, err)
	}
	e.Title = "Recorded build"
	tx.state.Evidence[e.ID] = e
	for i := 0; i < packageapp.MaxEvidenceSummaryItems; i++ {
		v := e
		v.ID = fmt.Sprintf("extra-%04d", i)
		tx.state.Evidence[v.ID] = v
	}
	if got, err := r.ReadEvidenceSummaryItems(t.Context(), s, nil); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("automatic selection silently truncated over-budget evidence", got, err)
	}
	if got, err := r.ReadEvidenceSummaryItems(t.Context(), s, []string{e.ID}); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("explicit selection scanned unrelated citation metadata", got, err)
	}
	byteBound := []string{e.ID}
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("extra-%04d", i)
		v := tx.state.Evidence[id]
		v.Title = strings.Repeat("x", packageapp.MaxEvidenceSummaryTitleBytes)
		tx.state.Evidence[id] = v
		byteBound = append(byteBound, id)
	}
	if got, err := r.ReadEvidenceSummaryItems(t.Context(), s, byteBound); !errors.Is(err, ErrValidation) || got != nil {
		t.Fatal("combined citation bytes exceeded the report budget", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := r.ReadEvidenceSummaryItems(ctx, s, []string{e.ID}); !errors.Is(err, context.Canceled) || got != nil {
		t.Fatal("citation read ignored cancellation", got, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadEvidenceSummaryItems(t.Context(), s, []string{e.ID}); !errors.Is(err, ErrConflict) {
		t.Fatal("citation read accepted a closed transaction", err)
	}
}

func TestMemoryFocusedEvidenceSummaryInsertRevalidatesAndDetaches(t *testing.T) {
	tx, r := memoryEvidenceSummaryFixture(t)
	e := tx.state.Evidence["tenant-evidence"]
	v := packagedomain.EvidenceSummary{ID: "new-summary", TenantID: "tenant", SubjectType: "release", SubjectID: "tenant-release", EvidenceIDs: []string{e.ID}, Summary: "Recorded build summary", Citations: []packagedomain.EvidenceCitation{{EvidenceID: e.ID, Type: e.Type, Title: e.Title, CanonicalHash: e.CanonicalHash}}, Assumptions: []string{"selected records"}, Limitations: []string{"review required"}, SchemaVersion: packagedomain.EvidenceSummaryVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedEvidenceSummary(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	want := domain.EvidenceSummary{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: v.EvidenceIDs, Summary: v.Summary, Citations: []domain.EvidenceCitation{{EvidenceID: e.ID, Type: e.Type, Title: e.Title, CanonicalHash: e.CanonicalHash}}, Assumptions: v.Assumptions, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
	if !reflect.DeepEqual(tx.state.EvidenceSummaries[v.ID], want) {
		t.Fatal("focused summary mapper dropped fields", tx.state.EvidenceSummaries[v.ID])
	}
	v.EvidenceIDs[0], v.Citations[0].Title, v.Assumptions[0], v.Limitations[0] = "mutated", "mutated", "mutated", "mutated"
	if saved := tx.state.EvidenceSummaries[v.ID]; saved.EvidenceIDs[0] != e.ID || saved.Citations[0].Title != e.Title || saved.Assumptions[0] != "selected records" || saved.Limitations[0] != "review required" {
		t.Fatal("summary insert retained caller metadata")
	}
	v.EvidenceIDs, v.Citations = []string{e.ID}, []packagedomain.EvidenceCitation{{EvidenceID: e.ID, Type: e.Type, Title: e.Title, CanonicalHash: e.CanonicalHash}}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v.ID, v.SubjectID = "foreign-root", "foreign-release"
	if err := r.InsertFocusedEvidenceSummary(t.Context(), v); !errors.Is(err, ErrNotFound) {
		t.Fatal("summary accepted a foreign root", err)
	}
	v.ID, v.SubjectID, v.Citations[0].Title = "forged-citation", "tenant-release", "forged title"
	if err := r.InsertFocusedEvidenceSummary(t.Context(), v); !errors.Is(err, ErrValidation) {
		t.Fatal("summary persisted mismatched citation metadata", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("rejected summary changed storage")
	}
}

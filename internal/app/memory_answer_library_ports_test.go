package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type memoryAnswerLibraryPorts interface {
	packageapp.AnswerLibraryReader
	packagequery.AnswerLibraryReader
	InsertFocusedAnswerLibraryEntry(context.Context, packagedomain.QuestionnaireAnswerLibraryEntry) error
}

func TestMemoryAnswerLibraryOwnershipReadsDoNotTransferPrivatePayloads(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Enterprise.(memoryAnswerLibraryPorts)
	if !ok {
		t.Fatal("memory enterprise lacks focused answer-library ports")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []struct{ product, release string }{{"", ""}, {"tenant-product", ""}, {"", "tenant-release"}, {"tenant-product", "tenant-release"}} {
		s, err := r.ReadAnswerLibraryScope(t.Context(), "tenant", raw.product, raw.release)
		product := raw.product
		if raw.release != "" {
			product = "tenant-product"
		}
		if err != nil || s != (packageapp.AnswerLibraryScope{TenantID: "tenant", ProductID: raw.product, ReleaseID: raw.release, Resources: application.ResourceReferences{ProductID: product, ReleaseID: raw.release}}) {
			t.Fatal("scope changed raw versus resolved coordinates", s, err)
		}
		if err := r.ValidateAnswerLibraryReferences(t.Context(), s, "tenant-control", []string{"tenant-evidence", "tenant-evidence"}); err != nil {
			t.Fatal(err)
		}
		if err := r.ValidateAnswerLibraryReferences(t.Context(), s, "foreign-control", nil); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign control accepted", err)
		}
		if err := r.ValidateAnswerLibraryReferences(t.Context(), s, "", []string{"foreign-evidence"}); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign citation accepted", err)
		}
	}
	if _, err := r.ReadAnswerLibraryScope(t.Context(), "tenant", "foreign-product", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("scope crossed tenant", err)
	}
	if err := r.ValidateAnswerLibraryReferences(t.Context(), packageapp.AnswerLibraryScope{TenantID: "tenant"}, "", make([]string, 4097)); !errors.Is(err, ErrValidation) {
		t.Fatal("unbounded citation list accepted", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("ownership reads changed state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadAnswerLibraryScope(ctx, "tenant", "", ""); !errors.Is(err, context.Canceled) {
		t.Fatal("scope ignored cancellation", err)
	}
	if err := r.ValidateAnswerLibraryReferences(ctx, packageapp.AnswerLibraryScope{TenantID: "tenant"}, "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("references ignored cancellation", err)
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.ProjectID = "foreign-project"
	tx.state.Evidence[e.ID] = e
	if err := r.ValidateAnswerLibraryReferences(t.Context(), packageapp.AnswerLibraryScope{TenantID: "tenant"}, "", []string{e.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign evidence parent accepted", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAnswerLibraryScope(t.Context(), "tenant", "", ""); !errors.Is(err, ErrConflict) {
		t.Fatal("scope accepted a closed transaction", err)
	}
	if err := r.ValidateAnswerLibraryReferences(t.Context(), packageapp.AnswerLibraryScope{TenantID: "tenant"}, "", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("references accepted a closed transaction", err)
	}
}

func TestMemoryAnswerLibraryPagesFilterBeforePrivateProjectionAndDetachFields(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Enterprise.(memoryAnswerLibraryPorts)
	if !ok {
		t.Fatal("memory enterprise lacks focused answer-library ports")
	}
	for key, e := range tx.state.AnswerLibrary {
		e.SchemaVersion = domain.QuestionnaireAnswerLibraryVersion
		if e.TenantID == "tenant" {
			e.EvidenceType, e.ControlID = "build", "tenant-control"
		}
		tx.state.AnswerLibrary[key] = e
	}
	global := tx.state.AnswerLibrary["tenant-answer"]
	global.ID, global.ProductID, global.ReleaseID = "000-global", "", ""
	global.Answer = strings.Repeat("private global", 65537)
	global.EvidenceIDs = nil
	tx.state.AnswerLibrary[global.ID] = global
	second := tx.state.AnswerLibrary["tenant-answer"]
	second.ID = "zzz-answer"
	tx.state.AnswerLibrary[second.ID] = second
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	request := packagequery.AnswerLibraryPageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}}
	first, err := r.PageAnswerLibrary(t.Context(), request)
	if err != nil || len(first.Items) != 1 || first.Items[0].Entry.ID != "tenant-answer" || first.Items[0].EffectiveProductID != "tenant-product" || first.Next == nil {
		t.Fatal("visibility applied after paging or widened private projection", first, err)
	}
	if !reflect.DeepEqual(first.Items[0].Entry, packagedomain.QuestionnaireAnswerLibraryEntry{ID: "tenant-answer", TenantID: "tenant", QuestionID: "q", EvidenceType: "build", ControlID: "tenant-control", ProductID: "tenant-product", ReleaseID: "tenant-release", Answer: "private scoped answer", EvidenceIDs: []string{"tenant-evidence"}, Limitations: []string{"review"}, SchemaVersion: domain.QuestionnaireAnswerLibraryVersion, CreatedAt: fixedNow()}) {
		t.Fatal("page dropped complete answer metadata", first.Items[0])
	}
	first.Items[0].Entry.EvidenceIDs[0], first.Items[0].Entry.Limitations[0] = "mutated", "mutated"
	request.After = first.Next
	last, err := r.PageAnswerLibrary(t.Context(), request)
	if err != nil || len(last.Items) != 1 || last.Items[0].Entry.ID != "zzz-answer" || last.Next != nil {
		t.Fatal("page lost continuation", last, err)
	}
	request.After = nil
	request.Filter.ProductID = "foreign-product"
	if _, err := r.PageAnswerLibrary(t.Context(), request); !errors.Is(err, packagequery.ErrNotFound) {
		t.Fatal("filter crossed tenant", err)
	}
	request.Filter.ProductID = "tenant-product"
	request.AllowedProductIDs = []string{"other-product"}
	if _, err := r.PageAnswerLibrary(t.Context(), request); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("explicit filter ignored current grants", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("paging or returned mutation changed storage")
	}
	request.Filter, request.AllowedProductIDs = packagequery.AnswerLibraryFilter{}, []string{"tenant-product"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if page, err := r.PageAnswerLibrary(ctx, request); !errors.Is(err, context.Canceled) || len(page.Items) != 0 || page.Next != nil {
		t.Fatal("paging ignored cancellation or exposed a partial page", page, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page, err := r.PageAnswerLibrary(t.Context(), request); !errors.Is(err, ErrConflict) || len(page.Items) != 0 || page.Next != nil {
		t.Fatal("paging accepted a closed transaction or exposed a partial page", page, err)
	}
}

func TestMemoryFocusedAnswerLibraryInsertRevalidatesAndDetaches(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Enterprise.(memoryAnswerLibraryPorts)
	if !ok {
		t.Fatal("memory enterprise lacks focused answer-library ports")
	}
	v := packagedomain.QuestionnaireAnswerLibraryEntry{ID: "new-answer", TenantID: "tenant", QuestionID: "q", EvidenceType: "build", ControlID: "tenant-control", ProductID: "tenant-product", ReleaseID: "tenant-release", Answer: "Reviewed", EvidenceIDs: []string{"tenant-evidence", "tenant-evidence"}, Limitations: []string{"", "review", "review"}, SchemaVersion: packagedomain.QuestionnaireAnswerLibraryVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedAnswerLibraryEntry(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	saved := tx.state.AnswerLibrary[v.ID]
	if !reflect.DeepEqual(saved, domain.QuestionnaireAnswerLibraryEntry{ID: v.ID, TenantID: v.TenantID, QuestionID: v.QuestionID, EvidenceType: v.EvidenceType, ControlID: v.ControlID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Answer: v.Answer, EvidenceIDs: v.EvidenceIDs, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}) {
		t.Fatal("focused insert changed complete DTO or duplicate/blank metadata", saved)
	}
	v.EvidenceIDs[0], v.Limitations[1] = "mutated", "mutated"
	if tx.state.AnswerLibrary[v.ID].EvidenceIDs[0] != "tenant-evidence" || tx.state.AnswerLibrary[v.ID].Limitations[1] != "review" {
		t.Fatal("insert retained caller arrays")
	}
	v.ID, v.ControlID = "foreign-ref", "foreign-control"
	v.EvidenceIDs = []string{"tenant-evidence"}
	v.Limitations = []string{"review"}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedAnswerLibraryEntry(t.Context(), v); !errors.Is(err, ErrNotFound) {
		t.Fatal("focused insert accepted foreign control", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("rejected insert changed storage")
	}
}

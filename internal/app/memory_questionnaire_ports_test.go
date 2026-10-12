package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestMemoryFocusedQuestionnaireWritesKeepCompleteDetachedRecords(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r := tx.Repositories().Enterprise.(interface {
		InsertFocusedQuestionnaireTemplate(context.Context, packagedomain.QuestionnaireTemplate) error
		InsertFocusedQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
	})
	tpl := packagedomain.QuestionnaireTemplate{ID: "new-template", TenantID: "tenant", Name: "Native", Version: "2", Questions: []packagedomain.QuestionnaireQuestion{{ID: "q", Prompt: "Reviewed?", ControlID: "tenant-control", EvidenceType: "build", AllowedFields: []string{"", "title", "title"}}}, SchemaVersion: packagedomain.QuestionnaireTemplateVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedQuestionnaireTemplate(t.Context(), tpl); err != nil {
		t.Fatal(err)
	}
	// Owned models and compatibility DTOs intentionally use different JSON
	// tags. Compare every named field recursively, including nil/empty slices,
	// rather than treating raw json.Marshal output as their shared wire codec.
	var assertFields func(reflect.Value, reflect.Value)
	assertFields = func(want, got reflect.Value) {
		t.Helper()
		if want.Type() == got.Type() {
			if !reflect.DeepEqual(want.Interface(), got.Interface()) {
				t.Fatal("focused mapper changed field", want.Interface(), got.Interface())
			}
			return
		}
		if want.Kind() != got.Kind() {
			t.Fatal("focused mapper changed field kind", want.Type(), got.Type())
		}
		switch want.Kind() {
		case reflect.Struct:
			if want.NumField() != got.NumField() {
				t.Fatal("focused mapper changed field inventory", want.Type(), got.Type())
			}
			for i := 0; i < want.NumField(); i++ {
				name := want.Type().Field(i).Name
				field := got.FieldByName(name)
				if !field.IsValid() {
					t.Fatal("focused mapper omitted field", name)
				}
				assertFields(want.Field(i), field)
			}
		case reflect.Slice:
			if want.Len() != got.Len() || want.IsNil() != got.IsNil() {
				t.Fatal("focused mapper changed slice shape")
			}
			for i := 0; i < want.Len(); i++ {
				assertFields(want.Index(i), got.Index(i))
			}
		default:
			t.Fatal("unexpected mapper field types", want.Type(), got.Type())
		}
	}
	assertFields(reflect.ValueOf(tpl), reflect.ValueOf(tx.state.QuestionnaireTemplates[tpl.ID]))
	tpl.Questions[0].Prompt, tpl.Questions[0].AllowedFields[1] = "mutated", "mutated"
	if tx.state.QuestionnaireTemplates[tpl.ID].Questions[0].Prompt != "Reviewed?" || tx.state.QuestionnaireTemplates[tpl.ID].Questions[0].AllowedFields[1] != "title" {
		t.Fatal("template insertion retained mutable input")
	}
	responses := []packagedomain.QuestionnaireResponse{{QuestionID: "q", Answer: "Reviewed", EvidenceIDs: []string{"tenant-evidence"}, Limitations: []string{"review"}}}
	hash, err := packageapp.HashQuestionnaireResponses(responses)
	if err != nil {
		t.Fatal(err)
	}
	pkg := packagedomain.QuestionnairePackage{ID: "new-package", TenantID: "tenant", TemplateID: tpl.ID, PackageID: "tenant-package", ProductID: "tenant-product", ReleaseID: "tenant-release", Responses: responses, ManifestHash: hash, SchemaVersion: packagedomain.QuestionnairePackageVersion, CreatedAt: fixedNow()}
	if err := r.InsertFocusedQuestionnairePackage(t.Context(), pkg); err != nil {
		t.Fatal(err)
	}
	assertFields(reflect.ValueOf(pkg), reflect.ValueOf(tx.state.QuestionnairePackages[pkg.ID]))
	draft := packagedomain.QuestionnaireDraft{ID: "new-draft", TenantID: "tenant", TemplateID: tpl.ID, ProductID: "tenant-product", ReleaseID: "tenant-release", Responses: responses, ManifestHash: hash, Limitations: []string{"human review"}, SchemaVersion: packagedomain.QuestionnaireDraftVersion, CreatedAt: fixedNow()}
	d := tx.Repositories().Future.(interface {
		InsertFocusedQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
	})
	if err := d.InsertFocusedQuestionnaireDraft(t.Context(), draft); err != nil {
		t.Fatal(err)
	}
	assertFields(reflect.ValueOf(draft), reflect.ValueOf(tx.state.QuestionnaireDrafts[draft.ID]))
	responses[0].Answer, responses[0].EvidenceIDs[0], responses[0].Limitations[0], draft.Limitations[0] = "mutated", "mutated", "mutated", "mutated"
	if tx.state.QuestionnairePackages[pkg.ID].Responses[0].Answer != "Reviewed" || tx.state.QuestionnairePackages[pkg.ID].Responses[0].EvidenceIDs[0] != "tenant-evidence" || tx.state.QuestionnaireDrafts[draft.ID].Responses[0].Limitations[0] != "review" || tx.state.QuestionnaireDrafts[draft.ID].Limitations[0] != "human review" {
		t.Fatal("focused inserts retained mutable response or limitation arrays")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedQuestionnairePackage(t.Context(), pkg); !errors.Is(err, ErrValidation) {
		t.Fatal("mutated input hash was not revalidated", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("rejected mutation changed immutable record")
	}
}

type memoryQuestionnaireScopeReader interface {
	ValidateQuestionnaireTemplateScope(context.Context, string, []string) error
	packageapp.QuestionnairePackageReader
}

func TestMemoryFocusedQuestionnaireWritesRejectForgedAssociationAndQuestionOrder(t *testing.T) {
	for _, kind := range []string{"package-association", "draft-order"} {
		t.Run(kind, func(t *testing.T) {
			_, tx := memoryQuestionnaireFixture(t)
			responses := []packagedomain.QuestionnaireResponse{{QuestionID: "q", Answer: "Reviewed", EvidenceIDs: []string{"tenant-evidence"}, Limitations: []string{"review"}}}
			if kind == "draft-order" {
				tpl := tx.state.QuestionnaireTemplates["tenant-template"]
				tpl.Questions = append(tpl.Questions, domain.QuestionnaireQuestion{ID: "q2"})
				tx.state.QuestionnaireTemplates[tpl.ID] = tpl
				responses = append([]packagedomain.QuestionnaireResponse{{QuestionID: "q2", Answer: "Reviewed"}}, responses...)
			} else {
				tx.state.Products["other-product"] = domain.Product{ID: "other-product", TenantID: "tenant"}
				pkg := tx.state.CustomerPackages["tenant-package"]
				pkg.ProductID, pkg.ReleaseID = "other-product", ""
				tx.state.CustomerPackages[pkg.ID] = pkg
			}
			hash, err := packageapp.HashQuestionnaireResponses(responses)
			if err != nil {
				t.Fatal(err)
			}
			before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "package-association" {
				r := tx.Repositories().Enterprise.(interface {
					InsertFocusedQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
				})
				err = r.InsertFocusedQuestionnairePackage(t.Context(), packagedomain.QuestionnairePackage{ID: "forged", TenantID: "tenant", TemplateID: "tenant-template", PackageID: "tenant-package", ProductID: "tenant-product", ReleaseID: "tenant-release", Responses: responses, ManifestHash: hash, SchemaVersion: packagedomain.QuestionnairePackageVersion, CreatedAt: fixedNow()})
				if !errors.Is(err, ErrConflict) {
					t.Fatal("focused insert accepted mismatched package association", err)
				}
			} else {
				r := tx.Repositories().Future.(interface {
					InsertFocusedQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
				})
				err = r.InsertFocusedQuestionnaireDraft(t.Context(), packagedomain.QuestionnaireDraft{ID: "forged", TenantID: "tenant", TemplateID: "tenant-template", ProductID: "tenant-product", ReleaseID: "tenant-release", Responses: responses, ManifestHash: hash, SchemaVersion: packagedomain.QuestionnaireDraftVersion, CreatedAt: fixedNow()})
				if !errors.Is(err, ErrValidation) {
					t.Fatal("focused insert accepted reordered questions", err)
				}
			}
			if !reflect.DeepEqual(before, tx.state) {
				t.Fatal("rejected focused insert changed repository state")
			}
		})
	}
}

func memoryQuestionnaireFixture(t *testing.T) (*MemoryUnitOfWorkFactory, *memoryUnitOfWork) {
	factory, tx := memoryMembershipReadFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.ControlFrameworks[tenant+"-framework"] = domain.ControlFramework{ID: tenant + "-framework", TenantID: tenant, Name: strings.Repeat("x", 65537)}
		tx.state.SecurityControls[tenant+"-control"] = domain.SecurityControl{ID: tenant + "-control", TenantID: tenant, FrameworkID: tenant + "-framework", Objective: strings.Repeat("x", 65537)}
		tx.state.QuestionnaireTemplates[tenant+"-template"] = domain.QuestionnaireTemplate{ID: tenant + "-template", TenantID: tenant, Questions: []domain.QuestionnaireQuestion{{ID: "q", ControlID: tenant + "-control", EvidenceType: "build", Prompt: strings.Repeat("x", 65537)}}}
		tx.state.Evidence[tenant+"-evidence"] = domain.EvidenceItem{ID: tenant + "-evidence", TenantID: tenant, ProductID: tenant + "-product", ReleaseID: tenant + "-release", Type: "build", Title: strings.Repeat("x", 65537), PayloadRef: "private"}
		tx.state.AnswerLibrary[tenant+"-answer"] = domain.QuestionnaireAnswerLibraryEntry{ID: tenant + "-answer", TenantID: tenant, QuestionID: "q", ProductID: tenant + "-product", ReleaseID: tenant + "-release", Answer: "private scoped answer", EvidenceIDs: []string{tenant + "-evidence"}, Limitations: []string{"review"}, CreatedAt: fixedNow()}
	}
	return factory, tx
}

func TestMemoryQuestionnaireScopesUseOnlyCurrentOwnedIdentifiers(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Enterprise.(memoryQuestionnaireScopeReader)
	if !ok {
		t.Fatal("memory enterprise lacks focused template/package scopes")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateQuestionnaireTemplateScope(t.Context(), "tenant", []string{"tenant-control"}); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]string{{"foreign-control"}, {"missing"}} {
		if err := r.ValidateQuestionnaireTemplateScope(t.Context(), "tenant", ids); !errors.Is(err, ErrNotFound) {
			t.Fatal("scope accepted foreign/missing control", ids, err)
		}
	}
	for _, ids := range [][]string{{"tenant-control", "tenant-control"}, {""}, {" tenant-control"}, {strings.Repeat("x", 1025)}, make([]string, 513)} {
		if err := r.ValidateQuestionnaireTemplateScope(t.Context(), "tenant", ids); !errors.Is(err, ErrValidation) {
			t.Fatal("scope accepted invalid identifiers", err)
		}
	}
	for _, in := range []packageapp.CreateQuestionnairePackageInput{{TemplateID: "tenant-template"}, {TemplateID: "tenant-template", ReleaseID: "tenant-release"}, {TemplateID: "tenant-template", PackageID: "tenant-package"}, {TemplateID: "tenant-template", PackageID: "tenant-package", ProductID: "tenant-product", ReleaseID: "tenant-release"}} {
		s, err := r.ReadQuestionnairePackageScope(t.Context(), "tenant", in)
		if err != nil || s.Selection.ProductID != in.ProductID || s.Selection.ReleaseID != in.ReleaseID || s.PackageID != in.PackageID {
			t.Fatal("package scope narrowed raw filters or read private fields", s, err)
		}
		if err := packageapp.ValidateQuestionnairePackageScope("tenant", in, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, in := range []packageapp.CreateQuestionnairePackageInput{{TemplateID: "foreign-template"}, {TemplateID: "tenant-template", PackageID: "foreign-package"}, {TemplateID: "tenant-template", ReleaseID: "foreign-release"}} {
		if _, err := r.ReadQuestionnairePackageScope(t.Context(), "tenant", in); !errors.Is(err, ErrNotFound) {
			t.Fatal("package scope accepted foreign parent", err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("scope reads changed repository state")
	}
	control := tx.state.SecurityControls["tenant-control"]
	control.FrameworkID = "foreign-framework"
	tx.state.SecurityControls[control.ID] = control
	if err := r.ValidateQuestionnaireTemplateScope(t.Context(), "tenant", []string{control.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatal("scope accepted foreign framework", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.ValidateQuestionnaireTemplateScope(ctx, "tenant", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("scope ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateQuestionnaireTemplateScope(t.Context(), "tenant", nil); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction remained usable", err)
	}
}

func TestMemoryQuestionnaireResponsesSeparateSelectorsFromPrivateAnswers(t *testing.T) {
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Future.(packageapp.QuestionnaireDraftReader)
	if !ok {
		t.Fatal("memory future repository lacks focused questionnaire response reads")
	}
	s, err := r.ReadQuestionnaireDraftScope(t.Context(), "tenant", packageapp.CreateQuestionnaireDraftInput{TemplateID: "tenant-template", ProductID: "tenant-product", ReleaseID: "tenant-release"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := r.ReadQuestionnaireDraftQuestions(t.Context(), s)
	if err != nil || !reflect.DeepEqual(questions, []packageapp.DraftQuestion{{ID: "q", ControlID: "tenant-control", EvidenceType: "build"}}) {
		t.Fatal("question selectors read prompts or changed order", questions, err)
	}
	q := questions[0]
	candidates, err := r.ReadQuestionnaireDraftCandidates(t.Context(), s, q, 1)
	if err != nil || len(candidates) != 1 || candidates[0].ID != "tenant-answer" || candidates[0].Resources != (application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}) {
		t.Fatal("candidate read crossed tenant or lost current coordinates", candidates, err)
	}
	answer, err := r.ReadQuestionnaireDraftAnswer(t.Context(), s, candidates[0].ID)
	if err != nil || answer.Answer != "private scoped answer" || !reflect.DeepEqual(answer.EvidenceIDs, []string{"tenant-evidence"}) {
		t.Fatal("answer projection lost fields", answer, err)
	}
	answer.EvidenceIDs[0], answer.Limitations[0] = "mutated", "mutated"
	if _, err := r.ReadQuestionnaireDraftAnswer(t.Context(), s, "foreign-answer"); !errors.Is(err, ErrNotFound) {
		t.Fatal("answer read crossed tenant", err)
	}
	ids, err := r.ReadQuestionnaireDraftEvidence(t.Context(), s, packageapp.DraftQuestion{EvidenceType: "build"}, 1)
	if err != nil || !reflect.DeepEqual(ids, []string{"tenant-evidence"}) {
		t.Fatal("fallback evidence lost owned ID selection", ids, err)
	}
	if err := r.ValidateQuestionnaireDraftEvidence(t.Context(), s, ids); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateQuestionnaireDraftEvidence(t.Context(), s, []string{"foreign-evidence"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("citations crossed tenant", err)
	}
	if _, err := r.ReadQuestionnaireDraftCandidates(t.Context(), s, q, 0); !errors.Is(err, ErrValidation) {
		t.Fatal("candidate budget silently truncated", err)
	}
	if _, err := r.ReadQuestionnaireDraftEvidence(t.Context(), s, packageapp.DraftQuestion{EvidenceType: "build"}, 0); !errors.Is(err, ErrValidation) {
		t.Fatal("evidence budget silently truncated", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("reads or returned slice mutation changed storage")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadQuestionnaireDraftQuestions(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatal("question read ignored cancellation", err)
	}
}

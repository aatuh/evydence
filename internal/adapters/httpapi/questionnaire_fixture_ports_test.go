package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Template/package operations use focused services on transaction repositories;
// answer-library operations still retain isolated historical writes. These
// test-only bridges are not runtime ports or evidence of SQL limits/locking.
type questionnaireFixtureCommands struct{ catalogFixtureCommands }
type answerLibraryFixtureQuery struct{ catalogFixtureCommands }

func questionnaireQuestionsFromCommand(qs []packagedomain.QuestionnaireQuestion) []domain.QuestionnaireQuestion {
	out := make([]domain.QuestionnaireQuestion, len(qs))
	for i, q := range qs {
		out[i] = domain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: slices.Clone(q.AllowedFields)}
	}
	return out
}
func answerLibraryLegacyInput(in packageapp.CreateAnswerLibraryEntryInput) app.CreateQuestionnaireAnswerLibraryEntryInput {
	return app.CreateQuestionnaireAnswerLibraryEntryInput{QuestionID: in.QuestionID, EvidenceType: in.EvidenceType, ControlID: in.ControlID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Answer: in.Answer, EvidenceIDs: slices.Clone(in.EvidenceIDs), Limitations: slices.Clone(in.Limitations)}
}
func questionnaireTemplateFixtureModel(v domain.QuestionnaireTemplate) packagedomain.QuestionnaireTemplate {
	qs := make([]packagedomain.QuestionnaireQuestion, len(v.Questions))
	for i, q := range v.Questions {
		qs[i] = packagedomain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: slices.Clone(q.AllowedFields)}
	}
	return packagedomain.QuestionnaireTemplate{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Version: v.Version, Questions: qs, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func questionnairePackageFixtureModel(v domain.QuestionnairePackage) packagedomain.QuestionnairePackage {
	responses := make([]packagedomain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = packagedomain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: slices.Clone(r.EvidenceIDs), Limitations: slices.Clone(r.Limitations)}
	}
	return packagedomain.QuestionnairePackage{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: responses, ManifestHash: v.ManifestHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func answerLibraryFixtureModel(v domain.QuestionnaireAnswerLibraryEntry) packagedomain.QuestionnaireAnswerLibraryEntry {
	return packagedomain.QuestionnaireAnswerLibraryEntry{ID: v.ID, TenantID: v.TenantID, QuestionID: v.QuestionID, EvidenceType: v.EvidenceType, ControlID: v.ControlID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Answer: v.Answer, EvidenceIDs: slices.Clone(v.EvidenceIDs), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (f questionnaireFixtureCommands) AuthorizeCreateQuestionnaireTemplate(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireTemplateInput) error {
	c, err := f.nativeTemplate(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateQuestionnaireTemplate(ctx, a, in)
}
func (f questionnaireFixtureCommands) CreateQuestionnaireTemplate(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireTemplateInput) (packagedomain.QuestionnaireTemplate, error) {
	c, err := f.nativeTemplate(false)
	if err != nil {
		return packagedomain.QuestionnaireTemplate{}, err
	}
	return c.CreateQuestionnaireTemplate(ctx, a, in)
}
func (f questionnaireFixtureCommands) AuthorizeCreateQuestionnairePackage(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnairePackageInput) error {
	c, err := f.nativePackage(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateQuestionnairePackage(ctx, a, in)
}
func (f questionnaireFixtureCommands) CreateQuestionnairePackage(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnairePackageInput) (packagedomain.QuestionnairePackage, error) {
	c, err := f.nativePackage(false)
	if err != nil {
		return packagedomain.QuestionnairePackage{}, err
	}
	return c.CreateQuestionnairePackage(ctx, a, in)
}
func (f questionnaireFixtureCommands) AuthorizeCreateAnswerLibraryEntry(ctx context.Context, a domain.Actor, in packageapp.CreateAnswerLibraryEntryInput) error {
	return f.commandLedger(ctx).AuthorizeQuestionnaireAnswerLibraryCreate(ctx, a, answerLibraryLegacyInput(in))
}
func (f questionnaireFixtureCommands) CreateAnswerLibraryEntry(ctx context.Context, a domain.Actor, in packageapp.CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error) {
	v, err := f.commandLedger(ctx).CreateQuestionnaireAnswerLibraryEntry(ctx, a, answerLibraryLegacyInput(in))
	return answerLibraryFixtureModel(v), err
}
func (f answerLibraryFixtureQuery) ListPage(ctx context.Context, a domain.Actor, filter packagequery.AnswerLibraryFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	values, err := f.commandLedger(ctx).ListQuestionnaireAnswerLibrary(ctx, a, app.ListQuestionnaireAnswerLibraryInput{QuestionID: filter.QuestionID, ProductID: filter.ProductID, ReleaseID: filter.ReleaseID})
	if err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	items := make([]packagedomain.QuestionnaireAnswerLibraryEntry, 0, len(values))
	for _, v := range values {
		items = append(items, answerLibraryFixtureModel(v))
	}
	return appquery.Page(items, request, after, func(v packagedomain.QuestionnaireAnswerLibraryEntry, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(v.ID, v.CreatedAt, sort)
	})
}
func (s *Server) bindQuestionnaireFixturePorts(ledger *app.Ledger) {
	f := questionnaireFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.questionnaireTemplateCommands.(questionnaireFixtureCommands); s.questionnaireTemplateCommands == nil || fixture {
		s.questionnaireTemplateCommands = f
	}
	if _, fixture := s.questionnairePackageCommands.(questionnaireFixtureCommands); s.questionnairePackageCommands == nil || fixture {
		s.questionnairePackageCommands = f
	}
	if _, fixture := s.answerLibraryCommands.(questionnaireFixtureCommands); s.answerLibraryCommands == nil || fixture {
		s.answerLibraryCommands = f
	}
	if _, fixture := s.answerLibraryQuery.(answerLibraryFixtureQuery); s.answerLibraryQuery == nil || fixture {
		s.answerLibraryQuery = answerLibraryFixtureQuery(f)
	}
}

var (
	_ QuestionnaireTemplateCommands = questionnaireFixtureCommands{}
	_ QuestionnairePackageCommands  = questionnaireFixtureCommands{}
	_ AnswerLibraryCommands         = questionnaireFixtureCommands{}
	_ AnswerLibraryQuery            = answerLibraryFixtureQuery{}
)

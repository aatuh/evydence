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

// Questionnaire and answer-library operations use focused services and
// transaction repositories. These test-only bridges are not runtime ports or
// evidence of SQL limits/locking.
type questionnaireFixtureCommands struct{ catalogFixtureCommands }
type answerLibraryFixtureQuery struct{ catalogFixtureCommands }

func questionnaireQuestionsFromCommand(qs []packagedomain.QuestionnaireQuestion) []domain.QuestionnaireQuestion {
	out := make([]domain.QuestionnaireQuestion, len(qs))
	for i, q := range qs {
		out[i] = domain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: slices.Clone(q.AllowedFields)}
	}
	return out
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
	c, err := f.nativeAnswerLibrary(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreateAnswerLibraryEntry(ctx, a, in)
}
func (f questionnaireFixtureCommands) CreateAnswerLibraryEntry(ctx context.Context, a domain.Actor, in packageapp.CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error) {
	c, err := f.nativeAnswerLibrary(false)
	if err != nil {
		return packagedomain.QuestionnaireAnswerLibraryEntry{}, err
	}
	return c.CreateAnswerLibraryEntry(ctx, a, in)
}
func (f answerLibraryFixtureQuery) ListPage(ctx context.Context, a domain.Actor, filter packagequery.AnswerLibraryFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry], error) {
	c, err := packagequery.NewAnswerLibrary(f)
	if err != nil {
		return appquery.Result[packagedomain.QuestionnaireAnswerLibraryEntry]{}, err
	}
	return c.ListPage(ctx, a, filter, request, after)
}
func (f answerLibraryFixtureQuery) PageAnswerLibrary(ctx context.Context, request packagequery.AnswerLibraryPageRequest) (appquery.Result[packagequery.AnswerLibraryPoint], error) {
	var out appquery.Result[packagequery.AnswerLibraryPoint]
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Enterprise.(packagequery.AnswerLibraryReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.PageAnswerLibrary(ctx, request)
		return err
	})
	return out, err
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

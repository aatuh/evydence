package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Test-only real-policy preflight over focused memory coordinates, followed by
// isolated historical writes. No runtime backend or SQL guarantee is implied.
type summaryDraftFixtureCommands struct{ catalogFixtureCommands }
type reportFixtureScopeReader interface {
	ReadEvidenceSummaryScope(context.Context, string, string, string) (packageapp.EvidenceSummaryScope, error)
	ReadQuestionnaireDraftScope(context.Context, string, packageapp.CreateQuestionnaireDraftInput) (packageapp.QuestionnaireDraftScope, error)
}
type reportFixtureGuardTransaction struct {
	reportFixtureScopeReader
	application.Authorizer
}

func (t reportFixtureGuardTransaction) ReadEvidenceSummaryScope(ctx context.Context, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	v, err := t.reportFixtureScopeReader.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return v, portalFixtureError(err)
}
func (t reportFixtureGuardTransaction) ReadQuestionnaireDraftScope(ctx context.Context, tenant string, in packageapp.CreateQuestionnaireDraftInput) (packageapp.QuestionnaireDraftScope, error) {
	v, err := t.reportFixtureScopeReader.ReadQuestionnaireDraftScope(ctx, tenant, in)
	return v, portalFixtureError(err)
}
func (reportFixtureGuardTransaction) ReadEvidenceSummaryItems(context.Context, packageapp.EvidenceSummaryScope, []string) ([]packageapp.EvidenceSummaryItem, error) {
	panic("summary preflight read citations")
}
func (reportFixtureGuardTransaction) InsertEvidenceSummary(context.Context, packagedomain.EvidenceSummary) error {
	panic("summary preflight wrote a report")
}
func (reportFixtureGuardTransaction) ReadQuestionnaireDraftQuestions(context.Context, packageapp.QuestionnaireDraftScope) ([]packageapp.DraftQuestion, error) {
	panic("draft preflight read question selectors")
}
func (reportFixtureGuardTransaction) ReadQuestionnaireDraftCandidates(context.Context, packageapp.QuestionnaireDraftScope, packageapp.DraftQuestion, int) ([]packageapp.DraftAnswerCandidate, error) {
	panic("draft preflight read answer candidates")
}
func (reportFixtureGuardTransaction) ReadQuestionnaireDraftAnswer(context.Context, packageapp.QuestionnaireDraftScope, string) (packageapp.DraftAnswer, error) {
	panic("draft preflight read private answers")
}
func (reportFixtureGuardTransaction) ReadQuestionnaireDraftEvidence(context.Context, packageapp.QuestionnaireDraftScope, packageapp.DraftQuestion, int) ([]string, error) {
	panic("draft preflight read evidence")
}
func (reportFixtureGuardTransaction) ValidateQuestionnaireDraftEvidence(context.Context, packageapp.QuestionnaireDraftScope, []string) error {
	panic("draft preflight validated citations")
}
func (reportFixtureGuardTransaction) InsertQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error {
	panic("draft preflight wrote a report")
}
func (reportFixtureGuardTransaction) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("report preflight wrote an audit")
}
func (f summaryDraftFixtureCommands) guard(ctx context.Context, a application.Authorizer, fn func(context.Context, reportFixtureGuardTransaction) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Future.(reportFixtureScopeReader)
		if !ok {
			return app.ErrValidation
		}
		return fn(ctx, reportFixtureGuardTransaction{r, a})
	})
}
func (f summaryDraftFixtureCommands) ExecuteEvidenceSummary(ctx context.Context, _ string, fn func(context.Context, packageapp.EvidenceSummaryTransaction) error) error {
	return f.guard(ctx, packagequery.NewEvidenceSummaryAuthorizer(), func(ctx context.Context, tx reportFixtureGuardTransaction) error { return fn(ctx, tx) })
}
func (f summaryDraftFixtureCommands) ExecuteQuestionnaireDraft(ctx context.Context, _ string, fn func(context.Context, packageapp.QuestionnaireDraftTransaction) error) error {
	return f.guard(ctx, packagequery.NewQuestionnaireDraftAuthorizer(), func(ctx context.Context, tx reportFixtureGuardTransaction) error { return fn(ctx, tx) })
}
func (f summaryDraftFixtureCommands) AuthorizeCreateEvidenceSummary(ctx context.Context, a domain.Actor, in packageapp.CreateEvidenceSummaryInput) error {
	g, err := packageapp.NewEvidenceSummaryCommands(packageapp.EvidenceSummaryCommandConfig{Transactions: f, Authorizer: packagequery.NewEvidenceSummaryAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
	if err != nil {
		return err
	}
	return g.AuthorizeCreateEvidenceSummary(ctx, a, in)
}
func (f summaryDraftFixtureCommands) AuthorizeCreateQuestionnaireDraft(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireDraftInput) error {
	g, err := packageapp.NewQuestionnaireDraftCommands(packageapp.QuestionnaireDraftCommandConfig{Transactions: f, Authorizer: packagequery.NewQuestionnaireDraftAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
	if err != nil {
		return err
	}
	return g.AuthorizeCreateQuestionnaireDraft(ctx, a, in)
}
func summaryFixtureModel(v domain.EvidenceSummary) packagedomain.EvidenceSummary {
	citations := make([]packagedomain.EvidenceCitation, len(v.Citations))
	for i, c := range v.Citations {
		citations[i] = packagedomain.EvidenceCitation{EvidenceID: c.EvidenceID, Type: c.Type, Title: c.Title, CanonicalHash: c.CanonicalHash}
	}
	return packagedomain.EvidenceSummary{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, EvidenceIDs: slices.Clone(v.EvidenceIDs), Summary: v.Summary, Citations: citations, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func draftFixtureModel(v domain.QuestionnaireDraft) packagedomain.QuestionnaireDraft {
	responses := make([]packagedomain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = packagedomain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: slices.Clone(r.EvidenceIDs), Limitations: slices.Clone(r.Limitations)}
	}
	return packagedomain.QuestionnaireDraft{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: responses, ManifestHash: v.ManifestHash, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (f summaryDraftFixtureCommands) CreateEvidenceSummary(ctx context.Context, a domain.Actor, in packageapp.CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error) {
	v, err := f.commandLedger(ctx).CreateEvidenceSummary(ctx, a, app.CreateEvidenceSummaryInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID, EvidenceIDs: slices.Clone(in.EvidenceIDs)})
	return summaryFixtureModel(v), err
}
func (f summaryDraftFixtureCommands) CreateQuestionnaireDraft(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error) {
	v, err := f.commandLedger(ctx).CreateQuestionnaireDraft(ctx, a, app.CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	return draftFixtureModel(v), err
}
func (s *Server) bindSummaryDraftFixturePorts(ledger *app.Ledger) {
	f := summaryDraftFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.evidenceSummaryCommands.(summaryDraftFixtureCommands); s.evidenceSummaryCommands == nil || fixture {
		s.evidenceSummaryCommands = f
	}
	if _, fixture := s.questionnaireDraftCommands.(summaryDraftFixtureCommands); s.questionnaireDraftCommands == nil || fixture {
		s.questionnaireDraftCommands = f
	}
}

var (
	_ EvidenceSummaryCommands    = summaryDraftFixtureCommands{}
	_ QuestionnaireDraftCommands = summaryDraftFixtureCommands{}
)

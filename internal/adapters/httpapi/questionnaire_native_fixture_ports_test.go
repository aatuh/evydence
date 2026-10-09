package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

type questionnaireNativeRepository interface {
	ValidateQuestionnaireTemplateScope(context.Context, string, []string) error
	InsertFocusedQuestionnaireTemplate(context.Context, packagedomain.QuestionnaireTemplate) error
	packageapp.QuestionnairePackageReader
	InsertFocusedQuestionnairePackage(context.Context, packagedomain.QuestionnairePackage) error
	packageapp.AnswerLibraryReader
	InsertFocusedAnswerLibraryEntry(context.Context, packagedomain.QuestionnaireAnswerLibraryEntry) error
}
type questionnaireNativeDraftRepository interface {
	packageapp.QuestionnaireDraftReader
	InsertFocusedQuestionnaireDraft(context.Context, packagedomain.QuestionnaireDraft) error
	packageapp.EvidenceSummaryReader
	InsertFocusedEvidenceSummary(context.Context, packagedomain.EvidenceSummary) error
}
type questionnaireNativeFixtureTransactions struct {
	catalogFixtureCommands
	readOnly   bool
	authorizer application.Authorizer
}
type questionnaireNativeFixtureTransaction struct {
	questionnaireNativeRepository
	questionnaireNativeDraftRepository
	repos      app.Repositories
	readOnly   bool
	authorizer application.Authorizer
}

func (f questionnaireNativeFixtureTransactions) execute(ctx context.Context, tenant string, fn func(context.Context, questionnaireNativeFixtureTransaction) error) error {
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Enterprise.(questionnaireNativeRepository)
		d, canRead := repos.Future.(questionnaireNativeDraftRepository)
		fence, canFence := repos.Identity.(interface {
			LockAPIKeyCreation(context.Context, string) error
		})
		if !ok || !canRead || !canFence || repos.Audit == nil {
			return app.ErrValidation
		}
		if err := fence.LockAPIKeyCreation(ctx, tenant); err != nil {
			return err
		}
		return fn(ctx, questionnaireNativeFixtureTransaction{r, d, repos, f.readOnly, f.authorizer})
	}))
}
func (f questionnaireNativeFixtureTransactions) ExecuteQuestionnaireTemplate(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnaireTemplateTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx questionnaireNativeFixtureTransaction) error { return fn(ctx, tx) })
}
func (f questionnaireNativeFixtureTransactions) ExecuteQuestionnairePackage(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnairePackageTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx questionnaireNativeFixtureTransaction) error { return fn(ctx, tx) })
}
func (f questionnaireNativeFixtureTransactions) ExecuteQuestionnaireDraft(ctx context.Context, tenant string, fn func(context.Context, packageapp.QuestionnaireDraftTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx questionnaireNativeFixtureTransaction) error { return fn(ctx, tx) })
}
func (f questionnaireNativeFixtureTransactions) ExecuteAnswerLibrary(ctx context.Context, tenant string, fn func(context.Context, packageapp.AnswerLibraryTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx questionnaireNativeFixtureTransaction) error { return fn(ctx, tx) })
}
func (f questionnaireNativeFixtureTransactions) ExecuteEvidenceSummary(ctx context.Context, tenant string, fn func(context.Context, packageapp.EvidenceSummaryTransaction) error) error {
	return f.execute(ctx, tenant, func(ctx context.Context, tx questionnaireNativeFixtureTransaction) error { return fn(ctx, tx) })
}
func (tx questionnaireNativeFixtureTransaction) ReadEvidenceSummaryScope(ctx context.Context, tenant, kind, id string) (packageapp.EvidenceSummaryScope, error) {
	v, err := tx.questionnaireNativeDraftRepository.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return v, portalFixtureError(err)
}
func (tx questionnaireNativeFixtureTransaction) ReadEvidenceSummaryItems(ctx context.Context, s packageapp.EvidenceSummaryScope, ids []string) ([]packageapp.EvidenceSummaryItem, error) {
	if tx.readOnly {
		panic("summary preflight read citation metadata")
	}
	v, err := tx.questionnaireNativeDraftRepository.ReadEvidenceSummaryItems(ctx, s, ids)
	return v, portalFixtureError(err)
}
func (tx questionnaireNativeFixtureTransaction) InsertEvidenceSummary(ctx context.Context, v packagedomain.EvidenceSummary) error {
	if tx.readOnly {
		panic("summary preflight wrote a report")
	}
	return portalFixtureError(tx.InsertFocusedEvidenceSummary(ctx, v))
}
func (tx questionnaireNativeFixtureTransaction) ReadAnswerLibraryScope(ctx context.Context, tenant, product, release string) (packageapp.AnswerLibraryScope, error) {
	v, err := tx.questionnaireNativeRepository.ReadAnswerLibraryScope(ctx, tenant, product, release)
	return v, portalFixtureError(err)
}
func (tx questionnaireNativeFixtureTransaction) ValidateAnswerLibraryReferences(ctx context.Context, s packageapp.AnswerLibraryScope, control string, ids []string) error {
	return portalFixtureError(tx.questionnaireNativeRepository.ValidateAnswerLibraryReferences(ctx, s, control, ids))
}
func (tx questionnaireNativeFixtureTransaction) InsertAnswerLibraryEntry(ctx context.Context, v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	if tx.readOnly {
		panic("answer-library preflight wrote an answer")
	}
	return portalFixtureError(tx.InsertFocusedAnswerLibraryEntry(ctx, v))
}
func (tx questionnaireNativeFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return tx.authorizer.Authorize(ctx, a, r)
}
func (tx questionnaireNativeFixtureTransaction) InsertQuestionnaireTemplate(ctx context.Context, v packagedomain.QuestionnaireTemplate) error {
	if tx.readOnly {
		panic("questionnaire preflight inserted a template")
	}
	return portalFixtureError(tx.InsertFocusedQuestionnaireTemplate(ctx, v))
}
func (tx questionnaireNativeFixtureTransaction) InsertQuestionnairePackage(ctx context.Context, v packagedomain.QuestionnairePackage) error {
	if tx.readOnly {
		panic("questionnaire preflight inserted a package")
	}
	return portalFixtureError(tx.InsertFocusedQuestionnairePackage(ctx, v))
}
func (tx questionnaireNativeFixtureTransaction) InsertQuestionnaireDraft(ctx context.Context, v packagedomain.QuestionnaireDraft) error {
	if tx.readOnly {
		panic("questionnaire preflight inserted a draft")
	}
	return portalFixtureError(tx.InsertFocusedQuestionnaireDraft(ctx, v))
}
func (tx questionnaireNativeFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("questionnaire preflight appended an audit")
	}
	return (portalFixtureTransaction{repos: tx.repos}).AppendAudit(ctx, e)
}
func (tx questionnaireNativeFixtureTransaction) ReadQuestionnaireDraftQuestions(ctx context.Context, s packageapp.QuestionnaireDraftScope) ([]packageapp.DraftQuestion, error) {
	if tx.readOnly {
		panic("questionnaire preflight read private selectors")
	}
	return tx.questionnaireNativeDraftRepository.ReadQuestionnaireDraftQuestions(ctx, s)
}
func (tx questionnaireNativeFixtureTransaction) ReadQuestionnaireDraftCandidates(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, n int) ([]packageapp.DraftAnswerCandidate, error) {
	if tx.readOnly {
		panic("questionnaire preflight read answer candidates")
	}
	return tx.questionnaireNativeDraftRepository.ReadQuestionnaireDraftCandidates(ctx, s, q, n)
}
func (tx questionnaireNativeFixtureTransaction) ReadQuestionnaireDraftAnswer(ctx context.Context, s packageapp.QuestionnaireDraftScope, id string) (packageapp.DraftAnswer, error) {
	if tx.readOnly {
		panic("questionnaire preflight read private answers")
	}
	return tx.questionnaireNativeDraftRepository.ReadQuestionnaireDraftAnswer(ctx, s, id)
}
func (tx questionnaireNativeFixtureTransaction) ReadQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, n int) ([]string, error) {
	if tx.readOnly {
		panic("questionnaire preflight read citations")
	}
	return tx.questionnaireNativeDraftRepository.ReadQuestionnaireDraftEvidence(ctx, s, q, n)
}
func (tx questionnaireNativeFixtureTransaction) ValidateQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, ids []string) error {
	if tx.readOnly {
		panic("questionnaire preflight validated citations")
	}
	return tx.questionnaireNativeDraftRepository.ValidateQuestionnaireDraftEvidence(ctx, s, ids)
}
func questionnaireNativeFixtureClockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	if readOnly {
		return application.ClockFunc(membershipFixtureClock), application.IDGeneratorFunc(membershipFixtureID)
	}
	return application.ClockFunc(time.Now), application.IDGeneratorFunc(application.NewID)
}
func (f questionnaireFixtureCommands) nativeTemplate(readOnly bool) (*packageapp.QuestionnaireTemplateCommands, error) {
	a := packagequery.NewQuestionnaireTemplateAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewQuestionnaireTemplateCommands(packageapp.QuestionnaireTemplateCommandConfig{Transactions: questionnaireNativeFixtureTransactions{f.catalogFixtureCommands, readOnly, a}, Authorizer: a, Clock: clock, IDs: ids})
}
func (f questionnaireFixtureCommands) nativePackage(readOnly bool) (*packageapp.QuestionnairePackageCommands, error) {
	a := packagequery.NewQuestionnairePackageAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewQuestionnairePackageCommands(packageapp.QuestionnairePackageCommandConfig{Transactions: questionnaireNativeFixtureTransactions{f.catalogFixtureCommands, readOnly, a}, Authorizer: a, Clock: clock, IDs: ids})
}
func (f summaryDraftFixtureCommands) nativeDraft(readOnly bool) (*packageapp.QuestionnaireDraftCommands, error) {
	a := packagequery.NewQuestionnaireDraftAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewQuestionnaireDraftCommands(packageapp.QuestionnaireDraftCommandConfig{Transactions: questionnaireNativeFixtureTransactions{f.catalogFixtureCommands, readOnly, a}, Authorizer: a, Clock: clock, IDs: ids})
}
func (f questionnaireFixtureCommands) nativeAnswerLibrary(readOnly bool) (*packageapp.AnswerLibraryCommands, error) {
	a := packagequery.NewAnswerLibraryAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewAnswerLibraryCommands(packageapp.AnswerLibraryCommandConfig{Transactions: questionnaireNativeFixtureTransactions{f.catalogFixtureCommands, readOnly, a}, Authorizer: a, Clock: clock, IDs: ids})
}
func (f summaryDraftFixtureCommands) nativeSummary(readOnly bool) (*packageapp.EvidenceSummaryCommands, error) {
	a := packagequery.NewEvidenceSummaryAuthorizer()
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	return packageapp.NewEvidenceSummaryCommands(packageapp.EvidenceSummaryCommandConfig{Transactions: questionnaireNativeFixtureTransactions{f.catalogFixtureCommands, readOnly, a}, Authorizer: a, Clock: clock, IDs: ids})
}

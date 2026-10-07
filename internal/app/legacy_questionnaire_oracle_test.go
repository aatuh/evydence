package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Historical generators retained unchanged for package-local regression tests.
// Production and HTTP fixtures use focused commands and repository projections;
// these methods do not provide a runtime backend or native SQL behavior proof.

func (l *Ledger) evidenceIDsForRefsLocked(tenantID string, refs resourceRefs, evidenceType string) []string {
	ids, _ := l.evidenceIDsForRefsBoundedLocked(tenantID, refs, evidenceType, len(l.evidence)+1)
	return ids
}

type CreateQuestionnaireTemplateInput struct {
	Name      string
	Version   string
	Questions []domain.QuestionnaireQuestion
}

type CreateQuestionnairePackageInput struct {
	TemplateID string
	PackageID  string
	ProductID  string
	ReleaseID  string
}

func (l *Ledger) CreateQuestionnaireTemplate(ctx context.Context, actor domain.Actor, in CreateQuestionnaireTemplateInput) (domain.QuestionnaireTemplate, error) {
	if err := ctx.Err(); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	if err := fromIdentityContextError(application.AuthorizeTenantWideScope(ctx, actor, ScopePackageWrite)); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	if len(in.Questions) > packageapp.MaxQuestionnaireTemplateQuestions {
		return domain.QuestionnaireTemplate{}, ErrValidation
	}
	ownedQuestions := make([]packagedomain.QuestionnaireQuestion, len(in.Questions))
	for i, q := range in.Questions {
		ownedQuestions[i] = packagedomain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: q.AllowedFields}
	}
	normalized, err := packageapp.NormalizeQuestionnaireTemplateInput(packageapp.CreateQuestionnaireTemplateInput{Name: in.Name, Version: in.Version, Questions: ownedQuestions})
	if err != nil {
		return domain.QuestionnaireTemplate{}, ErrValidation
	}
	questions := make([]domain.QuestionnaireQuestion, len(normalized.Questions))
	for i, q := range normalized.Questions {
		questions[i] = domain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: q.AllowedFields}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateQuestionnaireTemplateControlsLocked(actor.TenantID, packageapp.QuestionnaireTemplateControlIDs(normalized.Questions)); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	tpl := domain.QuestionnaireTemplate{ID: newID("qt"), TenantID: actor.TenantID, Name: normalized.Name, Version: normalized.Version, Questions: questions, SchemaVersion: domain.QuestionnaireTemplateVersion, CreatedAt: l.now()}
	if err := packageapp.ValidateQuestionnaireTemplateRecord(packagedomain.QuestionnaireTemplate{ID: tpl.ID, TenantID: tpl.TenantID, Name: tpl.Name, Version: tpl.Version, Questions: normalized.Questions, SchemaVersion: tpl.SchemaVersion, CreatedAt: tpl.CreatedAt}); err != nil {
		return domain.QuestionnaireTemplate{}, ErrValidation
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Enterprise.InsertQuestionnaireTemplate(ctx, tpl); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(tpl.CreatedAt, actor.TenantID, "questionnaire_template.created", "questionnaire_template", tpl.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.QuestionnaireTemplate{}, err
		}
		l.questionTemplates[tpl.ID] = tpl
		l.publishCommittedAuditEntryLocked(entry)
		return cloneQuestionnaireTemplateDTO(tpl), nil
	}
	l.questionTemplates[tpl.ID] = tpl
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_template.created", "questionnaire_template", tpl.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireTemplate{}, err
	}
	return cloneQuestionnaireTemplateDTO(tpl), nil
}

// Local-memory replay checks use only ownership IDs. Production template
// creation/replay binds the focused Package port and never calls this facade.
func (l *Ledger) AuthorizeQuestionnaireTemplateCreate(ctx context.Context, actor domain.Actor, controlIDs []string) error {
	if l == nil {
		return ErrValidation
	}
	if err := fromIdentityContextError(application.AuthorizeTenantWideScope(ctx, actor, ScopePackageWrite)); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validateQuestionnaireTemplateControlsLocked(actor.TenantID, controlIDs)
}

func cloneQuestionnaireTemplateDTO(v domain.QuestionnaireTemplate) domain.QuestionnaireTemplate {
	v.Questions = append([]domain.QuestionnaireQuestion(nil), v.Questions...)
	for i := range v.Questions {
		v.Questions[i].AllowedFields = append([]string(nil), v.Questions[i].AllowedFields...)
	}
	return v
}

func (l *Ledger) CreateQuestionnairePackage(ctx context.Context, actor domain.Actor, in CreateQuestionnairePackageInput) (domain.QuestionnairePackage, error) {
	normalized, err := prepareLocalQuestionnairePackage(ctx, actor, in)
	if err != nil {
		return domain.QuestionnairePackage{}, err
	}
	in = CreateQuestionnairePackageInput{TemplateID: normalized.TemplateID, PackageID: normalized.PackageID, ProductID: normalized.ProductID, ReleaseID: normalized.ReleaseID}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeQuestionnairePackageCreateLocked(ctx, actor, normalized); err != nil {
		return domain.QuestionnairePackage{}, err
	}
	tpl := l.questionTemplates[in.TemplateID]
	if len(tpl.Questions) == 0 || len(tpl.Questions) > packageapp.MaxQuestionnaireDraftQuestions {
		return domain.QuestionnairePackage{}, ErrValidation
	}
	responses := []domain.QuestionnaireResponse{}
	for _, question := range tpl.Questions {
		response, err := l.questionnaireResponseForQuestionLocked(actor, ScopePackageWrite, question, in.ProductID, in.ReleaseID)
		if err != nil {
			return domain.QuestionnairePackage{}, err
		}
		responses = append(responses, response)
	}
	hash, err := packageapp.HashQuestionnaireResponses(questionnairePackageToContext(domain.QuestionnairePackage{Responses: responses}).Responses)
	if err != nil {
		return domain.QuestionnairePackage{}, fromPackageContextError(err)
	}
	pkg := domain.QuestionnairePackage{ID: newID("qp"), TenantID: actor.TenantID, TemplateID: tpl.ID, PackageID: in.PackageID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Responses: responses, ManifestHash: hash, SchemaVersion: domain.QuestionnairePackageVersion, CreatedAt: l.now()}
	if err := packageapp.ValidateQuestionnairePackageRecord(questionnairePackageToContext(pkg)); err != nil {
		return domain.QuestionnairePackage{}, fromPackageContextError(err)
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Enterprise.InsertQuestionnairePackage(ctx, pkg); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(pkg.CreatedAt, actor.TenantID, "questionnaire_package.generated", "questionnaire_package", pkg.ID, actorType(actor), actorID(actor), hash, ""))
			return err
		}); err != nil {
			return domain.QuestionnairePackage{}, err
		}
		l.questionPackages[pkg.ID] = cloneQuestionnairePackageDTO(pkg)
		l.publishCommittedAuditEntryLocked(entry)
		return cloneQuestionnairePackageDTO(pkg), nil
	}
	l.questionPackages[pkg.ID] = cloneQuestionnairePackageDTO(pkg)
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_package.generated", "questionnaire_package", pkg.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnairePackage{}, err
	}
	return cloneQuestionnairePackageDTO(pkg), nil
}

type CreateQuestionnaireDraftInput struct {
	TemplateID string
	ProductID  string
	ReleaseID  string
}

func (l *Ledger) CreateQuestionnaireDraft(ctx context.Context, actor domain.Actor, in CreateQuestionnaireDraftInput) (domain.QuestionnaireDraft, error) {
	if err := ctx.Err(); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	normalized, err := packageapp.NormalizeQuestionnaireDraftInput(packageapp.CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return domain.QuestionnaireDraft{}, ErrValidation
	}
	in = CreateQuestionnaireDraftInput{TemplateID: normalized.TemplateID, ProductID: normalized.ProductID, ReleaseID: normalized.ReleaseID}
	l.mu.Lock()
	defer l.mu.Unlock()
	template, ok := l.questionTemplates[strings.TrimSpace(in.TemplateID)]
	if !ok || template.TenantID != actor.TenantID {
		return domain.QuestionnaireDraft{}, ErrNotFound
	}
	if err := l.ensureScopeLocked(actor.TenantID, strings.TrimSpace(in.ProductID), "", strings.TrimSpace(in.ReleaseID)); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopePackageRead, resourceRefs{ProductID: strings.TrimSpace(in.ProductID), ReleaseID: strings.TrimSpace(in.ReleaseID)}); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	responses := make([]domain.QuestionnaireResponse, 0, len(template.Questions))
	for _, question := range template.Questions {
		response, err := l.questionnaireResponseForQuestionLocked(actor, ScopePackageRead, question, in.ProductID, in.ReleaseID)
		if err != nil {
			return domain.QuestionnaireDraft{}, err
		}
		responses = append(responses, response)
	}
	hash, err := canonicalAnyHash(responses)
	if err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	draft := domain.QuestionnaireDraft{
		ID:            newID("qdr"),
		TenantID:      actor.TenantID,
		TemplateID:    template.ID,
		ProductID:     strings.TrimSpace(in.ProductID),
		ReleaseID:     strings.TrimSpace(in.ReleaseID),
		Responses:     responses,
		ManifestHash:  hash,
		Limitations:   []string{"Generated answers are drafts based on stored evidence and do not provide compliance conclusions."},
		SchemaVersion: domain.QuestionnaireDraftVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertQuestionnaireDraft(ctx, draft); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(draft.CreatedAt, actor.TenantID, "questionnaire_draft.created", "questionnaire_draft", draft.ID, actorType(actor), actorID(actor), hash, ""))
			return err
		}); err != nil {
			return domain.QuestionnaireDraft{}, err
		}
		l.questionDrafts[draft.ID] = draft
		l.publishCommittedAuditEntryLocked(entry)
		return draft, nil
	}
	l.questionDrafts[draft.ID] = draft
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_draft.created", "questionnaire_draft", draft.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	return draft, nil
}

func (l *Ledger) evidenceIDsForQuestionLocked(tenantID string, question domain.QuestionnaireQuestion, productID, releaseID string) []string {
	if question.ControlID != "" {
		ids := []string{}
		for _, link := range l.controlLinks {
			if link.TenantID == tenantID && link.ControlID == question.ControlID && scopeMatches(link.ProductID, productID) && scopeMatches(link.ReleaseID, releaseID) {
				if link.SubjectType == "evidence" {
					ids = append(ids, link.SubjectID)
				}
			}
		}
		return sortedStrings(ids)
	}
	return l.evidenceIDsForRefsLocked(tenantID, resourceRefs{ProductID: strings.TrimSpace(productID), ReleaseID: strings.TrimSpace(releaseID)}, strings.TrimSpace(question.EvidenceType))
}

func (l *Ledger) questionnaireResponseForQuestionLocked(actor domain.Actor, scope string, question domain.QuestionnaireQuestion, productID, releaseID string) (domain.QuestionnaireResponse, error) {
	var response domain.QuestionnaireResponse
	if entry, ok := l.questionnaireAnswerLibraryMatchLocked(actor, scope, question, productID, releaseID); ok {
		response = domain.QuestionnaireResponse{
			QuestionID:  question.ID,
			Answer:      entry.Answer,
			EvidenceIDs: append([]string(nil), entry.EvidenceIDs...),
			Limitations: append([]string(nil), entry.Limitations...),
		}
	} else {
		ids := l.evidenceIDsForQuestionLocked(actor.TenantID, question, productID, releaseID)
		answer := "No matching evidence is recorded for this question."
		if len(ids) > 0 {
			answer = "Evidence is available for review in the linked evidence records."
		}
		response = domain.QuestionnaireResponse{QuestionID: question.ID, Answer: answer, EvidenceIDs: ids, Limitations: []string{"Questionnaire responses summarize recorded evidence and require human review."}}
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if releaseID != "" {
		release, ok := l.releases[releaseID]
		if !ok || release.TenantID != actor.TenantID || productID != "" && release.ProductID != productID {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
		productID = release.ProductID
	}
	for _, id := range response.EvidenceIDs {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != actor.TenantID {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
		refs := refsForEvidence(item)
		if productID != "" && !l.productCoversRefsLocked(actor.TenantID, productID, refs) || releaseID != "" && !l.releaseCoversRefsLocked(actor.TenantID, releaseID, refs) {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
	}
	return response, nil
}

func (l *Ledger) questionnaireAnswerLibraryMatchLocked(actor domain.Actor, scope string, question domain.QuestionnaireQuestion, productID, releaseID string) (domain.QuestionnaireAnswerLibraryEntry, bool) {
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	candidates := []domain.QuestionnaireAnswerLibraryEntry{}
	for _, entry := range l.answerLibrary {
		if entry.TenantID != actor.TenantID || !questionnaireAnswerMatchesQuestion(entry, question) {
			continue
		}
		if entry.ProductID != "" && entry.ProductID != productID {
			continue
		}
		if entry.ReleaseID != "" && entry.ReleaseID != releaseID {
			continue
		}
		if err := l.authorizeResourceLocked(actor, scope, resourceRefs{ProductID: entry.ProductID, ReleaseID: entry.ReleaseID}); err != nil {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		return domain.QuestionnaireAnswerLibraryEntry{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := questionnaireAnswerSpecificity(candidates[i], question), questionnaireAnswerSpecificity(candidates[j], question)
		if left != right {
			return left > right
		}
		if !candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].CreatedAt.After(candidates[j].CreatedAt)
		}
		return candidates[i].ID < candidates[j].ID
	})
	return candidates[0], true
}

func questionnaireAnswerMatchesQuestion(entry domain.QuestionnaireAnswerLibraryEntry, question domain.QuestionnaireQuestion) bool {
	return packageapp.DraftAnswerMatchesQuestion(packageapp.DraftAnswerCandidate{QuestionID: entry.QuestionID, ControlID: entry.ControlID, EvidenceType: entry.EvidenceType}, packageapp.DraftQuestion{ID: question.ID, ControlID: question.ControlID, EvidenceType: question.EvidenceType})
}

func questionnaireAnswerSpecificity(entry domain.QuestionnaireAnswerLibraryEntry, question domain.QuestionnaireQuestion) int {
	return packageapp.DraftAnswerSpecificity(packageapp.DraftAnswerCandidate{QuestionID: entry.QuestionID, ControlID: entry.ControlID, EvidenceType: entry.EvidenceType, ProductID: entry.ProductID, ReleaseID: entry.ReleaseID}, packageapp.DraftQuestion{ID: question.ID, ControlID: question.ControlID, EvidenceType: question.EvidenceType})
}

func prepareLocalQuestionnairePackage(ctx context.Context, a domain.Actor, in CreateQuestionnairePackageInput) (packageapp.CreateQuestionnairePackageInput, error) {
	if err := packagequery.NewQuestionnairePackageAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return packageapp.CreateQuestionnairePackageInput{}, fromIdentityContextError(err)
	}
	v, err := packageapp.NormalizeQuestionnairePackageInput(packageapp.CreateQuestionnairePackageInput{TemplateID: in.TemplateID, PackageID: in.PackageID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	return v, fromPackageContextError(err)
}

// Explicit local-memory replay checks current references without reading answer
// text. PostgreSQL binds the focused Package service instead of this facade.
func (l *Ledger) AuthorizeQuestionnairePackageCreate(ctx context.Context, a domain.Actor, raw CreateQuestionnairePackageInput) error {
	if l == nil {
		return ErrValidation
	}
	in, err := prepareLocalQuestionnairePackage(ctx, a, raw)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeQuestionnairePackageCreateLocked(ctx, a, in)
}

func (l *Ledger) authorizeQuestionnairePackageCreateLocked(ctx context.Context, a domain.Actor, in packageapp.CreateQuestionnairePackageInput) error {
	tpl, ok := l.questionTemplates[in.TemplateID]
	if !ok || tpl.TenantID != a.TenantID {
		return ErrNotFound
	}
	resolve := func(product, release string) (application.ResourceReferences, error) {
		refs := application.ResourceReferences{ProductID: product, ReleaseID: release}
		if release != "" {
			r, ok := l.releases[release]
			if !ok || r.TenantID != a.TenantID || product != "" && product != r.ProductID {
				return refs, ErrNotFound
			}
			refs.ProductID = r.ProductID
		}
		if refs.ProductID != "" {
			p, ok := l.products[refs.ProductID]
			if !ok || p.TenantID != a.TenantID {
				return refs, ErrNotFound
			}
		}
		return refs, nil
	}
	refs, err := resolve(in.ProductID, in.ReleaseID)
	if err != nil {
		return err
	}
	scope := packageapp.QuestionnairePackageScope{Selection: packageapp.QuestionnaireDraftScope{TenantID: a.TenantID, TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: refs}}
	if in.PackageID != "" {
		pkg, ok := l.customerPackages[in.PackageID]
		if !ok || pkg.TenantID != a.TenantID {
			return ErrNotFound
		}
		p, err := resolve(pkg.ProductID, pkg.ReleaseID)
		if err != nil {
			return err
		}
		p.CustomerPackageID = in.PackageID
		scope.PackageID, scope.PackageResources = in.PackageID, p
	}
	if err := packageapp.ValidateQuestionnairePackageScope(a.TenantID, in, scope); err != nil {
		return fromPackageContextError(err)
	}
	if err := packagequery.NewQuestionnairePackageAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: refs, TenantWide: refs == (application.ResourceReferences{})}); err != nil {
		return fromIdentityContextError(err)
	}
	if in.PackageID != "" {
		return fromIdentityContextError(packagequery.NewQuestionnairePackageAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: scope.PackageResources}))
	}
	return ctx.Err()
}

func questionnairePackageToContext(v domain.QuestionnairePackage) packagedomain.QuestionnairePackage {
	responses := make([]packagedomain.QuestionnaireResponse, len(v.Responses))
	for i, r := range v.Responses {
		responses[i] = packagedomain.QuestionnaireResponse{QuestionID: r.QuestionID, Answer: r.Answer, EvidenceIDs: r.EvidenceIDs, Limitations: r.Limitations}
	}
	return packagedomain.QuestionnairePackage{ID: v.ID, TenantID: v.TenantID, TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Responses: responses, ManifestHash: v.ManifestHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func cloneQuestionnairePackageDTO(v domain.QuestionnairePackage) domain.QuestionnairePackage {
	v.Responses = append([]domain.QuestionnaireResponse(nil), v.Responses...)
	for i := range v.Responses {
		v.Responses[i].EvidenceIDs = append([]string(nil), v.Responses[i].EvidenceIDs...)
		v.Responses[i].Limitations = append([]string(nil), v.Responses[i].Limitations...)
	}
	return v
}

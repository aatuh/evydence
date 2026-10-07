package app

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Historical declarations retained unchanged for package-local regression tests.
// HTTP fixtures use focused commands and transaction repository projections;
// these methods are not a runtime backend or proof of native SQL behavior.

type CreateQuestionnaireAnswerLibraryEntryInput struct {
	QuestionID   string
	EvidenceType string
	ControlID    string
	ProductID    string
	ReleaseID    string
	Answer       string
	EvidenceIDs  []string
	Limitations  []string
}

type ListQuestionnaireAnswerLibraryInput struct {
	QuestionID string
	ProductID  string
	ReleaseID  string
}

func (l *Ledger) validateQuestionnaireTemplateControlsLocked(tenant string, ids []string) error {
	if len(ids) > packageapp.MaxQuestionnaireTemplateQuestions {
		return ErrValidation
	}
	if _, ok := l.tenants[tenant]; !ok {
		return ErrNotFound
	}
	for _, id := range ids {
		c, ok := l.controls[id]
		f, frameworkExists := l.frameworks[c.FrameworkID]
		if !ok || c.TenantID != tenant || !frameworkExists || f.TenantID != tenant {
			return ErrNotFound
		}
	}
	return nil
}

func (l *Ledger) CreateQuestionnaireAnswerLibraryEntry(ctx context.Context, actor domain.Actor, raw CreateQuestionnaireAnswerLibraryEntryInput) (domain.QuestionnaireAnswerLibraryEntry, error) {
	in, err := prepareLocalAnswerLibraryInput(ctx, actor, raw)
	if err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeAnswerLibraryCreateLocked(ctx, actor, in); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	entry := domain.QuestionnaireAnswerLibraryEntry{
		ID:            newID("qal"),
		TenantID:      actor.TenantID,
		QuestionID:    in.QuestionID,
		EvidenceType:  in.EvidenceType,
		ControlID:     in.ControlID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Answer:        in.Answer,
		EvidenceIDs:   in.EvidenceIDs,
		Limitations:   in.Limitations,
		SchemaVersion: domain.QuestionnaireAnswerLibraryVersion,
		CreatedAt:     l.now(),
	}
	if err := packageapp.ValidateAnswerLibraryRecord(answerLibraryEntryToContext(entry)); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, fromPackageContextError(err)
	}
	if l.unitOfWork != nil {
		var auditEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Enterprise.InsertQuestionnaireAnswerLibraryEntry(ctx, entry); err != nil {
				return err
			}
			var err error
			auditEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(entry.CreatedAt, actor.TenantID, "questionnaire_answer_library.created", "questionnaire_answer_library", entry.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.QuestionnaireAnswerLibraryEntry{}, err
		}
		l.answerLibrary[entry.ID] = entry
		l.publishCommittedAuditEntryLocked(auditEntry)
		return cloneAnswerLibraryDTO(entry), nil
	}
	l.answerLibrary[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_answer_library.created", "questionnaire_answer_library", entry.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireAnswerLibraryEntry{}, err
	}
	return cloneAnswerLibraryDTO(entry), nil
}

func (l *Ledger) ListQuestionnaireAnswerLibrary(ctx context.Context, actor domain.Actor, in ListQuestionnaireAnswerLibraryInput) ([]domain.QuestionnaireAnswerLibraryEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return nil, err
	}
	in.QuestionID, in.ProductID, in.ReleaseID = strings.TrimSpace(in.QuestionID), strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.ProductID != "" || in.ReleaseID != "" {
		if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
			return nil, err
		}
		if err := l.authorizeResourceLocked(actor, ScopePackageRead, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
			return nil, err
		}
	}
	out := []domain.QuestionnaireAnswerLibraryEntry{}
	for _, entry := range l.answerLibrary {
		if entry.TenantID != actor.TenantID {
			continue
		}
		if in.QuestionID != "" && entry.QuestionID != in.QuestionID {
			continue
		}
		if in.ProductID != "" && entry.ProductID != "" && entry.ProductID != in.ProductID {
			continue
		}
		if in.ReleaseID != "" && entry.ReleaseID != "" && entry.ReleaseID != in.ReleaseID {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopePackageRead, resourceRefs{ProductID: entry.ProductID, ReleaseID: entry.ReleaseID}) {
			continue
		}
		out = append(out, cloneAnswerLibraryDTO(entry))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func prepareLocalAnswerLibraryInput(ctx context.Context, a domain.Actor, in CreateQuestionnaireAnswerLibraryEntryInput) (packageapp.CreateAnswerLibraryEntryInput, error) {
	if err := packagequery.NewAnswerLibraryAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return packageapp.CreateAnswerLibraryEntryInput{}, fromIdentityContextError(err)
	}
	v, err := packageapp.NormalizeAnswerLibraryInput(packageapp.CreateAnswerLibraryEntryInput{QuestionID: in.QuestionID, EvidenceType: in.EvidenceType, ControlID: in.ControlID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Answer: in.Answer, EvidenceIDs: in.EvidenceIDs, Limitations: in.Limitations})
	return v, fromPackageContextError(err)
}

// Only explicit local-memory replay uses this facade. Durable production binds
// the Package-owned command directly and never reads these maps.
func (l *Ledger) AuthorizeQuestionnaireAnswerLibraryCreate(ctx context.Context, a domain.Actor, raw CreateQuestionnaireAnswerLibraryEntryInput) error {
	if l == nil {
		return ErrValidation
	}
	in, err := prepareLocalAnswerLibraryInput(ctx, a, raw)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeAnswerLibraryCreateLocked(ctx, a, in)
}

func (l *Ledger) authorizeAnswerLibraryCreateLocked(ctx context.Context, a domain.Actor, in packageapp.CreateAnswerLibraryEntryInput) error {
	refs := application.ResourceReferences{ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	if in.ReleaseID != "" {
		r, ok := l.releases[in.ReleaseID]
		if !ok || r.TenantID != a.TenantID || in.ProductID != "" && r.ProductID != in.ProductID {
			return ErrNotFound
		}
		refs.ProductID = r.ProductID
	}
	if refs.ProductID != "" {
		p, ok := l.products[refs.ProductID]
		if !ok || p.TenantID != a.TenantID {
			return ErrNotFound
		}
	}
	if err := packagequery.NewAnswerLibraryAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: refs, TenantWide: refs == (application.ResourceReferences{})}); err != nil {
		return fromIdentityContextError(err)
	}
	controls := []string{}
	if in.ControlID != "" {
		controls = append(controls, in.ControlID)
	}
	if err := l.validateQuestionnaireTemplateControlsLocked(a.TenantID, controls); err != nil {
		return err
	}
	seen := make(map[string]bool, len(in.EvidenceIDs))
	total := 0
	for _, id := range in.EvidenceIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		item, ok := l.evidence[id]
		if !ok || item.TenantID != a.TenantID || !evidenceMatchesRefs(item, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}) || !l.answerLibraryCitationParentsLocked(item) {
			return ErrNotFound
		}
		total += len(id) + len(item.ProductID) + len(item.ProjectID) + len(item.ReleaseID) + len(item.BuildID) + len(item.DeploymentID)
		if total > packageapp.MaxGeneratedReportBytes {
			return ErrValidation
		}
	}
	return ctx.Err()
}

// Resolve only selected local parent identities; raw matching above remains
// unchanged. Product, project, release, build and deployment must all agree.
func (l *Ledger) answerLibraryCitationParentsLocked(item domain.EvidenceItem) bool {
	for _, id := range []string{item.ProductID, item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID} {
		if id != strings.TrimSpace(id) || len(id) > packageapp.MaxAnswerLibraryIDBytes || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
			return false
		}
	}
	product := ""
	mergeProduct := func(id string) bool {
		p, ok := l.products[id]
		if id == "" || !ok || p.TenantID != item.TenantID || product != "" && product != id {
			return false
		}
		product = id
		return true
	}
	project := func(id string) bool {
		p, ok := l.projects[id]
		return ok && p.TenantID == item.TenantID && mergeProduct(p.ProductID)
	}
	release := func(id string) bool {
		r, ok := l.releases[id]
		return ok && r.TenantID == item.TenantID && mergeProduct(r.ProductID)
	}
	if item.ProductID != "" && !mergeProduct(item.ProductID) || item.ProjectID != "" && !project(item.ProjectID) || item.ReleaseID != "" && !release(item.ReleaseID) {
		return false
	}
	buildRelease := ""
	if item.BuildID != "" {
		b, ok := l.buildRuns[item.BuildID]
		if !ok || b.TenantID != item.TenantID || item.ProjectID != "" && b.ProjectID != item.ProjectID || item.ReleaseID != "" && b.ReleaseID != item.ReleaseID || !project(b.ProjectID) || !release(b.ReleaseID) {
			return false
		}
		buildRelease = b.ReleaseID
	}
	if item.DeploymentID != "" {
		d, ok := l.deployments[item.DeploymentID]
		if !ok || d.TenantID != item.TenantID || item.ReleaseID != "" && d.ReleaseID != item.ReleaseID || buildRelease != "" && buildRelease != d.ReleaseID || !release(d.ReleaseID) {
			return false
		}
		e, ok := l.environments[d.EnvironmentID]
		if !ok || e.TenantID != item.TenantID || !mergeProduct(e.ProductID) {
			return false
		}
	}
	return true
}

func answerLibraryEntryToContext(v domain.QuestionnaireAnswerLibraryEntry) packagedomain.QuestionnaireAnswerLibraryEntry {
	return packagedomain.QuestionnaireAnswerLibraryEntry{ID: v.ID, TenantID: v.TenantID, QuestionID: v.QuestionID, EvidenceType: v.EvidenceType, ControlID: v.ControlID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Answer: v.Answer, EvidenceIDs: v.EvidenceIDs, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func cloneAnswerLibraryDTO(v domain.QuestionnaireAnswerLibraryEntry) domain.QuestionnaireAnswerLibraryEntry {
	v.EvidenceIDs = append([]string(nil), v.EvidenceIDs...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}

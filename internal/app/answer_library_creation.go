package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

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

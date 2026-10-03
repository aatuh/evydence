package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

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

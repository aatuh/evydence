package app

import (
	"context"
	"errors"
	"slices"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func memoryAnswerLibraryScope(state *MemoryUnitOfWorkSnapshot, tenant, product, release string) (packageapp.AnswerLibraryScope, error) {
	out := packageapp.AnswerLibraryScope{TenantID: tenant, ProductID: product, ReleaseID: release}
	for _, id := range []string{product, release} {
		if id != "" && !memoryMembershipQueryText(id, packageapp.MaxAnswerLibraryIDBytes) {
			return out, ErrValidation
		}
	}
	kind, id := "tenant", tenant
	if release != "" {
		kind, id = "release", release
	} else if product != "" {
		kind, id = "product", product
	}
	root, err := memorySummaryScope(state, tenant, kind, id)
	if err != nil {
		return out, err
	}
	if product != "" && root.Resources.ProductID != product {
		return out, ErrNotFound
	}
	out.Resources = application.ResourceReferences{ProductID: root.Resources.ProductID, ReleaseID: release}
	return out, nil
}
func (r memoryEnterpriseRepository) ReadAnswerLibraryScope(ctx context.Context, tenant, product, release string) (packageapp.AnswerLibraryScope, error) {
	var out packageapp.AnswerLibraryScope
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryAnswerLibraryScope(state, tenant, product, release)
		return err
	})
	return out, err
}
func memoryAnswerLibraryReferences(state *MemoryUnitOfWorkSnapshot, s packageapp.AnswerLibraryScope, control string, ids []string) error {
	if len(ids) > packageapp.MaxAnswerLibraryEvidenceIDs || control != "" && !memoryMembershipQueryText(control, 1024) {
		return ErrValidation
	}
	if _, err := memoryAnswerLibraryScope(state, s.TenantID, s.ProductID, s.ReleaseID); err != nil {
		return err
	}
	if control != "" {
		if err := memoryQuestionnaireControl(state, s.TenantID, control); err != nil {
			return err
		}
	}
	seen := make(map[string]bool, len(ids))
	total := 0
	for _, id := range ids {
		if !memoryMembershipQueryText(id, 1024) {
			return ErrValidation
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		e, ok := state.Evidence[id]
		if !ok || e.ID != id || e.TenantID != s.TenantID || s.ProductID != "" && e.ProductID != s.ProductID || s.ReleaseID != "" && e.ReleaseID != s.ReleaseID {
			return ErrNotFound
		}
		refs := application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID}
		for _, value := range []string{e.ProductID, e.ProjectID, e.ReleaseID, e.BuildID, e.DeploymentID} {
			if !memoryMembershipText(value, 1024) {
				return ErrConflict
			}
			total += len(value)
		}
		total += len(id)
		if total > packageapp.MaxGeneratedReportBytes {
			return ErrValidation
		}
		if _, err := memoryOperationsCoordinates(state, s.TenantID, refs); err != nil {
			return ErrNotFound
		}
	}
	return nil
}
func (r memoryEnterpriseRepository) ValidateAnswerLibraryReferences(ctx context.Context, s packageapp.AnswerLibraryScope, control string, ids []string) error {
	if len(ids) > packageapp.MaxAnswerLibraryEvidenceIDs {
		return ErrValidation
	}
	return memoryIdentityRepository(r).membershipRead(ctx, s.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		return memoryAnswerLibraryReferences(state, s, control, ids)
	})
}
func memoryAnswerLibraryModel(e domain.QuestionnaireAnswerLibraryEntry) packagedomain.QuestionnaireAnswerLibraryEntry {
	return packagedomain.QuestionnaireAnswerLibraryEntry{ID: e.ID, TenantID: e.TenantID, QuestionID: e.QuestionID, EvidenceType: e.EvidenceType, ControlID: e.ControlID, ProductID: e.ProductID, ReleaseID: e.ReleaseID, Answer: e.Answer, EvidenceIDs: e.EvidenceIDs, Limitations: e.Limitations, SchemaVersion: e.SchemaVersion, CreatedAt: e.CreatedAt}
}
func (r memoryEnterpriseRepository) InsertFocusedAnswerLibraryEntry(ctx context.Context, v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	if err := packageapp.ValidateAnswerLibraryRecord(v); err != nil {
		return fromPackageContextError(err)
	}
	s, err := r.ReadAnswerLibraryScope(ctx, v.TenantID, v.ProductID, v.ReleaseID)
	if err != nil {
		return err
	}
	if err := r.ValidateAnswerLibraryReferences(ctx, s, v.ControlID, v.EvidenceIDs); err != nil {
		return err
	}
	return r.InsertQuestionnaireAnswerLibraryEntry(ctx, domain.QuestionnaireAnswerLibraryEntry{ID: v.ID, TenantID: v.TenantID, QuestionID: v.QuestionID, EvidenceType: v.EvidenceType, ControlID: v.ControlID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Answer: v.Answer, EvidenceIDs: slices.Clone(v.EvidenceIDs), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}

// Current-parent and grant predicates precede keyset paging. Only the selected
// page's private answer/arrays are validated and copied into the result.
func (r memoryEnterpriseRepository) PageAnswerLibrary(ctx context.Context, req packagequery.AnswerLibraryPageRequest) (appquery.Result[packagequery.AnswerLibraryPoint], error) {
	var out appquery.Result[packagequery.AnswerLibraryPoint]
	if req.TenantWide && (len(req.AllowedProductIDs) > 0 || len(req.AllowedReleaseIDs) > 0) || !req.TenantWide && len(req.AllowedProductIDs) == 0 && len(req.AllowedReleaseIDs) == 0 {
		return out, packagequery.ErrValidation
	}
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type point struct {
		id, product string
		at          time.Time
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, req.TenantID, func(state *MemoryUnitOfWorkSnapshot) error {
		f := req.Filter
		filterProduct := ""
		if f.ProductID != "" {
			if err := memoryRoleProduct(state, req.TenantID, f.ProductID); err != nil {
				return packagequery.ErrNotFound
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, f.ProductID) {
				return application.ErrForbidden
			}
		}
		if f.ReleaseID != "" {
			s, err := memoryAnswerLibraryScope(state, req.TenantID, "", f.ReleaseID)
			if err != nil {
				return packagequery.ErrNotFound
			}
			filterProduct = s.Resources.ProductID
			if f.ProductID != "" && f.ProductID != filterProduct {
				return packagequery.ErrValidation
			}
			if !req.TenantWide && !slices.Contains(req.AllowedReleaseIDs, f.ReleaseID) && !slices.Contains(req.AllowedProductIDs, filterProduct) {
				return application.ErrForbidden
			}
		}
		points := []point{}
		for key, e := range state.AnswerLibrary {
			if e.TenantID != req.TenantID || f.QuestionID != "" && e.QuestionID != f.QuestionID || f.ReleaseID != "" && e.ReleaseID != "" && e.ReleaseID != f.ReleaseID {
				continue
			}
			s, err := memoryAnswerLibraryScope(state, req.TenantID, e.ProductID, e.ReleaseID)
			if err != nil {
				continue
			}
			product := s.Resources.ProductID
			if f.ProductID != "" && product != "" && product != f.ProductID || filterProduct != "" && product != "" && product != filterProduct {
				continue
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, product) && (e.ReleaseID == "" || !slices.Contains(req.AllowedReleaseIDs, e.ReleaseID)) {
				continue
			}
			if err := memoryAnswerLibraryReferences(state, s, e.ControlID, e.EvidenceIDs); err != nil {
				continue
			}
			if key != e.ID || !memoryMembershipQueryText(e.ID, 1024) {
				return packagequery.ErrInvalidProjection
			}
			points = append(points, point{e.ID, product, e.CreatedAt})
		}
		page, err := appquery.Page(points, req.Page, req.After, func(v point, sort appquery.Sort) appquery.SortKey { return appquery.RecordSortKey(v.id, v.at, sort) })
		if err != nil {
			return err
		}
		out = appquery.Result[packagequery.AnswerLibraryPoint]{Items: make([]packagequery.AnswerLibraryPoint, 0, len(page.Items)), Next: page.Next}
		for _, p := range page.Items {
			e := memoryAnswerLibraryModel(state.AnswerLibrary[p.id])
			if err := packageapp.ValidateAnswerLibraryRecord(e); err != nil {
				return packagequery.ErrInvalidProjection
			}
			e.EvidenceIDs, e.Limitations = slices.Clone(e.EvidenceIDs), slices.Clone(e.Limitations)
			out.Items = append(out.Items, packagequery.AnswerLibraryPoint{Entry: e, EffectiveProductID: p.product})
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		err = packagequery.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = packagequery.ErrValidation
	}
	if err != nil {
		return appquery.Result[packagequery.AnswerLibraryPoint]{}, err
	}
	return out, nil
}

var _ packageapp.AnswerLibraryReader = memoryEnterpriseRepository{}
var _ packagequery.AnswerLibraryReader = memoryEnterpriseRepository{}

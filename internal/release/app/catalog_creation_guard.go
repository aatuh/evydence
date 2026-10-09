package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type CatalogCreationProduct struct{ ID, TenantID string }

// This read-only port excludes names, slugs, versions and uniqueness lookups.
type CatalogCreationGuardReader interface {
	LockCatalogCreationTenant(context.Context, string) error
	ReadCatalogCreationProduct(context.Context, string, string) (CatalogCreationProduct, error)
}

type catalogCreationGuardTransaction interface {
	application.Authorizer
	CatalogCreationGuardReader
}

func normalizeCatalogCreationText(raw string, limit int) (string, error) {
	if len(raw) > limit || !validBuildText(raw) {
		return "", ErrValidation
	}
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", ErrValidation
	}
	return v, nil
}

func NormalizeProductCreationInput(in CreateProductInput) (CreateProductInput, error) {
	var err error
	if in.Name, err = normalizeCatalogCreationText(in.Name, 65536); err != nil {
		return CreateProductInput{}, err
	}
	if in.Slug, err = normalizeCatalogCreationText(in.Slug, 65536); err != nil {
		return CreateProductInput{}, err
	}
	if len(in.Slug) > 1024 {
		return CreateProductInput{}, ErrValidation
	}
	return in, nil
}
func NormalizeProjectCreationInput(in CreateProjectInput) (CreateProjectInput, error) {
	var err error
	if in.ProductID, err = normalizeCatalogCreationText(in.ProductID, 1024); err != nil {
		return CreateProjectInput{}, err
	}
	if in.Name, err = normalizeCatalogCreationText(in.Name, 65536); err != nil {
		return CreateProjectInput{}, err
	}
	return in, nil
}
func NormalizeReleaseCreationInput(in CreateReleaseInput) (CreateReleaseInput, error) {
	var err error
	if in.ProductID, err = normalizeCatalogCreationText(in.ProductID, 1024); err != nil {
		return CreateReleaseInput{}, err
	}
	if in.Version, err = normalizeCatalogCreationText(in.Version, 65536); err != nil {
		return CreateReleaseInput{}, err
	}
	return in, nil
}

func validateCatalogCreationActor(ctx context.Context, a identitydomain.Actor) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if a.TenantID == "" || len(a.TenantID) > 1024 || !validBuildText(a.TenantID) || strings.TrimSpace(a.TenantID) != a.TenantID {
		return ErrValidation
	}
	return nil
}

func authorizeCatalogCreationScope(ctx context.Context, tx catalogCreationGuardTransaction, a identitydomain.Actor, scope, productID string) error {
	request := application.AuthorizationRequest{Scope: scope, ScopeOnly: productID != "", TenantWide: productID == ""}
	if err := tx.Authorize(ctx, a, request); err != nil {
		return err
	}
	if err := tx.LockCatalogCreationTenant(ctx, a.TenantID); err != nil {
		return err
	}
	if productID == "" {
		return nil
	}
	p, err := tx.ReadCatalogCreationProduct(ctx, a.TenantID, productID)
	if err != nil {
		return err
	}
	if p.TenantID != a.TenantID || p.ID != productID {
		return ErrNotFound
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: scope, Resources: application.ResourceReferences{ProductID: p.ID}})
}

func (s *ProductCommands) AuthorizeProductCreation(ctx context.Context, a identitydomain.Actor, in CreateProductInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeProductWrite, TenantWide: true}); err != nil {
		return err
	}
	if _, err := NormalizeProductCreationInput(in); err != nil {
		return err
	}
	return s.transactions.ExecuteProduct(ctx, func(ctx context.Context, tx ProductTransaction) error {
		g, ok := tx.(catalogCreationGuardTransaction)
		if !ok {
			return ErrValidation
		}
		return authorizeCatalogCreationScope(ctx, g, a, ScopeProductWrite, "")
	})
}
func (s *ProjectCommands) AuthorizeProjectCreation(ctx context.Context, a identitydomain.Actor, in CreateProjectInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeProjectWrite, ScopeOnly: true}); err != nil {
		return err
	}
	input, err := NormalizeProjectCreationInput(in)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteProject(ctx, func(ctx context.Context, tx ProjectTransaction) error {
		g, ok := tx.(catalogCreationGuardTransaction)
		if !ok {
			return ErrValidation
		}
		return authorizeCatalogCreationScope(ctx, g, a, ScopeProjectWrite, input.ProductID)
	})
}
func (s *ReleaseCommands) AuthorizeReleaseCreation(ctx context.Context, a identitydomain.Actor, in CreateReleaseInput) error {
	if s == nil {
		return ErrValidation
	}
	if err := validateCatalogCreationActor(ctx, a); err != nil {
		return err
	}
	if err := s.authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return err
	}
	input, err := NormalizeReleaseCreationInput(in)
	if err != nil {
		return err
	}
	return s.transactions.ExecuteReleaseCreation(ctx, func(ctx context.Context, tx ReleaseCreationTransaction) error {
		g, ok := tx.(catalogCreationGuardTransaction)
		if !ok {
			return ErrValidation
		}
		return authorizeCatalogCreationScope(ctx, g, a, ScopeReleaseWrite, input.ProductID)
	})
}

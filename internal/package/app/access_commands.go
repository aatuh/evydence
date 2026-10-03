package app

import (
	"context"
	"math"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxCustomerPackageManifestBytes = 8 << 20
	MaxSecurityReviewEvidenceIDs    = 4096
)

type AccessTransaction interface {
	GetCustomerSecurityPackageForUpdate(context.Context, string, string) (packagedomain.CustomerSecurityPackage, error)
	UpdateCustomerSecurityPackageAccess(context.Context, packagedomain.CustomerSecurityPackage, packagedomain.CustomerSecurityPackage) error
	application.Authorizer
	application.AuditAppender
}

type AccessTransactions interface {
	ExecutePackageAccess(context.Context, func(context.Context, AccessTransaction) error) error
}

type AccessCommandConfig struct {
	Transactions AccessTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}

// AccessCommands owns audited access to a single customer package. Its narrow
// transaction reads and locks only that package; no tenant-wide state is read.
type AccessCommands struct{ config AccessCommandConfig }

func NewAccessCommands(config AccessCommandConfig) (*AccessCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &AccessCommands{config: config}, nil
}

func (s *AccessCommands) AccessCustomerSecurityPackage(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	return s.access(ctx, actor, id, nil)
}

func (s *AccessCommands) access(ctx context.Context, actor identitydomain.Actor, id string, validate func(packagedomain.CustomerSecurityPackage) error) (packagedomain.CustomerSecurityPackage, error) {
	var empty packagedomain.CustomerSecurityPackage
	if s == nil {
		return empty, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return empty, err
	}
	if err := validateActor(actor); err != nil {
		return empty, err
	}
	if !actor.HasScope(ScopePackageRead) && !actor.HasScope("admin") {
		return empty, ErrForbidden
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePackageRead, ScopeOnly: true}); err != nil {
		return empty, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return empty, ErrValidation
	}
	var accessed packagedomain.CustomerSecurityPackage
	err := s.config.Transactions.ExecutePackageAccess(ctx, func(ctx context.Context, tx AccessTransaction) error {
		current, err := tx.GetCustomerSecurityPackageForUpdate(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if !validCustomerSecurityPackage(current, actor.TenantID, id) {
			return ErrNotFound
		}
		refs := application.ResourceReferences{ProductID: current.ProductID, ReleaseID: current.ReleaseID, CustomerPackageID: current.ID}
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePackageRead, Resources: refs}); err != nil {
			return err
		}
		// Resolve time after the row lock, so a lock wait cannot resurrect an
		// expired package. The count and audit record commit together.
		now := s.config.Clock.Now().UTC()
		if now.IsZero() || !current.ExpiresAt.After(now) || current.AccessCount < 0 || current.AccessCount >= math.MaxInt32 {
			return ErrConflict
		}
		if validate != nil {
			if err := validate(current); err != nil {
				return err
			}
		}
		accessed = cloneCustomerSecurityPackage(current)
		accessed.AccessCount++
		if err := tx.UpdateCustomerSecurityPackageAccess(ctx, current, accessed); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "customer_package.accessed", SubjectType: "customer_security_package", SubjectID: current.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now, PayloadHash: current.ManifestHash})
		return err
	})
	if err != nil {
		return empty, err
	}
	return cloneCustomerSecurityPackage(accessed), nil
}

// SecurityReviewPackageReport retains the historical audited-access side
// effect, while rendering only the frozen package's evidence identifiers.
func (s *AccessCommands) SecurityReviewPackageReport(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.SecurityReviewPackageReport, error) {
	var ids []string
	pkg, err := s.access(ctx, actor, id, func(pkg packagedomain.CustomerSecurityPackage) error {
		var err error
		ids, err = securityReviewEvidenceIDs(pkg.Manifest["evidence_ids"])
		return err
	})
	if err != nil {
		return packagedomain.SecurityReviewPackageReport{}, err
	}
	return packagedomain.SecurityReviewPackageReport{ReportType: "security_review_package", TemplateVersion: "security-review-package.v1.0.0", PackageID: pkg.ID, ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, EvidenceIDs: ids, Assumptions: []string{"Report includes only package-scoped evidence metadata."}, Limitations: []string{"This report supports customer review but is not a compliance, legal, or secure-release conclusion."}, GeneratedAt: s.config.Clock.Now().UTC()}, nil
}

func securityReviewEvidenceIDs(value any) ([]string, error) {
	ids := []string{}
	switch values := value.(type) {
	case nil:
		return ids, nil
	case []string:
		if len(values) > MaxSecurityReviewEvidenceIDs {
			return nil, ErrConflict
		}
		ids = append(ids, values...)
	case []any:
		if len(values) > MaxSecurityReviewEvidenceIDs {
			return nil, ErrConflict
		}
		for _, entry := range values {
			id, ok := entry.(string)
			if !ok {
				return nil, ErrConflict
			}
			ids = append(ids, id)
		}
	default:
		return nil, ErrConflict
	}
	if len(ids) > MaxSecurityReviewEvidenceIDs {
		return nil, ErrConflict
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || len(id) > 1024 || seen[id] {
			return nil, ErrConflict
		}
		seen[id] = true
	}
	return ids, nil
}

// The explicit local-memory service adapts its compatibility transaction to
// the same command orchestration rather than duplicating access policy.
type serviceAccessTransactions struct{ runner TransactionRunner }

func (t serviceAccessTransactions) ExecutePackageAccess(ctx context.Context, command func(context.Context, AccessTransaction) error) error {
	return t.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error { return command(ctx, serviceAccessTransaction{tx: tx}) })
}

type serviceAccessTransaction struct{ tx Transaction }

func (t serviceAccessTransaction) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	return t.tx.Packages().GetCustomerSecurityPackageForUpdate(ctx, tenantID, id)
}
func (t serviceAccessTransaction) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, current packagedomain.CustomerSecurityPackage) error {
	return t.tx.Packages().UpdateCustomerSecurityPackageAccess(ctx, previous, current)
}
func (t serviceAccessTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return t.tx.Authorization().Authorize(ctx, actor, request)
}
func (t serviceAccessTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, event)
}

func (s *Service) accessCommands() *AccessCommands {
	return &AccessCommands{config: AccessCommandConfig{Transactions: serviceAccessTransactions{runner: s.transactions}, Authorizer: s.authorizer, Clock: s.clock, IDs: s.ids}}
}
func (s *Service) SecurityReviewPackageReport(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.SecurityReviewPackageReport, error) {
	return s.accessCommands().SecurityReviewPackageReport(ctx, actor, id)
}

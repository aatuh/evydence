package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Historical portal implementation, retained only for package-local behavior,
// cancellation and persistence regressions during aggregate retirement. These
// declarations are compiled only for this package's own tests, not runtime use. Native
// portal behavior is exercised separately through focused Package services and
// the native HTTP/composition suites, not through this oracle.

const customerPortalFailedAccessLimit = 5

type CreateCustomerPortalAccessInput struct {
	PackageID     string
	CustomerName  string
	ReviewerName  string
	ReviewerEmail string
	RequireNDA    bool
	Watermark     string
	ExpiresAt     time.Time
}

type CustomerPortalAcceptanceInput struct {
	NDAAccepted   bool
	NDAAcceptedBy string
}

func (l *Ledger) CreateCustomerPortalAccess(ctx context.Context, actor domain.Actor, in CreateCustomerPortalAccessInput) (domain.CustomerPortalAccess, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	input, err := prepareLocalPortalAccess(ctx, actor, in)
	if err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	in = CreateCustomerPortalAccessInput{PackageID: input.PackageID, CustomerName: input.CustomerName, ReviewerName: input.ReviewerName, ReviewerEmail: input.ReviewerEmail, RequireNDA: input.RequireNDA, Watermark: input.Watermark, ExpiresAt: input.ExpiresAt}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizePortalWriteLocked(ctx, actor, in.PackageID); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	if !in.ExpiresAt.After(l.now()) {
		return domain.CustomerPortalAccess{}, "", ErrValidation
	}
	pkg := l.customerPackages[in.PackageID]
	secret := "evycp_" + randomToken(32)
	accessID := newID("cpa")
	watermark := in.Watermark
	if watermark == "" {
		watermark = packageapp.PortalDistributionWatermark(input, accessID)
	}
	access := domain.CustomerPortalAccess{ID: accessID, TenantID: actor.TenantID, PackageID: pkg.ID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: watermark, Prefix: secretPrefix(secret), ExpiresAt: in.ExpiresAt.UTC(), SchemaVersion: domain.CustomerPortalAccessVersion, CreatedAt: l.now(), Hash: l.hashSecret(secret)}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertCustomerPortalAccess(ctx, access); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(access.CreatedAt, actor.TenantID, "customer_portal_access.created", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.CustomerPortalAccess{}, "", err
		}
		l.portalAccess[access.ID] = access
		l.publishCommittedAuditEntryLocked(entry)
		public := access
		public.Hash = ""
		return public, secret, nil
	}
	l.portalAccess[access.ID] = access
	_, _ = l.appendChainLocked(actor.TenantID, "customer_portal_access.created", "customer_security_package", pkg.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistCriticalStateLocked(ctx); err != nil {
		return domain.CustomerPortalAccess{}, "", err
	}
	access.Hash = ""
	return access, secret, nil
}

func (l *Ledger) ListCustomerPortalAccess(ctx context.Context, actor domain.Actor, packageID string) ([]domain.CustomerPortalAccess, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return nil, err
	}
	packageID = strings.TrimSpace(packageID)
	l.mu.Lock()
	defer l.mu.Unlock()
	if packageID != "" {
		pkg, ok := l.customerPackages[packageID]
		if !ok || !l.currentPortalPackageLocked(actor.TenantID, pkg) {
			return nil, ErrNotFound
		}
		if !l.resourceAllowedLocked(actor, ScopePackageRead, resourceRefs{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}) {
			return nil, ErrForbidden
		}
	}
	accesses := []domain.CustomerPortalAccess{}
	for _, access := range l.portalAccess {
		if access.TenantID != actor.TenantID || (packageID != "" && access.PackageID != packageID) {
			continue
		}
		pkg, ok := l.customerPackages[access.PackageID]
		if !ok || !l.currentPortalPackageLocked(actor.TenantID, pkg) ||
			!l.resourceAllowedLocked(actor, ScopePackageRead, resourceRefs{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}) {
			continue
		}
		access.Hash = ""
		accesses = append(accesses, access)
	}
	sort.Slice(accesses, func(i, j int) bool {
		if accesses[i].CreatedAt.Equal(accesses[j].CreatedAt) {
			return accesses[i].ID < accesses[j].ID
		}
		return accesses[i].CreatedAt.Before(accesses[j].CreatedAt)
	})
	return accesses, nil
}

func (l *Ledger) currentPortalPackageLocked(tenantID string, pkg domain.CustomerSecurityPackage) bool {
	if pkg.TenantID != tenantID || pkg.ProductID == "" {
		return false
	}
	product, ok := l.products[pkg.ProductID]
	if !ok || product.TenantID != tenantID {
		return false
	}
	if pkg.ReleaseID != "" {
		release, ok := l.releases[pkg.ReleaseID]
		return ok && release.TenantID == tenantID && release.ProductID == pkg.ProductID
	}
	return true
}

func (l *Ledger) RevokeCustomerPortalAccess(ctx context.Context, actor domain.Actor, id string) (domain.CustomerPortalAccess, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerPortalAccess{}, err
	}
	if err := require(actor, ScopePackageWrite); err != nil {
		return domain.CustomerPortalAccess{}, err
	}
	id, err := packageapp.NormalizePortalAccessID(id)
	if err != nil {
		return domain.CustomerPortalAccess{}, fromPackageContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	access, ok := l.portalAccess[id]
	if !ok || access.TenantID != actor.TenantID {
		return domain.CustomerPortalAccess{}, ErrNotFound
	}
	if err := l.authorizePortalWriteLocked(ctx, actor, access.PackageID); err != nil {
		return domain.CustomerPortalAccess{}, err
	}
	if access.RevokedAt == nil {
		previous := access
		now := l.now()
		access.RevokedAt = &now
		if l.unitOfWork != nil {
			var entry domain.AuditChainEntry
			if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
				if err := repos.Identity.UpdateCustomerPortalAccess(ctx, previous, access); err != nil {
					return err
				}
				var err error
				entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, access.TenantID, "customer_portal_access.revoked", "customer_portal_access", access.ID, actorType(actor), actorID(actor), "", ""))
				return err
			}); err != nil {
				return domain.CustomerPortalAccess{}, err
			}
			l.portalAccess[id] = access
			l.publishCommittedAuditEntryLocked(entry)
			public := access
			public.Hash = ""
			return domain.CustomerPortalAccess(packageapp.ClonePortalAccess(packagedomain.CustomerPortalAccess(public))), nil
		}
		l.portalAccess[id] = access
		_, _ = l.appendChainLocked(access.TenantID, "customer_portal_access.revoked", "customer_portal_access", access.ID, actorType(actor), actorID(actor), "", "")
		if err := l.persistCriticalStateLocked(ctx); err != nil {
			return domain.CustomerPortalAccess{}, err
		}
	}
	access.Hash = ""
	return domain.CustomerPortalAccess(packageapp.ClonePortalAccess(packagedomain.CustomerPortalAccess(access))), nil
}

func (l *Ledger) AccessCustomerPortalPackage(ctx context.Context, token string) (domain.CustomerSecurityPackage, error) {
	return l.AccessCustomerPortalPackageWithAcceptance(ctx, token, CustomerPortalAcceptanceInput{})
}

func (l *Ledger) AccessCustomerPortalPackageWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (domain.CustomerSecurityPackage, error) {
	return l.accessCustomerPortalPackage(ctx, token, in, "customer_portal_package.accessed")
}

func (l *Ledger) accessCustomerPortalPackage(ctx context.Context, token string, in CustomerPortalAcceptanceInput, successEntryType string) (domain.CustomerSecurityPackage, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerSecurityPackage{}, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.CustomerSecurityPackage{}, ErrUnauthorized
	}
	prefix := secretPrefix(token)
	hash := l.hashSecret(token)
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, access := range l.portalAccess {
		if !secretHashEqual(access.Hash, hash) || access.RevokedAt != nil || !access.ExpiresAt.After(l.now()) {
			if access.Prefix == prefix && access.RevokedAt == nil && access.ExpiresAt.After(l.now()) {
				previous := access
				now := l.now()
				access.FailedAccessCount++
				if access.RevokedAt == nil && access.FailedAccessCount >= customerPortalFailedAccessLimit {
					access.RevokedAt = &now
				}
				access.LastFailedAt = &now
				effects := []customerPortalAuditEffect{{EntryType: "customer_portal_package.access_failed", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: "unverified"}}
				if access.RevokedAt != nil && access.FailedAccessCount == customerPortalFailedAccessLimit {
					effects = append(effects, customerPortalAuditEffect{EntryType: "customer_portal_access.revoked_after_failed_access", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: "unverified"})
				}
				if err := l.persistCustomerPortalAccessUpdateLocked(ctx, previous, access, effects); err != nil {
					return domain.CustomerSecurityPackage{}, ErrUnauthorized
				}
			}
			continue
		}
		pkg, ok := l.customerPackages[access.PackageID]
		if !ok || pkg.TenantID != access.TenantID || !pkg.ExpiresAt.After(l.now()) {
			return domain.CustomerSecurityPackage{}, ErrNotFound
		}
		if access.RequireNDA && access.NDAAcceptedAt == nil {
			acceptedBy := cleanExternalLabel(in.NDAAcceptedBy)
			if !in.NDAAccepted || acceptedBy == "" {
				if err := l.persistCustomerPortalAccessUpdateLocked(ctx, access, access, []customerPortalAuditEffect{{EntryType: "customer_portal_package.nda_required", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash}}); err != nil {
					return domain.CustomerSecurityPackage{}, err
				}
				return domain.CustomerSecurityPackage{}, ErrForbidden
			}
			now := l.now()
			access.NDAAcceptedAt = &now
			access.NDAAcceptedBy = acceptedBy
		}
		previous := l.portalAccess[id]
		access.AccessCount++
		now := l.now()
		access.LastAccessedAt = &now
		effects := []customerPortalAuditEffect{}
		if previous.NDAAcceptedAt == nil && access.NDAAcceptedAt != nil {
			effects = append(effects, customerPortalAuditEffect{EntryType: "customer_portal_package.nda_accepted", SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash})
		}
		effects = append(effects,
			customerPortalAuditEffect{EntryType: successEntryType, SubjectType: "customer_portal_access", SubjectID: access.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash},
			customerPortalAuditEffect{EntryType: successEntryType, SubjectType: "customer_security_package", SubjectID: pkg.ID, ActorID: access.ID, PayloadHash: pkg.ManifestHash},
		)
		if err := l.persistCustomerPortalAccessUpdateLocked(ctx, previous, access, effects); err != nil {
			return domain.CustomerSecurityPackage{}, err
		}
		return packageWithDistributionWatermark(pkg, access), nil
	}
	return domain.CustomerSecurityPackage{}, ErrUnauthorized
}

type customerPortalAuditEffect struct {
	EntryType   string
	SubjectType string
	SubjectID   string
	ActorID     string
	PayloadHash string
}

// persistCustomerPortalAccessUpdateLocked uses the previous counters and
// revocation state as an optimistic predicate. A token-dependent update is
// therefore committed with its audit trail or remains invisible on conflict.
func (l *Ledger) persistCustomerPortalAccessUpdateLocked(ctx context.Context, previous, current domain.CustomerPortalAccess, effects []customerPortalAuditEffect) error {
	if l.unitOfWork != nil {
		entries := []domain.AuditChainEntry{}
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.UpdateCustomerPortalAccess(ctx, previous, current); err != nil {
				return err
			}
			for _, effect := range effects {
				entry, err := repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(l.now(), current.TenantID, effect.EntryType, effect.SubjectType, effect.SubjectID, "customer_portal", effect.ActorID, effect.PayloadHash, ""))
				if err != nil {
					return err
				}
				entries = append(entries, entry)
			}
			return nil
		}); err != nil {
			return err
		}
		l.portalAccess[current.ID] = current
		for _, entry := range entries {
			l.publishCommittedAuditEntryLocked(entry)
		}
		return nil
	}
	l.portalAccess[current.ID] = current
	for _, effect := range effects {
		_, _ = l.appendChainLocked(current.TenantID, effect.EntryType, effect.SubjectType, effect.SubjectID, "customer_portal", effect.ActorID, effect.PayloadHash, "")
	}
	return l.persistCriticalStateLocked(ctx)
}

func prepareLocalPortalAccess(ctx context.Context, a domain.Actor, in CreateCustomerPortalAccessInput) (packageapp.CreatePortalAccessInput, error) {
	if err := packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return packageapp.CreatePortalAccessInput{}, fromIdentityContextError(err)
	}
	v, err := packageapp.NormalizePortalAccessInput(packageapp.CreatePortalAccessInput{PackageID: in.PackageID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: in.Watermark, ExpiresAt: in.ExpiresAt})
	return v, fromPackageContextError(err)
}

func (l *Ledger) authorizePortalWriteLocked(ctx context.Context, a domain.Actor, id string) error {
	pkg, ok := l.customerPackages[id]
	if !ok || !l.currentPortalPackageLocked(a.TenantID, pkg) {
		return ErrNotFound
	}
	refs := application.ResourceReferences{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}
	if err := packageapp.ValidatePortalPackageScope(a.TenantID, id, packageapp.PortalPackageScope{TenantID: pkg.TenantID, PackageID: pkg.ID, Resources: refs}); err != nil {
		return fromPackageContextError(err)
	}
	return fromIdentityContextError(packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: refs}))
}

func (l *Ledger) ExportCustomerPortalPackageArchive(ctx context.Context, token string) (CustomerPackageArchive, error) {
	return l.ExportCustomerPortalPackageArchiveWithAcceptance(ctx, token, CustomerPortalAcceptanceInput{})
}

func (l *Ledger) ExportCustomerPortalPackageArchiveWithAcceptance(ctx context.Context, token string, in CustomerPortalAcceptanceInput) (CustomerPackageArchive, error) {
	pkg, err := l.accessCustomerPortalPackage(ctx, token, in, "customer_portal_package.downloaded")
	if err != nil {
		return CustomerPackageArchive{}, err
	}
	return customerPackageArchive(pkg)
}

func packageWithDistributionWatermark(pkg domain.CustomerSecurityPackage, access domain.CustomerPortalAccess) domain.CustomerSecurityPackage {
	pkg.DistributionWatermark = packageDistributionWatermark(pkg, portalReviewerLabel(access.CustomerName, access.ReviewerName, access.ReviewerEmail), access.ID)
	if access.Watermark != "" {
		pkg.DistributionWatermark = access.Watermark
	}
	return pkg
}

func portalReviewerLabel(customerName, reviewerName, reviewerEmail string) string {
	if reviewerName != "" && reviewerEmail != "" {
		return reviewerName + " <" + reviewerEmail + ">"
	}
	if reviewerEmail != "" {
		return reviewerEmail
	}
	if reviewerName != "" {
		return reviewerName
	}
	return customerName
}

func packageDistributionWatermark(pkg domain.CustomerSecurityPackage, customerName, accessID string) string {
	customerName = cleanExternalLabel(customerName)
	accessID = strings.TrimSpace(accessID)
	if customerName == "" && accessID == "" {
		return "Evydence package " + pkg.ID + " exported for scoped review."
	}
	return cleanExternalLabel("Evydence package " + pkg.ID + " for " + customerName + " via access " + accessID + ".")
}

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const PortalFailedAccessLimit = 5

type PortalAcceptanceInput struct {
	NDAAccepted   bool
	NDAAcceptedBy string
}
type PortalAccessCandidate struct{ TenantID, AccessID string }
type PortalAccessLookup interface {
	LookupPortalAccess(context.Context, string) (PortalAccessCandidate, error)
}
type PortalTokenCredentials interface {
	HashPortalToken(string) string
	EqualPortalHashes(string, string) bool
}
type PortalTokenTransaction interface {
	ReadPortalAccessForToken(context.Context, string, string) (packagedomain.CustomerPortalAccess, error)
	ReadPortalPackageScope(context.Context, string, string) (PortalPackageScope, error)
	GetPortalPackageForUpdate(context.Context, string, string) (packagedomain.CustomerSecurityPackage, error)
	UpdatePortalTokenAccess(context.Context, packagedomain.CustomerPortalAccess, packagedomain.CustomerPortalAccess) error
	application.AuditAppender
}
type PortalTokenTransactions interface {
	ExecutePortalToken(context.Context, string, func(context.Context, PortalTokenTransaction) error) error
}
type PortalTokenCommandConfig struct {
	Lookup       PortalAccessLookup
	Transactions PortalTokenTransactions
	Credentials  PortalTokenCredentials
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PortalTokenCommands struct{ config PortalTokenCommandConfig }

func NewPortalTokenCommands(c PortalTokenCommandConfig) (*PortalTokenCommands, error) {
	if c.Lookup == nil || c.Transactions == nil || c.Credentials == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PortalTokenCommands{c}, nil
}
func NormalizePortalAcceptanceInput(in PortalAcceptanceInput) (PortalAcceptanceInput, error) {
	if !portalText(in.NDAAcceptedBy, MaxPortalAccessLabelBytes) {
		return in, ErrValidation
	}
	in.NDAAcceptedBy = cleanPortalLabel(in.NDAAcceptedBy)
	return in, nil
}

// Denial counters and NDA-required audit events deliberately commit before
// returning a semantic 401/403. Storage, audit, and commit failures instead roll
// back every effect and never publish a package or a successful access result.
func (s *PortalTokenCommands) AccessPortalPackage(ctx context.Context, token string, in PortalAcceptanceInput, download bool) (packagedomain.CustomerSecurityPackage, error) {
	var empty packagedomain.CustomerSecurityPackage
	if s == nil {
		return empty, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return empty, err
	}
	if !portalText(token, MaxPortalAccessIDBytes) {
		return empty, application.ErrUnauthorized
	}
	token = strings.TrimSpace(token)
	if len(token) < 12 || !strings.HasPrefix(token, "evycp_") {
		return empty, application.ErrUnauthorized
	}
	in, err := NormalizePortalAcceptanceInput(in)
	if err != nil {
		return empty, err
	}
	candidate, err := s.config.Lookup.LookupPortalAccess(ctx, token[:12])
	if err != nil {
		return empty, err
	}
	if !portalID(candidate.TenantID) || !portalID(candidate.AccessID) {
		return empty, application.ErrUnauthorized
	}
	var out packagedomain.CustomerSecurityPackage
	var outcome error
	err = s.config.Transactions.ExecutePortalToken(ctx, candidate.TenantID, func(ctx context.Context, tx PortalTokenTransaction) error {
		if tx == nil {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		v, err := tx.ReadPortalAccessForToken(ctx, candidate.TenantID, candidate.AccessID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				outcome = application.ErrUnauthorized
				return nil
			}
			return err
		}
		if v.TenantID != candidate.TenantID || v.ID != candidate.AccessID || v.Prefix != token[:12] {
			outcome = application.ErrUnauthorized
			return nil
		}
		if err := ValidatePortalAccessProjection(v); err != nil {
			return err
		}
		if raw, err := hex.DecodeString(v.Hash); err != nil || len(raw) != 32 {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !portalTime(now) {
			return ErrValidation
		}
		if v.RevokedAt != nil || !v.ExpiresAt.After(now) {
			outcome = application.ErrUnauthorized
			return nil
		}
		if !s.config.Credentials.EqualPortalHashes(v.Hash, s.config.Credentials.HashPortalToken(token)) {
			if v.FailedAccessCount >= math.MaxInt32 {
				return ErrConflict
			}
			updated := ClonePortalAccess(v)
			updated.FailedAccessCount++
			updated.LastFailedAt = &now
			if updated.FailedAccessCount >= PortalFailedAccessLimit {
				updated.RevokedAt = &now
			}
			if err := tx.UpdatePortalTokenAccess(ctx, v, updated); err != nil {
				return err
			}
			if err := s.audit(ctx, tx, v, "customer_portal_package.access_failed", "customer_portal_access", v.ID, "unverified", "", now); err != nil {
				return err
			}
			if updated.RevokedAt != nil {
				if err := s.audit(ctx, tx, v, "customer_portal_access.revoked_after_failed_access", "customer_portal_access", v.ID, "unverified", "", now); err != nil {
					return err
				}
			}
			outcome = application.ErrUnauthorized
			return ctx.Err()
		}
		scope, err := tx.ReadPortalPackageScope(ctx, v.TenantID, v.PackageID)
		if err != nil {
			return err
		}
		if err := ValidatePortalPackageScope(v.TenantID, v.PackageID, scope); err != nil {
			return err
		}
		pkg, err := tx.GetPortalPackageForUpdate(ctx, v.TenantID, v.PackageID)
		if err != nil {
			return err
		}
		if pkg.ID != v.PackageID || pkg.TenantID != v.TenantID || pkg.ProductID != scope.Resources.ProductID || pkg.ReleaseID != scope.Resources.ReleaseID {
			return ErrNotFound
		}
		now = s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !portalTime(now) {
			return ErrValidation
		}
		if !v.ExpiresAt.After(now) {
			outcome = application.ErrUnauthorized
			return nil
		}
		if !pkg.ExpiresAt.After(now) {
			return ErrNotFound
		}
		if v.RequireNDA && v.NDAAcceptedAt == nil && (!in.NDAAccepted || in.NDAAcceptedBy == "") {
			if err := s.audit(ctx, tx, v, "customer_portal_package.nda_required", "customer_portal_access", v.ID, v.ID, pkg.ManifestHash, now); err != nil {
				return err
			}
			outcome = application.ErrForbidden
			return ctx.Err()
		}
		if v.AccessCount >= math.MaxInt32 {
			return ErrConflict
		}
		updated := ClonePortalAccess(v)
		updated.AccessCount++
		updated.LastAccessedAt = &now
		if v.RequireNDA && v.NDAAcceptedAt == nil {
			updated.NDAAcceptedAt = &now
			updated.NDAAcceptedBy = in.NDAAcceptedBy
		}
		if err := tx.UpdatePortalTokenAccess(ctx, v, updated); err != nil {
			return err
		}
		if v.NDAAcceptedAt == nil && updated.NDAAcceptedAt != nil {
			if err := s.audit(ctx, tx, v, "customer_portal_package.nda_accepted", "customer_portal_access", v.ID, v.ID, pkg.ManifestHash, now); err != nil {
				return err
			}
		}
		entry := "customer_portal_package.accessed"
		if download {
			entry = "customer_portal_package.downloaded"
		}
		for _, subject := range []struct{ kind, id string }{{"customer_portal_access", v.ID}, {"customer_security_package", pkg.ID}} {
			if err := s.audit(ctx, tx, v, entry, subject.kind, subject.id, v.ID, pkg.ManifestHash, now); err != nil {
				return err
			}
		}
		out = cloneCustomerSecurityPackage(pkg)
		out.DistributionWatermark = v.Watermark
		if out.DistributionWatermark == "" {
			out.DistributionWatermark = PortalDistributionWatermark(CreatePortalAccessInput{PackageID: v.PackageID, CustomerName: v.CustomerName, ReviewerName: v.ReviewerName, ReviewerEmail: v.ReviewerEmail}, v.ID)
		}
		return ctx.Err()
	})
	if err != nil {
		return empty, err
	}
	if outcome != nil {
		return empty, outcome
	}
	return cloneCustomerSecurityPackage(out), nil
}
func (s *PortalTokenCommands) audit(ctx context.Context, tx PortalTokenTransaction, v packagedomain.CustomerPortalAccess, entry, kind, id, actor, hash string, now time.Time) error {
	e := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: v.TenantID, EntryType: entry, SubjectType: kind, SubjectID: id, ActorType: "customer_portal", ActorID: actor, PayloadHash: hash, OccurredAt: now}
	if !portalID(e.ID) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, e)
	return err
}
func ValidatePortalAccessProjection(v packagedomain.CustomerPortalAccess) error {
	if !portalID(v.ID) || !portalID(v.TenantID) || !portalID(v.PackageID) || !portalText(v.Prefix, 12) || len(v.Prefix) != 12 || !strings.HasPrefix(v.Prefix, "evycp_") || !portalID(v.SchemaVersion) || !portalTime(v.ExpiresAt) || !portalTime(v.CreatedAt) || v.AccessCount < 0 || v.FailedAccessCount < 0 || v.AccessCount > math.MaxInt32 || v.FailedAccessCount > math.MaxInt32 {
		return ErrConflict
	}
	for _, label := range []string{v.CustomerName, v.ReviewerName, v.ReviewerEmail, v.NDAAcceptedBy, v.Watermark} {
		if !portalText(label, MaxPortalAccessLabelBytes) {
			return ErrConflict
		}
	}
	for _, at := range []*time.Time{v.RevokedAt, v.NDAAcceptedAt, v.LastAccessedAt, v.LastFailedAt} {
		if at != nil && !portalTime(*at) {
			return ErrConflict
		}
	}
	return nil
}

// Only monotonic access/failure counters, first NDA acceptance and revocation
// may change. Package identity, recipient labels and token material are immutable.
func ValidatePortalTokenTransition(previous, current packagedomain.CustomerPortalAccess) error {
	if ValidatePortalAccessProjection(previous) != nil || ValidatePortalAccessProjection(current) != nil || previous.RevokedAt != nil || len(previous.Hash) != 64 {
		return ErrValidation
	}
	old, v := ClonePortalAccess(previous), ClonePortalAccess(current)
	old.AccessCount, old.FailedAccessCount, v.AccessCount, v.FailedAccessCount = 0, 0, 0, 0
	old.RevokedAt, old.LastAccessedAt, old.LastFailedAt, old.NDAAcceptedAt = nil, nil, nil, nil
	v.RevokedAt, v.LastAccessedAt, v.LastFailedAt, v.NDAAcceptedAt = nil, nil, nil, nil
	old.NDAAcceptedBy, v.NDAAcceptedBy = "", ""
	if !reflect.DeepEqual(old, v) {
		return ErrValidation
	}
	if previous.NDAAcceptedAt != nil && (!reflect.DeepEqual(previous.NDAAcceptedAt, current.NDAAcceptedAt) || previous.NDAAcceptedBy != current.NDAAcceptedBy) {
		return ErrValidation
	}
	if current.NDAAcceptedAt != nil && (!current.RequireNDA || current.NDAAcceptedBy == "") {
		return ErrValidation
	}
	if current.NDAAcceptedAt == nil && current.NDAAcceptedBy != "" {
		return ErrValidation
	}
	access := current.AccessCount == previous.AccessCount+1 && current.FailedAccessCount == previous.FailedAccessCount
	failure := current.FailedAccessCount == previous.FailedAccessCount+1 && current.AccessCount == previous.AccessCount
	if !access && !failure {
		return ErrValidation
	}
	if access && (current.LastAccessedAt == nil || current.RevokedAt != nil || !reflect.DeepEqual(previous.LastFailedAt, current.LastFailedAt)) {
		return ErrValidation
	}
	if failure && (current.LastFailedAt == nil || !reflect.DeepEqual(previous.LastAccessedAt, current.LastAccessedAt) || !reflect.DeepEqual(previous.NDAAcceptedAt, current.NDAAcceptedAt) || previous.NDAAcceptedBy != current.NDAAcceptedBy || (current.FailedAccessCount >= PortalFailedAccessLimit) != (current.RevokedAt != nil)) {
		return ErrValidation
	}
	if previous.LastAccessedAt != nil && current.LastAccessedAt != nil && current.LastAccessedAt.Before(*previous.LastAccessedAt) || previous.LastFailedAt != nil && current.LastFailedAt != nil && current.LastFailedAt.Before(*previous.LastFailedAt) {
		return ErrValidation
	}
	return nil
}

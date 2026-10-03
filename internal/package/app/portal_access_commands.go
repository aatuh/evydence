package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxPortalAccessIDBytes    = 1024
	MaxPortalAccessLabelBytes = 640
)

type CreatePortalAccessInput struct {
	PackageID, CustomerName, ReviewerName, ReviewerEmail, Watermark string
	RequireNDA                                                      bool
	ExpiresAt                                                       time.Time
}
type PortalCredential struct{ Secret, Prefix, Hash string }
type PortalCredentialIssuer interface {
	GeneratePortalCredential() (PortalCredential, error)
}

// Scope reads contain ownership coordinates only, never package manifests,
// redacted evidence, signing material, or existing portal token hashes.
type PortalPackageScope struct {
	TenantID, PackageID string
	Resources           application.ResourceReferences
}
type PortalAccessWriteReader interface {
	ReadPortalPackageScope(context.Context, string, string) (PortalPackageScope, error)
	ReadPortalAccessForRevocation(context.Context, string, string) (packagedomain.CustomerPortalAccess, error)
}
type PortalAccessTransaction interface {
	PortalAccessWriteReader
	InsertPortalAccess(context.Context, packagedomain.CustomerPortalAccess) error
	RevokePortalAccess(context.Context, string, string, time.Time) error
	application.Authorizer
	application.AuditAppender
}
type PortalAccessTransactions interface {
	ExecutePortalAccess(context.Context, string, func(context.Context, PortalAccessTransaction) error) error
}
type PortalAccessCommandConfig struct {
	Transactions PortalAccessTransactions
	Credentials  PortalCredentialIssuer
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PortalAccessCommands struct{ config PortalAccessCommandConfig }

func NewPortalAccessCommands(c PortalAccessCommandConfig) (*PortalAccessCommands, error) {
	if c.Transactions == nil || c.Credentials == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PortalAccessCommands{config: c}, nil
}
func portalText(v string, limit int) bool {
	return len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func portalID(v string) bool {
	return v != "" && strings.TrimSpace(v) == v && portalText(v, MaxPortalAccessIDBytes)
}
func portalTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }

func NormalizePortalAccessID(id string) (string, error) {
	if !portalText(id, MaxPortalAccessIDBytes) {
		return "", ErrValidation
	}
	id = strings.TrimSpace(id)
	if !portalID(id) {
		return "", ErrValidation
	}
	return id, nil
}

// Preserve the historical 160-rune/control-character label normalization,
// while bounding raw input before allocating or silently trimming it.
func cleanPortalLabel(v string) string {
	runes := make([]rune, 0, 160)
	for _, r := range strings.TrimSpace(v) {
		if r < 32 || r == 127 {
			continue
		}
		runes = append(runes, r)
		if len(runes) == 160 {
			break
		}
	}
	return strings.TrimSpace(string(runes))
}
func NormalizePortalAccessInput(in CreatePortalAccessInput) (CreatePortalAccessInput, error) {
	if !portalText(in.PackageID, MaxPortalAccessIDBytes) || !portalTime(in.ExpiresAt.UTC()) {
		return in, ErrValidation
	}
	for _, v := range []string{in.CustomerName, in.ReviewerName, in.ReviewerEmail, in.Watermark} {
		if !portalText(v, MaxPortalAccessLabelBytes) {
			return in, ErrValidation
		}
	}
	in.PackageID = strings.TrimSpace(in.PackageID)
	in.CustomerName, in.ReviewerName = cleanPortalLabel(in.CustomerName), cleanPortalLabel(in.ReviewerName)
	in.ReviewerEmail, in.Watermark = strings.ToLower(cleanPortalLabel(in.ReviewerEmail)), cleanPortalLabel(in.Watermark)
	in.ExpiresAt = in.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !portalID(in.PackageID) || in.CustomerName == "" {
		return in, ErrValidation
	}
	if in.ReviewerEmail != "" {
		at := strings.IndexByte(in.ReviewerEmail, '@')
		if strings.ContainsAny(in.ReviewerEmail, " \t\r\n") || at <= 0 || at >= len(in.ReviewerEmail)-1 || !strings.Contains(in.ReviewerEmail[at+1:], ".") {
			return in, ErrValidation
		}
	}
	return in, nil
}
func ValidatePortalPackageScope(tenant, id string, s PortalPackageScope) error {
	r := s.Resources
	if s.TenantID != tenant || s.PackageID != id || !portalID(tenant) || !portalID(id) || !portalID(r.ProductID) || r.CustomerPackageID != id || r.ReleaseID != "" && !portalID(r.ReleaseID) || r != (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: r.ReleaseID, CustomerPackageID: id}) {
		return ErrNotFound
	}
	return nil
}
func (s *PortalAccessCommands) prepare(ctx context.Context, a identitydomain.Actor) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return err
	}
	if !portalID(a.TenantID) || !portalID(auditActorID(a)) {
		return ErrValidation
	}
	return nil
}
func (s *PortalAccessCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, PortalAccessTransaction) error) error {
	return s.config.Transactions.ExecutePortalAccess(ctx, a.TenantID, func(ctx context.Context, tx PortalAccessTransaction) error {
		if tx == nil {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func authorizePortalPackage(ctx context.Context, tx PortalAccessTransaction, a identitydomain.Actor, id string) error {
	scope, err := tx.ReadPortalPackageScope(ctx, a.TenantID, id)
	if err != nil {
		return err
	}
	if err = ValidatePortalPackageScope(a.TenantID, id, scope); err != nil {
		return err
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: scope.Resources})
}
func (s *PortalAccessCommands) AuthorizeCreatePortalAccess(ctx context.Context, a identitydomain.Actor, in CreatePortalAccessInput) error {
	if err := s.prepare(ctx, a); err != nil {
		return err
	}
	in, err := NormalizePortalAccessInput(in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx PortalAccessTransaction) error {
		return authorizePortalPackage(ctx, tx, a, in.PackageID)
	})
}
func (s *PortalAccessCommands) CreatePortalAccess(ctx context.Context, a identitydomain.Actor, in CreatePortalAccessInput) (packagedomain.CustomerPortalAccess, string, error) {
	var empty packagedomain.CustomerPortalAccess
	if err := s.prepare(ctx, a); err != nil {
		return empty, "", err
	}
	in, err := NormalizePortalAccessInput(in)
	if err != nil {
		return empty, "", err
	}
	var out packagedomain.CustomerPortalAccess
	var secret string
	err = s.execute(ctx, a, func(ctx context.Context, tx PortalAccessTransaction) error {
		if err := authorizePortalPackage(ctx, tx, a, in.PackageID); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !portalTime(now) || !in.ExpiresAt.After(now) {
			return ErrValidation
		}
		credential, err := s.config.Credentials.GeneratePortalCredential()
		if err != nil {
			return err
		}
		if !validPortalCredential(credential) {
			return ErrValidation
		}
		out = packagedomain.CustomerPortalAccess{ID: s.config.IDs.NewID("cpa"), TenantID: a.TenantID, PackageID: in.PackageID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: in.Watermark, Prefix: credential.Prefix, Hash: credential.Hash, ExpiresAt: in.ExpiresAt, SchemaVersion: packagedomain.CustomerPortalAccessVersion, CreatedAt: now}
		if out.Watermark == "" {
			out.Watermark = PortalDistributionWatermark(in, out.ID)
		}
		if err := ValidatePortalAccessCreation(out); err != nil {
			return err
		}
		if err := tx.InsertPortalAccess(ctx, out); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, a, "customer_portal_access.created", "customer_security_package", in.PackageID, now); err != nil {
			return err
		}
		secret = credential.Secret
		return nil
	})
	if err != nil {
		return empty, "", err
	}
	out.Hash = ""
	return ClonePortalAccess(out), secret, nil
}
func PortalDistributionWatermark(in CreatePortalAccessInput, id string) string {
	label := in.CustomerName
	switch {
	case in.ReviewerName != "" && in.ReviewerEmail != "":
		label = in.ReviewerName + " <" + in.ReviewerEmail + ">"
	case in.ReviewerEmail != "":
		label = in.ReviewerEmail
	case in.ReviewerName != "":
		label = in.ReviewerName
	}
	return cleanPortalLabel("Evydence package " + in.PackageID + " for " + cleanPortalLabel(label) + " via access " + strings.TrimSpace(id) + ".")
}
func validPortalCredential(c PortalCredential) bool {
	if len(c.Secret) != 49 || !strings.HasPrefix(c.Secret, "evycp_") || len(c.Prefix) != 12 || c.Prefix != c.Secret[:12] || len(c.Hash) != 64 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Secret[6:])
	if err != nil || len(raw) != 32 {
		return false
	}
	hash, err := hex.DecodeString(c.Hash)
	return err == nil && len(hash) == 32
}
func ValidatePortalAccessCreation(v packagedomain.CustomerPortalAccess) error {
	in, err := NormalizePortalAccessInput(CreatePortalAccessInput{PackageID: v.PackageID, CustomerName: v.CustomerName, ReviewerName: v.ReviewerName, ReviewerEmail: v.ReviewerEmail, Watermark: v.Watermark, RequireNDA: v.RequireNDA, ExpiresAt: v.ExpiresAt})
	if err != nil || in.PackageID != v.PackageID || in.CustomerName != v.CustomerName || in.ReviewerName != v.ReviewerName || in.ReviewerEmail != v.ReviewerEmail || in.Watermark != v.Watermark || !portalID(v.ID) || !portalID(v.TenantID) || len(v.Prefix) != 12 || !strings.HasPrefix(v.Prefix, "evycp_") || len(v.Hash) != 64 || !portalTime(v.CreatedAt) || !v.ExpiresAt.After(v.CreatedAt) || v.SchemaVersion != packagedomain.CustomerPortalAccessVersion || v.RevokedAt != nil || v.NDAAcceptedAt != nil || v.NDAAcceptedBy != "" || v.AccessCount != 0 || v.FailedAccessCount != 0 || v.LastAccessedAt != nil || v.LastFailedAt != nil {
		return ErrValidation
	}
	if raw, err := hex.DecodeString(v.Hash); err != nil || len(raw) != 32 {
		return ErrValidation
	}
	return nil
}
func (s *PortalAccessCommands) appendAudit(ctx context.Context, tx PortalAccessTransaction, a identitydomain.Actor, entry, kind, id string, now time.Time) error {
	e := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: entry, SubjectType: kind, SubjectID: id, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now}
	if !portalID(e.ID) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, e)
	return err
}
func (s *PortalAccessCommands) revocation(ctx context.Context, a identitydomain.Actor, id string, write bool) (packagedomain.CustomerPortalAccess, error) {
	var empty packagedomain.CustomerPortalAccess
	if err := s.prepare(ctx, a); err != nil {
		return empty, err
	}
	id, err := NormalizePortalAccessID(id)
	if err != nil {
		return empty, err
	}
	var out packagedomain.CustomerPortalAccess
	err = s.execute(ctx, a, func(ctx context.Context, tx PortalAccessTransaction) error {
		v, err := tx.ReadPortalAccessForRevocation(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if v.ID != id || v.TenantID != a.TenantID || !portalID(v.PackageID) || v.Hash != "" {
			return ErrNotFound
		}
		if err := ValidatePortalAccessProjection(v); err != nil {
			return err
		}
		if err := authorizePortalPackage(ctx, tx, a, v.PackageID); err != nil {
			return err
		}
		out = ClonePortalAccess(v)
		if !write || v.RevokedAt != nil {
			return nil
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !portalTime(now) {
			return ErrValidation
		}
		if err := tx.RevokePortalAccess(ctx, a.TenantID, id, now); err != nil {
			return err
		}
		out.RevokedAt = &now
		return s.appendAudit(ctx, tx, a, "customer_portal_access.revoked", "customer_portal_access", id, now)
	})
	if err != nil {
		return empty, err
	}
	return ClonePortalAccess(out), nil
}
func (s *PortalAccessCommands) AuthorizeRevokePortalAccess(ctx context.Context, a identitydomain.Actor, id string) error {
	_, err := s.revocation(ctx, a, id, false)
	return err
}
func (s *PortalAccessCommands) RevokePortalAccess(ctx context.Context, a identitydomain.Actor, id string) (packagedomain.CustomerPortalAccess, error) {
	return s.revocation(ctx, a, id, true)
}

func ClonePortalAccess(v packagedomain.CustomerPortalAccess) packagedomain.CustomerPortalAccess {
	for _, p := range []**time.Time{&v.NDAAcceptedAt, &v.RevokedAt, &v.LastAccessedAt, &v.LastFailedAt} {
		if *p != nil {
			at := **p
			*p = &at
		}
	}
	return v
}

package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// EvidenceBundleScopeTransaction reads only identity/ownership coordinates.
// Tenant locking must acquire the common writer fence before ownership locks.
type EvidenceBundleScopeTransaction interface {
	LockEvidenceBundleTenant(context.Context, string) error
	LockEvidenceBundleRelease(context.Context, string, string) (string, error)
	LockEvidenceBundleEvidence(context.Context, string, string) (application.ResourceReferences, error)
}

// NormalizeEvidenceBundleSelection bounds raw IDs before copying or deduping.
// The snapshot bound also covers server-selected IDs on completed replay.
func NormalizeEvidenceBundleSelection(release string, ids []string) (string, []string, error) {
	valid := func(v string) bool { return len(v) <= 1024 && utf8.ValidString(v) && !strings.ContainsRune(v, 0) }
	if !valid(release) || len(ids) > MaxBundleSnapshotRows {
		return "", nil, ErrValidation
	}
	for _, id := range ids {
		if !valid(id) || strings.TrimSpace(id) == "" {
			return "", nil, ErrValidation
		}
	}
	values, err := normalizedNonEmptyStrings(ids, true)
	return strings.TrimSpace(release), values, err
}

func (s *ExportCommands) AuthorizeEvidenceBundleExport(ctx context.Context, a identitydomain.Actor, release string, ids []string) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:read", ScopeOnly: true}); err != nil {
		return err
	}
	if err := validateReportTemplateTenant(a); err != nil {
		return err
	}
	release, ids, err := NormalizeEvidenceBundleSelection(release, ids)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteEvidenceBundleExport(ctx, func(ctx context.Context, tx ExportTransaction) error {
		scope, ok := tx.(EvidenceBundleScopeTransaction)
		if !ok {
			return ErrValidation
		}
		if err := scope.LockEvidenceBundleTenant(ctx, a.TenantID); err != nil {
			return err
		}
		if release != "" {
			product, err := scope.LockEvidenceBundleRelease(ctx, a.TenantID, release)
			if err != nil {
				return err
			}
			if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:read", Resources: application.ResourceReferences{ProductID: product, ReleaseID: release}}); err != nil {
				return err
			}
		}
		for _, id := range ids {
			refs, err := scope.LockEvidenceBundleEvidence(ctx, a.TenantID, id)
			if err != nil {
				return err
			}
			if release != "" && refs.ReleaseID != release {
				return ErrNotFound
			}
			if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:read", Resources: refs}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Replay authorizes the saved IDs, never a new snapshot or signing lifecycle.
func (s *ExportCommands) AuthorizeEvidenceBundleReplay(ctx context.Context, a identitydomain.Actor, release string, ids []string) error {
	return s.AuthorizeEvidenceBundleExport(ctx, a, release, ids)
}

package app

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const MaxPortableBundleReferences = 1024
const MaxPortableBundleManifestBytes = 64 << 10

type BundleImportScopeLocker interface {
	LockBundleImportTenant(context.Context, string) error
}

// ValidatePortableBundleInput bounds the portable input before copying or
// hashing. Source IDs remain labels; only the target actor grants authority.
func ValidatePortableBundleInput(b packagedomain.EvidenceBundle) error {
	valid := func(v string, max int) bool {
		return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
	}
	for _, v := range []string{b.ID, b.TenantID, b.ReleaseID} {
		if !valid(v, 1024) {
			return ErrValidation
		}
	}
	if !valid(b.ManifestHash, 128) || strings.TrimSpace(b.ManifestHash) == "" || !valid(b.SchemaVersion, 65536) || !valid(b.VerificationText, 65536) || len(b.EvidenceIDs) > MaxPortableBundleReferences || len(b.SignatureRefs) > MaxPortableBundleReferences {
		return ErrValidation
	}
	for _, values := range [][]string{b.EvidenceIDs, b.SignatureRefs} {
		for _, v := range values {
			if !valid(v, 1024) || strings.TrimSpace(v) == "" {
				return ErrValidation
			}
		}
	}
	if len(b.Manifest) == 0 {
		return ErrValidation
	}
	raw, err := json.Marshal(b.Manifest)
	if err != nil || len(raw) > MaxPortableBundleManifestBytes || jsonbounds.Validate(raw, jsonbounds.DefaultLimits()) != nil {
		return ErrValidation
	}
	var rawIDs []string
	switch v := b.Manifest["evidence_ids"].(type) {
	case []string:
		rawIDs = v
	case []any:
		if len(v) > MaxPortableBundleReferences {
			return ErrValidation
		}
		for _, value := range v {
			str, ok := value.(string)
			if !ok {
				return ErrValidation
			}
			rawIDs = append(rawIDs, str)
		}
	default:
		return ErrValidation
	}
	if len(rawIDs) > MaxPortableBundleReferences {
		return ErrValidation
	}
	for _, id := range rawIDs {
		if !valid(id, 1024) || strings.TrimSpace(id) == "" {
			return ErrValidation
		}
	}
	if _, ok := evidenceIDsFromManifest(b.Manifest["evidence_ids"]); !ok {
		return ErrValidation
	}
	return nil
}

func (s *ImportCommands) AuthorizeBundleImport(ctx context.Context, a identitydomain.Actor, b packagedomain.EvidenceBundle) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateActor(a); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:write", TenantWide: true}); err != nil {
		return err
	}
	if err := validateReportTemplateTenant(a); err != nil {
		return err
	}
	if err := ValidatePortableBundleInput(b); err != nil {
		return err
	}
	return s.config.Transactions.ExecuteBundleImport(ctx, func(ctx context.Context, tx ImportTransaction) error {
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "bundle:write", TenantWide: true}); err != nil {
			return err
		}
		guard, ok := tx.(BundleImportScopeLocker)
		if !ok {
			return ErrValidation
		}
		return guard.LockBundleImportTenant(ctx, a.TenantID)
	})
}

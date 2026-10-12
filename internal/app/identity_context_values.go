package app

import (
	"errors"
	"reflect"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// These detached value mappings and stateless comparisons are shared by native
// wiring and remaining compatibility boundaries. They own no Ledger state.
func sameSSOProviderTrustState(left, right domain.SSOProvider) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.Type == right.Type &&
		left.Issuer == right.Issuer &&
		left.ClientID == right.ClientID &&
		left.Status == right.Status &&
		reflect.DeepEqual(left.JWKS, right.JWKS) &&
		reflect.DeepEqual(left.SAMLSigningCertificates, right.SAMLSigningCertificates) &&
		equalOptionalTime(left.TrustMaterialUpdatedAt, right.TrustMaterialUpdatedAt)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func ssoProviderToIdentityContext(value domain.SSOProvider) identitydomain.SSOProvider {
	return identitydomain.SSOProvider{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Issuer: value.Issuer,
		ClientID: value.ClientID, GroupsClaim: value.GroupsClaim, RoleMapping: cloneStringMap(value.RoleMapping),
		JWKS: cloneIdentityAnyMap(value.JWKS), SAMLSigningCertificates: append([]string(nil), value.SAMLSigningCertificates...),
		TrustMaterialUpdatedAt: cloneTimePtr(value.TrustMaterialUpdatedAt), Status: value.Status,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ssoProviderFromIdentityContext(value identitydomain.SSOProvider) domain.SSOProvider {
	return domain.SSOProvider{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Issuer: value.Issuer,
		ClientID: value.ClientID, GroupsClaim: value.GroupsClaim, RoleMapping: cloneStringMap(value.RoleMapping),
		JWKS: cloneIdentityAnyMap(value.JWKS), SAMLSigningCertificates: append([]string(nil), value.SAMLSigningCertificates...),
		TrustMaterialUpdatedAt: cloneTimePtr(value.TrustMaterialUpdatedAt), Status: value.Status,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func verificationChecksToIdentityContext(values []domain.VerifyCheck) []identitydomain.VerificationCheck {
	result := make([]identitydomain.VerificationCheck, 0, len(values))
	for _, value := range values {
		result = append(result, identitydomain.VerificationCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func verificationChecksFromIdentityContext(values []identitydomain.VerificationCheck) []domain.VerifyCheck {
	result := make([]domain.VerifyCheck, 0, len(values))
	for _, value := range values {
		result = append(result, domain.VerifyCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func providerVerificationToIdentityContext(value domain.ProviderVerification) identitydomain.ProviderVerification {
	return identitydomain.ProviderVerification{
		ID: value.ID, TenantID: value.TenantID, ProviderType: value.ProviderType, ProviderID: value.ProviderID,
		Subject: value.Subject, Result: value.Result, Checks: verificationChecksToIdentityContext(value.Checks),
		Profile: identitydomain.VerificationProfileSnapshot{
			ID: value.Profile.ID, Version: value.Profile.Version,
			RequiredChecks: append([]string(nil), value.Profile.RequiredChecks...),
			TrustMaterial:  append([]string(nil), value.Profile.TrustMaterial...), IdentityPolicy: value.Profile.IdentityPolicy,
			TransparencyProof: value.Profile.TransparencyProof, PayloadScope: value.Profile.PayloadScope,
			PayloadDigest: value.Profile.PayloadDigest, Limitations: append([]string(nil), value.Profile.Limitations...),
		},
		Limitations: append([]string(nil), value.Limitations...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func providerVerificationFromIdentityContext(value identitydomain.ProviderVerification) domain.ProviderVerification {
	return ProviderVerificationFromIdentity(value)
}

// ProviderVerificationFromIdentity maps the context-owned record to the
// existing public/persistence DTO, including its JSON names and assurance
// profile. It copies slices and has no Ledger or repository dependency.
func ProviderVerificationFromIdentity(value identitydomain.ProviderVerification) domain.ProviderVerification {
	return domain.ProviderVerification{
		ID: value.ID, TenantID: value.TenantID, ProviderType: value.ProviderType, ProviderID: value.ProviderID,
		Subject: value.Subject, Result: value.Result, Checks: verificationChecksFromIdentityContext(value.Checks),
		Profile: domain.VerificationProfile{
			ID: value.Profile.ID, Version: value.Profile.Version,
			RequiredChecks: append([]string(nil), value.Profile.RequiredChecks...),
			TrustMaterial:  append([]string(nil), value.Profile.TrustMaterial...), IdentityPolicy: value.Profile.IdentityPolicy,
			TransparencyProof: value.Profile.TransparencyProof, PayloadScope: value.Profile.PayloadScope,
			PayloadDigest: value.Profile.PayloadDigest, Limitations: append([]string(nil), value.Profile.Limitations...),
		},
		Limitations: append([]string(nil), value.Limitations...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func fromIdentityContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, identityapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, identityapp.ErrUnauthorized), errors.Is(err, application.ErrUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, identityapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, identityapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, identityapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, identityapp.ErrVerificationFailed):
		return ErrVerificationFailed
	default:
		return err
	}
}

func cloneSigningKeyMap(values map[string]domain.SigningKey) map[string]domain.SigningKey {
	result := make(map[string]domain.SigningKey, len(values))
	for id, value := range values {
		value.Private = append([]byte(nil), value.Private...)
		value.ValidUntil = cloneTimePtr(value.ValidUntil)
		value.RevokedAt = cloneTimePtr(value.RevokedAt)
		value.CompromisedAt = cloneTimePtr(value.CompromisedAt)
		result[id] = value
	}
	return result
}

func cloneIdentityAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = cloneIdentityAny(value)
	}
	return result
}

func cloneIdentityAny(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneIdentityAnyMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneIdentityAny(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	default:
		return typed
	}
}

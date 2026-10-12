package app

import (
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Provider registration and trust rotation publish public metadata, not credentials.
// Preserve harmless group identifiers such as token-reviewers only inside
// this versioned DTO. Generic logs/packages keep their existing denylist.
func publicSSOProviderReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	var p domain.SSOProvider
	if json.Unmarshal(encoded, &p) != nil || p.SchemaVersion != domain.SSOProviderSchemaVersion || p.Status != "active" || p.CreatedAt.IsZero() || p.TrustMaterialUpdatedAt != nil && p.TrustMaterialUpdatedAt.IsZero() || p.RoleMapping == nil {
		return nil, false
	}
	for _, id := range []string{p.ID, p.TenantID} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.ClientID) == "" || p.Issuer == "" || p.Type != "oidc" && p.Type != "saml" {
		return nil, false
	}
	for _, v := range []string{p.Name, p.ClientID, p.Issuer, p.GroupsClaim} {
		if !validPublicMembershipText(v, 65536) {
			return nil, false
		}
	}
	encoded, err = json.Marshal(p.RoleMapping)
	if err != nil || len(encoded) > 65536 {
		return nil, false
	}
	trust := identityapp.PublicTrustMaterialValidator{}
	p.JWKS, err = trust.NormalizeJWKS(p.JWKS)
	if err != nil {
		return nil, false
	}
	p.SAMLSigningCertificates, err = trust.NormalizeSAMLSigningCertificates(p.SAMLSigningCertificates)
	if err != nil {
		return nil, false
	}
	roles := make(map[string]any, len(p.RoleMapping))
	for group, role := range p.RoleMapping {
		if validPublicMembershipText(group, 65536) && validPublicMembershipText(role, 65536) && redaction.RedactString(group) == group && redaction.RedactString(role) == role {
			roles[group] = role
		}
	}
	encoded, err = json.Marshal(p)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	if json.Unmarshal(encoded, &projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	result := safe.(map[string]any)
	result["role_mapping"] = roles
	// Diagnostic redaction flattens line breaks. Only the parsed, normalized
	// public certificate can bypass that transformation; arbitrary PEM input
	// and trailing private blocks never reach this versioned replay field.
	if len(p.SAMLSigningCertificates) != 0 {
		certificates := make([]any, len(p.SAMLSigningCertificates))
		for i, certificate := range p.SAMLSigningCertificates {
			certificates[i] = certificate
		}
		result["saml_signing_certificates"] = certificates
	}
	return result, true
}

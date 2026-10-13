package httpapi

import (
	"github.com/aatuh/api-toolkit/v3/specs"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func samlNameIDFormats() []string {
	return []string{identitydomain.SAMLNameIDUnspecified, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}
}
func registerSAMLSchemas(r *specs.Registry) {
	r.RegisterSchema("ConfigureSAMLProviderBindingRequest", objectSchema(map[string]any{
		"recipient":      map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "format": "uri", "description": "Exact absolute HTTPS recipient, without userinfo, query or fragment."},
		"name_id_format": map[string]any{"type": "string", "enum": samlNameIDFormats(), "default": identitydomain.SAMLNameIDUnspecified},
	}, "recipient"))
	r.RegisterSchema("SAMLProviderBinding", objectSchema(map[string]any{
		"tenant_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024}, "provider_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
		"recipient": map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "format": "uri"}, "name_id_format": map[string]any{"type": "string", "enum": samlNameIDFormats()},
		"schema_version": map[string]any{"type": "string", "const": identitydomain.SAMLProviderBindingSchemaVersion}, "updated_at": map[string]any{"type": "string", "format": "date-time"},
	}, "tenant_id", "provider_id", "recipient", "name_id_format", "schema_version", "updated_at"))
	r.RegisterSchema("SAMLProviderBindingEnvelope", dataEnvelopeSchema("#/components/schemas/SAMLProviderBinding"))
	r.RegisterSchema("BeginSAMLAuthenticationRequest", objectSchema(map[string]any{
		"provider_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024}, "delivery": map[string]any{"type": "string", "enum": []string{"api", "browser"}, "default": "api"},
	}, "provider_id"))
	r.RegisterSchema("SAMLAuthenticationRequest", objectSchema(map[string]any{
		"id":        map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z_][A-Za-z0-9_.-]*$"},
		"tenant_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024}, "provider_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
		"delivery": map[string]any{"type": "string", "enum": []string{"api", "browser"}},
		"issuer":   map[string]any{"type": "string", "minLength": 1, "maxLength": 4096}, "audience": map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
		"recipient": map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "format": "uri"}, "name_id_format": map[string]any{"type": "string", "enum": samlNameIDFormats()},
		"created_at": map[string]any{"type": "string", "format": "date-time"}, "expires_at": map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string", "const": identitydomain.SAMLAuthenticationRequestSchemaVersion},
	}, "id", "tenant_id", "provider_id", "delivery", "issuer", "audience", "recipient", "name_id_format", "created_at", "expires_at", "schema_version"))
	r.RegisterSchema("BeginSAMLAuthenticationResponse", objectSchema(map[string]any{
		"authentication_request": map[string]any{"$ref": "#/components/schemas/SAMLAuthenticationRequest"},
		"state_secret":           map[string]any{"type": "string", "minLength": 52, "maxLength": 52, "pattern": "^evylogin_[A-Za-z0-9_-]{43}$", "description": "One-time API delivery only; browser delivery uses its HttpOnly Secure state cookie and omits this field."},
	}, "authentication_request"))
	r.RegisterSchema("BeginSAMLAuthenticationEnvelope", dataEnvelopeSchema("#/components/schemas/BeginSAMLAuthenticationResponse"))
}

package httpapi

import "github.com/aatuh/api-toolkit/v3/specs"

func NewSpecRegistry() *specs.Registry {
	registry := specs.NewRegistryWithOptions(specs.Info{
		Title:       "Evydence API",
		Description: "Self-hosted API evidence and compliance-readiness ledger.",
		Version:     "dev",
	}, specs.RegistryOptions{OpenAPIVersion: specs.OpenAPIVersion31})
	registry.RegisterSecurityScheme("BearerAuth", specs.SecurityScheme{Type: "http", Scheme: "bearer"})
	registry.RegisterSchema("Problem", map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type":     map[string]any{"type": "string"},
			"title":    map[string]any{"type": "string"},
			"status":   map[string]any{"type": "integer"},
			"detail":   map[string]any{"type": "string"},
			"instance": map[string]any{"type": "string"},
			"code":     map[string]any{"type": "string"},
			"request_id": map[string]any{
				"type":        "string",
				"description": "Request identifier mirrored from the X-Request-ID response header.",
			},
		},
	})
	registerCriticalSchemas(registry)
	return registry
}

func registerCriticalSchemas(registry *specs.Registry) {
	registry.RegisterSchema("DataEnvelope", objectSchema(map[string]any{
		"data": map[string]any{},
		"meta": objectSchema(map[string]any{
			"api_version": map[string]any{"type": "string"},
		}, "api_version"),
	}, "data", "meta"))
	registry.RegisterSchema("InstanceAdminSnapshot", objectSchema(map[string]any{
		"tenant_count":    map[string]any{"type": "integer"},
		"user_count":      map[string]any{"type": "integer"},
		"api_key_count":   map[string]any{"type": "integer"},
		"resource_counts": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
	}, "tenant_count", "resource_counts"))
	registry.RegisterSchema("CreateSSOSessionRequest", objectSchema(map[string]any{
		"user_id":     map[string]any{"type": "string"},
		"provider_id": map[string]any{"type": "string"},
		"expires_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "user_id", "provider_id", "expires_at"))
	registry.RegisterSchema("CreateSSOProviderRequest", objectSchema(map[string]any{
		"name":                      map[string]any{"type": "string"},
		"type":                      map[string]any{"type": "string", "enum": []string{"oidc", "saml"}},
		"issuer":                    map[string]any{"type": "string"},
		"client_id":                 map[string]any{"type": "string"},
		"groups_claim":              map[string]any{"type": "string"},
		"role_mapping":              map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		"jwks":                      map[string]any{"type": "object", "description": "Optional static JWKS public-key material for local OIDC ID-token verification. Private keys and provider secrets must not be supplied."},
		"saml_signing_certificates": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional PEM-encoded SAML assertion signing certificates. Private keys and provider secrets must not be supplied."},
	}, "name", "type", "issuer", "client_id"))
	registry.RegisterSchema("VerifyProviderIdentityRequest", objectSchema(map[string]any{
		"provider_type":  map[string]any{"type": "string", "enum": []string{"oidc", "saml"}},
		"provider_id":    map[string]any{"type": "string"},
		"subject":        map[string]any{"type": "string"},
		"id_token":       map[string]any{"type": "string", "description": "Optional OIDC ID token verified locally against the provider's configured static JWKS."},
		"saml_assertion": map[string]any{"type": "string", "description": "Optional SAML assertion verified locally against configured SAML signing certificates."},
	}, "provider_type", "provider_id", "subject"))
	registry.RegisterSchema("VerifyCheck", objectSchema(map[string]any{
		"name":   map[string]any{"type": "string"},
		"result": map[string]any{"type": "string", "enum": []string{"passed", "failed", "warning"}},
		"detail": map[string]any{"type": "string"},
	}, "name", "result"))
	registry.RegisterSchema("SSOProvider", objectSchema(map[string]any{
		"id":                        map[string]any{"type": "string"},
		"tenant_id":                 map[string]any{"type": "string"},
		"name":                      map[string]any{"type": "string"},
		"type":                      map[string]any{"type": "string", "enum": []string{"oidc", "saml"}},
		"issuer":                    map[string]any{"type": "string"},
		"client_id":                 map[string]any{"type": "string"},
		"groups_claim":              map[string]any{"type": "string"},
		"role_mapping":              map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
		"jwks":                      map[string]any{"type": "object", "description": "Configured public JWKS material, when supplied."},
		"saml_signing_certificates": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Configured SAML assertion signing certificates, when supplied."},
		"status":                    map[string]any{"type": "string"},
		"schema_version":            map[string]any{"type": "string"},
		"created_at":                map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "type", "issuer", "client_id", "status", "schema_version", "created_at"))
	registry.RegisterSchema("SSOProviderEnvelope", dataEnvelopeSchema("#/components/schemas/SSOProvider"))
	registry.RegisterSchema("ProviderVerification", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"provider_type":  map[string]any{"type": "string", "enum": []string{"oidc", "saml"}},
		"provider_id":    map[string]any{"type": "string"},
		"subject":        map[string]any{"type": "string"},
		"result":         map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"checks":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "provider_type", "provider_id", "subject", "result", "checks", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("ProviderVerificationEnvelope", dataEnvelopeSchema("#/components/schemas/ProviderVerification"))
	registry.RegisterSchema("SSOSessionCreateResponse", objectSchema(map[string]any{
		"session": map[string]any{"type": "object"},
		"secret":  map[string]any{"type": "string", "description": "One-time SSO session bearer secret; not returned by list/read operations."},
	}, "session", "secret"))
	registry.RegisterSchema("SSOSessionCreateEnvelope", dataEnvelopeSchema("#/components/schemas/SSOSessionCreateResponse"))
	registry.RegisterSchema("CreateEvidenceRequest", objectSchema(map[string]any{
		"product_id":   map[string]any{"type": "string"},
		"project_id":   map[string]any{"type": "string"},
		"release_id":   map[string]any{"type": "string"},
		"artifact_id":  map[string]any{"type": "string"},
		"type":         map[string]any{"type": "string"},
		"subtype":      map[string]any{"type": "string"},
		"title":        map[string]any{"type": "string"},
		"payload_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
		"payload":      map[string]any{},
		"tags":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"source":       map[string]any{"type": "string"},
		"subject_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "type", "title"))
	registry.RegisterSchema("EvidenceSearchResponse", objectSchema(map[string]any{
		"items":       map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"next_cursor": map[string]any{"type": "string"},
	}, "items"))
	registry.RegisterSchema("EvidenceSearchEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceSearchResponse"))
	registry.RegisterSchema("CreateReleaseBundleRequest", objectSchema(map[string]any{
		"release_id": map[string]any{"type": "string"},
	}, "release_id"))
	registry.RegisterSchema("ReleaseBundleVerification", objectSchema(map[string]any{
		"result":       map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
		"checked_at":   map[string]any{"type": "string", "format": "date-time"},
	}, "result"))
	registry.RegisterSchema("ReleaseBundleVerificationEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseBundleVerification"))
	registry.RegisterSchema("CreateCustomerPortalAccessRequest", objectSchema(map[string]any{
		"package_id":    map[string]any{"type": "string"},
		"customer_name": map[string]any{"type": "string"},
		"expires_at":    map[string]any{"type": "string", "format": "date-time"},
	}, "package_id", "customer_name", "expires_at"))
	registry.RegisterSchema("CustomerPortalAccessCreateResponse", objectSchema(map[string]any{
		"access": map[string]any{"type": "object"},
		"secret": map[string]any{"type": "string", "description": "One-time portal token; stored only as a HMAC hash."},
	}, "access", "secret"))
	registry.RegisterSchema("CustomerPortalAccessCreateEnvelope", dataEnvelopeSchema("#/components/schemas/CustomerPortalAccessCreateResponse"))
	registry.RegisterSchema("CustomerPortalPackageRequest", objectSchema(map[string]any{
		"token": map[string]any{"type": "string", "description": "Customer portal access token issued by createCustomerPortalAccess."},
	}, "token"))
}

func objectSchema(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func dataEnvelopeSchema(dataRef string) map[string]any {
	return objectSchema(map[string]any{
		"data": map[string]any{"$ref": dataRef},
		"meta": objectSchema(map[string]any{
			"api_version": map[string]any{"type": "string"},
		}, "api_version"),
	}, "data", "meta")
}

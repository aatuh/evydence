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
	registry.RegisterSchema("EmptyObject", objectSchema(map[string]any{}))
	registry.RegisterSchema("HealthStatus", objectSchema(map[string]any{
		"status": map[string]any{"type": "string", "enum": []string{"ok"}},
	}, "status"))
	registry.RegisterSchema("HealthStatusEnvelope", dataEnvelopeSchema("#/components/schemas/HealthStatus"))
	registry.RegisterSchema("VersionInfo", objectSchema(map[string]any{
		"version": map[string]any{"type": "string"},
	}, "version"))
	registry.RegisterSchema("VersionInfoEnvelope", dataEnvelopeSchema("#/components/schemas/VersionInfo"))
	registry.RegisterSchema("MetricsSnapshot", objectSchema(map[string]any{
		"tenant_id":                            map[string]any{"type": "string"},
		"resource_counts":                      map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"customer_portal_failed_access_count":  map[string]any{"type": "integer"},
		"customer_portal_revoked_access_count": map[string]any{"type": "integer"},
	}, "tenant_id", "resource_counts", "customer_portal_failed_access_count", "customer_portal_revoked_access_count"))
	registry.RegisterSchema("MetricsSnapshotEnvelope", dataEnvelopeSchema("#/components/schemas/MetricsSnapshot"))
	registry.RegisterSchema("OpenAPIDocument", map[string]any{
		"type":                 "object",
		"additionalProperties": true,
		"properties": map[string]any{
			"openapi":    map[string]any{"type": "string"},
			"info":       map[string]any{"type": "object", "additionalProperties": true},
			"paths":      map[string]any{"type": "object", "additionalProperties": true},
			"components": map[string]any{"type": "object", "additionalProperties": true},
		},
		"required": []string{"openapi", "info", "paths"},
	})
	registry.RegisterSchema("InstanceAdminSnapshot", objectSchema(map[string]any{
		"report_type":     map[string]any{"type": "string"},
		"tenant_count":    map[string]any{"type": "integer"},
		"resource_counts": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"limitations":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":    map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "tenant_count", "resource_counts", "limitations", "generated_at"))
	registry.RegisterSchema("InstanceAdminSnapshotEnvelope", dataEnvelopeSchema("#/components/schemas/InstanceAdminSnapshot"))
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
		"result": map[string]any{"type": "string", "enum": []string{"passed", "failed", "warning", "skipped"}},
		"detail": map[string]any{"type": "string"},
	}, "name", "result"))
	registry.RegisterSchema("AuditChainEntry", objectSchema(map[string]any{
		"id":                   map[string]any{"type": "string"},
		"tenant_id":            map[string]any{"type": "string"},
		"sequence":             map[string]any{"type": "integer", "format": "int64"},
		"entry_type":           map[string]any{"type": "string"},
		"subject_type":         map[string]any{"type": "string"},
		"subject_id":           map[string]any{"type": "string"},
		"actor_type":           map[string]any{"type": "string"},
		"actor_id":             map[string]any{"type": "string"},
		"occurred_at":          map[string]any{"type": "string", "format": "date-time"},
		"request_id":           map[string]any{"type": "string"},
		"idempotency_key":      map[string]any{"type": "string"},
		"payload_hash":         map[string]any{"type": "string"},
		"canonical_entry_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
		"previous_entry_hash":  map[string]any{"type": "string"},
		"entry_hash":           map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_ref":        map[string]any{"type": "string"},
		"metadata":             map[string]any{"type": "object", "additionalProperties": true},
		"schema_version":       map[string]any{"type": "string"},
	}, "id", "tenant_id", "sequence", "entry_type", "subject_type", "subject_id", "actor_type", "actor_id", "occurred_at", "canonical_entry_hash", "previous_entry_hash", "entry_hash", "schema_version"))
	registry.RegisterSchema("AuditChainEntryListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/AuditChainEntry"))
	registry.RegisterSchema("ReadinessStatus", objectSchema(map[string]any{
		"status": map[string]any{"type": "string"},
		"checks": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"name":   map[string]any{"type": "string"},
			"status": map[string]any{"type": "string"},
		}, "name", "status")},
	}, "status", "checks"))
	registry.RegisterSchema("ReadinessStatusEnvelope", dataEnvelopeSchema("#/components/schemas/ReadinessStatus"))
	registry.RegisterSchema("BackupManifest", objectSchema(map[string]any{
		"id":                 map[string]any{"type": "string"},
		"tenant_id":          map[string]any{"type": "string"},
		"state_hash":         map[string]any{"type": "string", "pattern": "^sha256:"},
		"resource_counts":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"consistency_checks": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"limitations":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":     map[string]any{"type": "string"},
		"created_at":         map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "state_hash", "resource_counts", "consistency_checks", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("BackupManifestEnvelope", dataEnvelopeSchema("#/components/schemas/BackupManifest"))
	registry.RegisterSchema("VerificationResult", objectSchema(map[string]any{
		"id":           map[string]any{"type": "string"},
		"tenant_id":    map[string]any{"type": "string"},
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
		"result":       map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"checks":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"verified_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "result", "checks", "verified_at"))
	registry.RegisterSchema("VerificationResultEnvelope", dataEnvelopeSchema("#/components/schemas/VerificationResult"))
	registry.RegisterSchema("PolicyCheck", objectSchema(map[string]any{
		"name":        map[string]any{"type": "string"},
		"result":      map[string]any{"type": "string", "enum": []string{"passed", "failed", "warning", "skipped"}},
		"severity":    map[string]any{"type": "string"},
		"missing":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"explanation": map[string]any{"type": "string"},
	}, "name", "result", "severity", "explanation"))
	registry.RegisterSchema("PolicyEvaluation", objectSchema(map[string]any{
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"result":     map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"policy_set": map[string]any{"type": "string"},
		"checks":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/PolicyCheck"}},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "result", "policy_set", "checks", "created_at"))
	registry.RegisterSchema("PolicyEvaluationEnvelope", dataEnvelopeSchema("#/components/schemas/PolicyEvaluation"))
	registry.RegisterSchema("EvaluatePolicyRequest", objectSchema(map[string]any{
		"release_id": map[string]any{"type": "string"},
	}, "release_id"))
	registry.RegisterSchema("ReadinessReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"product_id":       map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"result":           map[string]any{"type": "string"},
		"checks":           map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"gaps":             map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "result", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("ReadinessReportEnvelope", dataEnvelopeSchema("#/components/schemas/ReadinessReport"))
	registry.RegisterSchema("MissingEvidenceReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"result":           map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"missing":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "report_type", "template_version", "release_id", "result", "missing", "assumptions", "limitations"))
	registry.RegisterSchema("MissingEvidenceReportEnvelope", dataEnvelopeSchema("#/components/schemas/MissingEvidenceReport"))
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
	registry.RegisterSchema("CreateOrganizationRequest", objectSchema(map[string]any{
		"name": map[string]any{"type": "string"},
		"slug": map[string]any{"type": "string"},
	}, "name", "slug"))
	registry.RegisterSchema("Organization", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"slug":           map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "slug", "status", "schema_version", "created_at"))
	registry.RegisterSchema("OrganizationEnvelope", dataEnvelopeSchema("#/components/schemas/Organization"))
	registry.RegisterSchema("CreateUserRequest", objectSchema(map[string]any{
		"organization_id": map[string]any{"type": "string"},
		"email":           map[string]any{"type": "string", "format": "email"},
		"display_name":    map[string]any{"type": "string"},
	}, "email", "display_name"))
	registry.RegisterSchema("HumanUser", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"organization_id": map[string]any{"type": "string"},
		"email":           map[string]any{"type": "string", "format": "email"},
		"display_name":    map[string]any{"type": "string"},
		"status":          map[string]any{"type": "string"},
		"deactivated_at":  map[string]any{"type": "string", "format": "date-time"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "email", "display_name", "status", "schema_version", "created_at"))
	registry.RegisterSchema("HumanUserEnvelope", dataEnvelopeSchema("#/components/schemas/HumanUser"))
	registry.RegisterSchema("CreateRoleBindingRequest", objectSchema(map[string]any{
		"subject_type":  map[string]any{"type": "string", "enum": []string{"user", "collector"}},
		"subject_id":    map[string]any{"type": "string"},
		"role":          map[string]any{"type": "string"},
		"resource_type": map[string]any{"type": "string"},
		"resource_id":   map[string]any{"type": "string"},
	}, "subject_type", "subject_id", "role"))
	registry.RegisterSchema("RoleBinding", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"role":           map[string]any{"type": "string"},
		"resource_type":  map[string]any{"type": "string"},
		"resource_id":    map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "role", "schema_version", "created_at"))
	registry.RegisterSchema("RoleBindingEnvelope", dataEnvelopeSchema("#/components/schemas/RoleBinding"))
	registry.RegisterSchema("RoleBindingListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/RoleBinding"))
	registry.RegisterSchema("LinkSSOIdentityRequest", objectSchema(map[string]any{
		"user_id":     map[string]any{"type": "string"},
		"provider_id": map[string]any{"type": "string"},
		"subject":     map[string]any{"type": "string"},
		"email":       map[string]any{"type": "string", "format": "email"},
		"verified":    map[string]any{"type": "boolean"},
	}, "user_id", "provider_id", "subject", "email", "verified"))
	registry.RegisterSchema("UserIdentityLink", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"user_id":        map[string]any{"type": "string"},
		"provider_id":    map[string]any{"type": "string"},
		"subject":        map[string]any{"type": "string"},
		"email":          map[string]any{"type": "string", "format": "email"},
		"verified":       map[string]any{"type": "boolean"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "user_id", "provider_id", "subject", "email", "verified", "schema_version", "created_at"))
	registry.RegisterSchema("UserIdentityLinkEnvelope", dataEnvelopeSchema("#/components/schemas/UserIdentityLink"))
	registry.RegisterSchema("SSOSession", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"user_id":        map[string]any{"type": "string"},
		"provider_id":    map[string]any{"type": "string"},
		"prefix":         map[string]any{"type": "string", "description": "Non-secret session token prefix for audit displays."},
		"expires_at":     map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":     map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "user_id", "provider_id", "prefix", "expires_at", "schema_version", "created_at"))
	registry.RegisterSchema("SSOSessionEnvelope", dataEnvelopeSchema("#/components/schemas/SSOSession"))
	registry.RegisterSchema("SSOSessionCreateResponse", objectSchema(map[string]any{
		"session": map[string]any{"$ref": "#/components/schemas/SSOSession"},
		"secret":  map[string]any{"type": "string", "description": "One-time SSO session bearer secret; not returned by list/read operations."},
	}, "session", "secret"))
	registry.RegisterSchema("SSOSessionCreateEnvelope", dataEnvelopeSchema("#/components/schemas/SSOSessionCreateResponse"))
	registry.RegisterSchema("CreateAPIKeyRequest", objectSchema(map[string]any{
		"name":       map[string]any{"type": "string"},
		"scopes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"expires_at": map[string]any{"type": "string", "format": "date-time"},
	}, "name", "scopes"))
	registry.RegisterSchema("APIKey", objectSchema(map[string]any{
		"id":           map[string]any{"type": "string"},
		"tenant_id":    map[string]any{"type": "string"},
		"name":         map[string]any{"type": "string"},
		"prefix":       map[string]any{"type": "string", "description": "Non-secret key prefix for lookup and audit displays."},
		"scopes":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"created_at":   map[string]any{"type": "string", "format": "date-time"},
		"expires_at":   map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":   map[string]any{"type": "string", "format": "date-time"},
		"last_used_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "prefix", "scopes", "created_at"))
	registry.RegisterSchema("APIKeyCreateResponse", objectSchema(map[string]any{
		"api_key": map[string]any{"$ref": "#/components/schemas/APIKey"},
		"secret":  map[string]any{"type": "string", "description": "One-time API key secret; stored only as a peppered HMAC hash."},
	}, "api_key", "secret"))
	registry.RegisterSchema("APIKeyCreateEnvelope", dataEnvelopeSchema("#/components/schemas/APIKeyCreateResponse"))
	registry.RegisterSchema("APIKeyListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/APIKey"))
	registry.RegisterSchema("CreateCollectorRequest", objectSchema(map[string]any{
		"name":    map[string]any{"type": "string"},
		"type":    map[string]any{"type": "string", "enum": []string{"github_actions", "gitlab_ci", "generic_ci", "import_bundle"}},
		"version": map[string]any{"type": "string"},
		"scopes":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "name", "type", "version"))
	registry.RegisterSchema("Collector", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"type":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"api_key_id":     map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"allowed_scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"last_seen_at":   map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "type", "version", "api_key_id", "status", "allowed_scopes", "schema_version", "created_at"))
	registry.RegisterSchema("CollectorCreateResponse", objectSchema(map[string]any{
		"collector": map[string]any{"$ref": "#/components/schemas/Collector"},
		"api_key":   map[string]any{"$ref": "#/components/schemas/APIKey"},
		"secret":    map[string]any{"type": "string", "description": "One-time collector API key secret; stored only as a peppered HMAC hash."},
	}, "collector", "api_key", "secret"))
	registry.RegisterSchema("CollectorCreateEnvelope", dataEnvelopeSchema("#/components/schemas/CollectorCreateResponse"))
	registry.RegisterSchema("CollectorListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/Collector"))
	registry.RegisterSchema("CreateControlFrameworkRequest", objectSchema(map[string]any{
		"name":        map[string]any{"type": "string"},
		"slug":        map[string]any{"type": "string"},
		"version":     map[string]any{"type": "string"},
		"description": map[string]any{"type": "string"},
	}, "name", "version"))
	registry.RegisterSchema("ControlFramework", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"slug":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"description":    map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "slug", "version", "status", "schema_version", "created_at"))
	registry.RegisterSchema("ControlFrameworkEnvelope", dataEnvelopeSchema("#/components/schemas/ControlFramework"))
	registry.RegisterSchema("ControlFrameworkListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/ControlFramework"))
	registry.RegisterSchema("ControlEvidenceRequirement", objectSchema(map[string]any{
		"type":           map[string]any{"type": "string"},
		"freshness_days": map[string]any{"type": "integer", "minimum": 0},
		"required":       map[string]any{"type": "boolean"},
	}, "type", "required"))
	registry.RegisterSchema("CreateSecurityControlRequest", objectSchema(map[string]any{
		"framework_id":          map[string]any{"type": "string"},
		"code":                  map[string]any{"type": "string"},
		"title":                 map[string]any{"type": "string"},
		"objective":             map[string]any{"type": "string"},
		"evidence_requirements": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ControlEvidenceRequirement"}},
		"applicability":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "framework_id", "code", "title", "objective"))
	registry.RegisterSchema("SecurityControl", objectSchema(map[string]any{
		"id":                    map[string]any{"type": "string"},
		"tenant_id":             map[string]any{"type": "string"},
		"framework_id":          map[string]any{"type": "string"},
		"code":                  map[string]any{"type": "string"},
		"title":                 map[string]any{"type": "string"},
		"objective":             map[string]any{"type": "string"},
		"evidence_requirements": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ControlEvidenceRequirement"}},
		"applicability":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":        map[string]any{"type": "string"},
		"created_at":            map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "framework_id", "code", "title", "objective", "schema_version", "created_at"))
	registry.RegisterSchema("SecurityControlEnvelope", dataEnvelopeSchema("#/components/schemas/SecurityControl"))
	registry.RegisterSchema("LinkControlEvidenceRequest", objectSchema(map[string]any{
		"evidence_type": map[string]any{"type": "string"},
		"subject_type":  map[string]any{"type": "string"},
		"subject_id":    map[string]any{"type": "string"},
		"product_id":    map[string]any{"type": "string"},
		"release_id":    map[string]any{"type": "string"},
		"confidence":    map[string]any{"type": "string", "enum": []string{"high", "medium", "low", "unsupported"}},
		"notes":         map[string]any{"type": "string"},
	}, "evidence_type", "subject_type", "subject_id", "confidence"))
	registry.RegisterSchema("ControlEvidence", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"control_id":     map[string]any{"type": "string"},
		"evidence_type":  map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"confidence":     map[string]any{"type": "string"},
		"notes":          map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "control_id", "evidence_type", "subject_type", "subject_id", "confidence", "schema_version", "created_at"))
	registry.RegisterSchema("ControlEvidenceEnvelope", dataEnvelopeSchema("#/components/schemas/ControlEvidence"))
	registry.RegisterSchema("ControlEvidenceListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/ControlEvidence"))
	registry.RegisterSchema("CreateProductRequest", objectSchema(map[string]any{
		"name": map[string]any{"type": "string"},
		"slug": map[string]any{"type": "string"},
	}, "name", "slug"))
	registry.RegisterSchema("Product", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"slug":           map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "slug", "schema_version", "created_at"))
	registry.RegisterSchema("ProductEnvelope", dataEnvelopeSchema("#/components/schemas/Product"))
	registry.RegisterSchema("ProductListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/Product"))
	registry.RegisterSchema("CreateProjectRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
		"slug":       map[string]any{"type": "string"},
	}, "product_id", "name", "slug"))
	registry.RegisterSchema("Project", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"slug":           map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "name", "slug", "schema_version", "created_at"))
	registry.RegisterSchema("ProjectEnvelope", dataEnvelopeSchema("#/components/schemas/Project"))
	registry.RegisterSchema("CreateReleaseRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"project_id": map[string]any{"type": "string"},
		"version":    map[string]any{"type": "string"},
	}, "product_id", "version"))
	registry.RegisterSchema("Release", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"project_id":     map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string", "enum": []string{"draft", "frozen", "approved"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
		"frozen_at":      map[string]any{"type": "string", "format": "date-time"},
		"approved_at":    map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "version", "status", "schema_version", "created_at"))
	registry.RegisterSchema("ReleaseEnvelope", dataEnvelopeSchema("#/components/schemas/Release"))
	registry.RegisterSchema("RegisterArtifactRequest", objectSchema(map[string]any{
		"release_id":  map[string]any{"type": "string"},
		"name":        map[string]any{"type": "string"},
		"media_type":  map[string]any{"type": "string"},
		"digest":      map[string]any{"type": "string", "pattern": "^sha256:"},
		"size":        map[string]any{"type": "integer", "minimum": 0},
		"subject_ref": map[string]any{"type": "string"},
	}, "name", "digest"))
	registry.RegisterSchema("Artifact", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"media_type":     map[string]any{"type": "string"},
		"digest":         map[string]any{"type": "string"},
		"size":           map[string]any{"type": "integer"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "digest", "schema_version", "created_at"))
	registry.RegisterSchema("ArtifactEnvelope", dataEnvelopeSchema("#/components/schemas/Artifact"))
	registry.RegisterSchema("CreateBuildRequest", objectSchema(map[string]any{
		"project_id":   map[string]any{"type": "string"},
		"release_id":   map[string]any{"type": "string"},
		"provider":     map[string]any{"type": "string"},
		"commit_sha":   map[string]any{"type": "string"},
		"status":       map[string]any{"type": "string", "enum": []string{"queued", "running", "passed", "failed", "cancelled"}},
		"started_at":   map[string]any{"type": "string", "format": "date-time"},
		"completed_at": map[string]any{"type": "string", "format": "date-time"},
		"github":       map[string]any{"type": "object"},
		"outputs":      map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
	}, "project_id", "release_id", "provider", "commit_sha", "status", "started_at"))
	registry.RegisterSchema("BuildRun", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"collector_id":   map[string]any{"type": "string"},
		"project_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"commit_sha":     map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"outputs":        map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "project_id", "release_id", "provider", "commit_sha", "status", "schema_version", "created_at"))
	registry.RegisterSchema("BuildRunEnvelope", dataEnvelopeSchema("#/components/schemas/BuildRun"))
	registry.RegisterSchema("SourceSnapshotRepositoryInput", objectSchema(map[string]any{
		"full_name":      map[string]any{"type": "string"},
		"clone_url":      map[string]any{"type": "string"},
		"default_branch": map[string]any{"type": "string"},
	}, "full_name"))
	registry.RegisterSchema("SourceSnapshotCommitInput", objectSchema(map[string]any{
		"sha":          map[string]any{"type": "string"},
		"author":       map[string]any{"type": "string"},
		"message":      map[string]any{"type": "string", "description": "Commit message supplied by the collector; Evydence stores a message hash."},
		"committed_at": map[string]any{"type": "string", "format": "date-time"},
	}, "sha", "committed_at"))
	registry.RegisterSchema("SourceSnapshotBranchInput", objectSchema(map[string]any{
		"name":            map[string]any{"type": "string"},
		"protected":       map[string]any{"type": "boolean"},
		"protection_hash": map[string]any{"type": "string"},
	}, "name"))
	registry.RegisterSchema("SourceSnapshotPullRequestInput", objectSchema(map[string]any{
		"provider_id":     map[string]any{"type": "string"},
		"title":           map[string]any{"type": "string"},
		"state":           map[string]any{"type": "string"},
		"source_branch":   map[string]any{"type": "string"},
		"target_branch":   map[string]any{"type": "string"},
		"review_decision": map[string]any{"type": "string"},
	}, "provider_id", "state"))
	registry.RegisterSchema("SourceSnapshotRequest", objectSchema(map[string]any{
		"project_id":   map[string]any{"type": "string"},
		"repository":   map[string]any{"$ref": "#/components/schemas/SourceSnapshotRepositoryInput"},
		"commit":       map[string]any{"$ref": "#/components/schemas/SourceSnapshotCommitInput"},
		"branch":       map[string]any{"$ref": "#/components/schemas/SourceSnapshotBranchInput"},
		"pull_request": map[string]any{"$ref": "#/components/schemas/SourceSnapshotPullRequestInput"},
	}, "repository"))
	registry.RegisterSchema("SourceRepository", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"project_id":     map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"full_name":      map[string]any{"type": "string"},
		"clone_url":      map[string]any{"type": "string"},
		"default_branch": map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "provider", "full_name", "schema_version", "created_at"))
	registry.RegisterSchema("SourceCommit", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"repository_id":  map[string]any{"type": "string"},
		"sha":            map[string]any{"type": "string"},
		"author":         map[string]any{"type": "string"},
		"message_hash":   map[string]any{"type": "string"},
		"committed_at":   map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "repository_id", "sha", "schema_version", "created_at"))
	registry.RegisterSchema("SourceBranch", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"repository_id":   map[string]any{"type": "string"},
		"name":            map[string]any{"type": "string"},
		"head_commit_id":  map[string]any{"type": "string"},
		"protected":       map[string]any{"type": "boolean"},
		"protection_hash": map[string]any{"type": "string"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "repository_id", "name", "protected", "schema_version", "created_at"))
	registry.RegisterSchema("PullRequest", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"repository_id":   map[string]any{"type": "string"},
		"provider":        map[string]any{"type": "string"},
		"provider_id":     map[string]any{"type": "string"},
		"title":           map[string]any{"type": "string"},
		"state":           map[string]any{"type": "string"},
		"source_branch":   map[string]any{"type": "string"},
		"target_branch":   map[string]any{"type": "string"},
		"head_commit_id":  map[string]any{"type": "string"},
		"review_decision": map[string]any{"type": "string"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "repository_id", "provider", "provider_id", "state", "schema_version", "created_at"))
	registry.RegisterSchema("SourceSnapshotResult", objectSchema(map[string]any{
		"repository":   map[string]any{"$ref": "#/components/schemas/SourceRepository"},
		"commit":       map[string]any{"$ref": "#/components/schemas/SourceCommit"},
		"branch":       map[string]any{"$ref": "#/components/schemas/SourceBranch"},
		"pull_request": map[string]any{"$ref": "#/components/schemas/PullRequest"},
	}, "repository"))
	registry.RegisterSchema("SourceSnapshotEnvelope", dataEnvelopeSchema("#/components/schemas/SourceSnapshotResult"))
	registry.RegisterSchema("CreateGraphSnapshotRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
	}))
	registry.RegisterSchema("EvidenceGraphNode", objectSchema(map[string]any{
		"id":    map[string]any{"type": "string"},
		"type":  map[string]any{"type": "string"},
		"label": map[string]any{"type": "string"},
	}, "id", "type", "label"))
	registry.RegisterSchema("EvidenceGraphEdge", objectSchema(map[string]any{
		"from":         map[string]any{"type": "string"},
		"to":           map[string]any{"type": "string"},
		"relationship": map[string]any{"type": "string"},
	}, "from", "to", "relationship"))
	registry.RegisterSchema("EvidenceGraphSnapshot", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"nodes":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceGraphNode"}},
		"edges":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceGraphEdge"}},
		"graph_hash":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "nodes", "edges", "graph_hash", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("EvidenceGraphSnapshotEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceGraphSnapshot"))
	registry.RegisterSchema("EvidenceUploadRequest", objectSchema(map[string]any{
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "object"},
	}, "release_id", "payload"))
	registry.RegisterSchema("SBOM", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"evidence_id":     map[string]any{"type": "string"},
		"release_id":      map[string]any{"type": "string"},
		"artifact_id":     map[string]any{"type": "string"},
		"format":          map[string]any{"type": "string"},
		"spec_version":    map[string]any{"type": "string"},
		"component_count": map[string]any{"type": "integer"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "evidence_id", "release_id", "format", "component_count", "created_at"))
	registry.RegisterSchema("SBOMEnvelope", dataEnvelopeSchema("#/components/schemas/SBOM"))
	registry.RegisterSchema("VEXDocument", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"evidence_id":     map[string]any{"type": "string"},
		"release_id":      map[string]any{"type": "string"},
		"artifact_id":     map[string]any{"type": "string"},
		"format":          map[string]any{"type": "string"},
		"author":          map[string]any{"type": "string"},
		"statement_count": map[string]any{"type": "integer"},
		"status_summary":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "evidence_id", "release_id", "format", "statement_count", "schema_version", "created_at"))
	registry.RegisterSchema("VEXDocumentEnvelope", dataEnvelopeSchema("#/components/schemas/VEXDocument"))
	registry.RegisterSchema("VulnerabilityScan", objectSchema(map[string]any{
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"scanner":    map[string]any{"type": "string"},
		"target_ref": map[string]any{"type": "string"},
		"summary":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"findings":   map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "scanner", "target_ref", "summary", "findings", "created_at"))
	registry.RegisterSchema("VulnerabilityScanEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityScan"))
	registry.RegisterSchema("UploadVulnerabilityScanRequest", objectSchema(map[string]any{
		"scanner":    map[string]any{"type": "string"},
		"target_ref": map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"findings": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"vulnerability": map[string]any{"type": "string"},
			"component":     map[string]any{"type": "string"},
			"severity":      map[string]any{"type": "string"},
			"state":         map[string]any{"type": "string"},
		}, "vulnerability", "severity")},
	}, "scanner", "target_ref", "release_id", "findings"))
	registry.RegisterSchema("SubjectRef", objectSchema(map[string]any{
		"type":   map[string]any{"type": "string"},
		"id":     map[string]any{"type": "string"},
		"digest": map[string]any{"type": "string"},
	}, "type"))
	registry.RegisterSchema("EvidenceRef", objectSchema(map[string]any{
		"type":         map[string]any{"type": "string"},
		"id":           map[string]any{"type": "string"},
		"relationship": map[string]any{"type": "string"},
	}, "type", "id"))
	registry.RegisterSchema("EvidenceNotice", objectSchema(map[string]any{
		"code":    map[string]any{"type": "string"},
		"message": map[string]any{"type": "string"},
	}, "code", "message"))
	registry.RegisterSchema("CreateEvidenceRequest", objectSchema(map[string]any{
		"product_id":         map[string]any{"type": "string"},
		"project_id":         map[string]any{"type": "string"},
		"release_id":         map[string]any{"type": "string"},
		"build_id":           map[string]any{"type": "string"},
		"deployment_id":      map[string]any{"type": "string"},
		"type":               map[string]any{"type": "string"},
		"subtype":            map[string]any{"type": "string"},
		"title":              map[string]any{"type": "string"},
		"source_system":      map[string]any{"type": "string"},
		"source_identity":    map[string]any{"type": "object", "additionalProperties": true},
		"collector_id":       map[string]any{"type": "string"},
		"observed_at":        map[string]any{"type": "string", "format": "date-time"},
		"payload_ref":        map[string]any{"type": "string"},
		"payload_hash":       map[string]any{"type": "string", "pattern": "^sha256:"},
		"payload_media_type": map[string]any{"type": "string"},
		"payload_size":       map[string]any{"type": "integer", "minimum": 0},
		"subject_refs":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SubjectRef"}},
		"metadata":           map[string]any{"type": "object", "additionalProperties": true},
		"tags":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "type", "title", "payload_hash"))
	registry.RegisterSchema("EvidenceItem", objectSchema(map[string]any{
		"id":                    map[string]any{"type": "string"},
		"tenant_id":             map[string]any{"type": "string"},
		"product_id":            map[string]any{"type": "string"},
		"project_id":            map[string]any{"type": "string"},
		"release_id":            map[string]any{"type": "string"},
		"build_id":              map[string]any{"type": "string"},
		"deployment_id":         map[string]any{"type": "string"},
		"type":                  map[string]any{"type": "string"},
		"subtype":               map[string]any{"type": "string"},
		"title":                 map[string]any{"type": "string"},
		"source_system":         map[string]any{"type": "string"},
		"source_identity":       map[string]any{"type": "object", "additionalProperties": true},
		"collector_id":          map[string]any{"type": "string"},
		"uploaded_by":           map[string]any{"type": "string"},
		"observed_at":           map[string]any{"type": "string", "format": "date-time"},
		"evidence_version":      map[string]any{"type": "integer"},
		"schema_version":        map[string]any{"type": "string"},
		"payload_ref":           map[string]any{"type": "string"},
		"payload_hash":          map[string]any{"type": "string", "pattern": "^sha256:"},
		"payload_media_type":    map[string]any{"type": "string"},
		"payload_size":          map[string]any{"type": "integer"},
		"canonical_hash":        map[string]any{"type": "string", "pattern": "^sha256:"},
		"canonicalization":      map[string]any{"type": "string"},
		"subject_refs":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SubjectRef"}},
		"related_evidence_refs": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceRef"}},
		"supersedes":            map[string]any{"type": "string"},
		"superseded_by":         map[string]any{"type": "string"},
		"trust_level":           map[string]any{"type": "string"},
		"verification_status":   map[string]any{"type": "string"},
		"signature_refs":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"chain_entry_id":        map[string]any{"type": "string"},
		"tags":                  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"metadata":              map[string]any{"type": "object", "additionalProperties": true},
		"warnings":              map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceNotice"}},
		"limitations":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"created_at":            map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "type", "title", "source_system", "observed_at", "evidence_version", "schema_version", "payload_hash", "canonical_hash", "canonicalization", "trust_level", "verification_status", "chain_entry_id", "created_at"))
	registry.RegisterSchema("EvidenceItemEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceItem"))
	registry.RegisterSchema("EvidenceItemListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/EvidenceItem"))
	registry.RegisterSchema("EvidenceSearchResponse", objectSchema(map[string]any{
		"items":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceItem"}},
		"next_cursor": map[string]any{"type": "string"},
	}, "items"))
	registry.RegisterSchema("EvidenceSearchEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceSearchResponse"))
	registry.RegisterSchema("CreateReleaseBundleRequest", objectSchema(map[string]any{
		"release_id": map[string]any{"type": "string"},
	}, "release_id"))
	registry.RegisterSchema("ReleaseBundleManifest", objectSchema(map[string]any{
		"manifest_version": map[string]any{"type": "string"},
		"bundle_id":        map[string]any{"type": "string"},
		"tenant_id":        map[string]any{"type": "string"},
		"release":          map[string]any{"type": "object", "additionalProperties": true},
		"evidence_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"chain_checkpoint": map[string]any{"type": "object", "additionalProperties": true},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
		"generator":        map[string]any{"type": "object", "additionalProperties": true},
	}, "manifest_version", "bundle_id", "tenant_id", "release", "evidence_ids", "chain_checkpoint", "generated_at", "generator"))
	registry.RegisterSchema("ReleaseBundleManifestEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseBundleManifest"))
	registry.RegisterSchema("ReleaseBundle", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"state":          map[string]any{"type": "string"},
		"manifest":       map[string]any{"$ref": "#/components/schemas/ReleaseBundleManifest"},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
		"published_at":   map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "state", "manifest", "manifest_hash", "signature_refs", "created_at"))
	registry.RegisterSchema("ReleaseBundleEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseBundle"))
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

func dataArrayEnvelopeSchema(itemRef string) map[string]any {
	return objectSchema(map[string]any{
		"data": map[string]any{"type": "array", "items": map[string]any{"$ref": itemRef}},
		"meta": objectSchema(map[string]any{
			"api_version": map[string]any{"type": "string"},
		}, "api_version"),
	}, "data", "meta")
}

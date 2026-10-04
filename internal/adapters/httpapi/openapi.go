package httpapi

import (
	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func NewSpecRegistry() *specs.Registry {
	registry := specs.NewRegistryWithOptions(specs.Info{
		Title:       "Evydence API",
		Description: "Self-hosted API evidence and compliance-readiness ledger.",
		Version:     "dev",
	}, specs.RegistryOptions{OpenAPIVersion: specs.OpenAPIVersion31})
	registry.RegisterSecurityScheme("BearerAuth", specs.SecurityScheme{Type: "http", Scheme: "bearer"})
	registerProblemSchemas(registry)
	registry.RegisterSchema("Problem", map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"type":     map[string]any{"type": "string"},
			"title":    map[string]any{"type": "string"},
			"status":   map[string]any{"type": "integer"},
			"detail":   map[string]any{"type": "string"},
			"instance": map[string]any{"type": "string"},
			"code":     map[string]any{"$ref": "#/components/schemas/ErrorCode"},
			"retryable": map[string]any{
				"type":        "boolean",
				"description": "Whether the documented retry class permits an automatic client retry.",
			},
			"retry_class": map[string]any{
				"$ref": "#/components/schemas/RetryClass",
			},
			"retry_after_seconds": map[string]any{
				"type":        "integer",
				"minimum":     1,
				"description": "Positive catalog retry interval, mirrored in Retry-After when present.",
			},
			"violations": map[string]any{
				"type":        "array",
				"maxItems":    32,
				"description": "Optional safe request-body JSON Pointer validation violations.",
				"items":       map[string]any{"$ref": "#/components/schemas/FieldViolation"},
			},
			"current_revision": map[string]any{
				"type":        "integer",
				"format":      "int64",
				"minimum":     1,
				"description": "Current resource revision included with VERSION_CONFLICT responses.",
			},
			"request_id": map[string]any{
				"type":        "string",
				"description": "Request identifier mirrored from the X-Request-ID response header.",
			},
		},
		"required": []string{"type", "title", "status", "detail", "code", "request_id", "retryable", "retry_class"},
	})
	registerCriticalSchemas(registry)
	return registry
}

func registerProblemSchemas(registry *specs.Registry) {
	definitions := app.ErrorCatalog()
	codes := make([]string, 0, len(definitions))
	retryClasses := make([]string, 0, len(definitions))
	seenRetryClasses := map[string]struct{}{}
	for _, definition := range definitions {
		codes = append(codes, string(definition.Code))
		if _, seen := seenRetryClasses[string(definition.RetryClass)]; seen {
			continue
		}
		seenRetryClasses[string(definition.RetryClass)] = struct{}{}
		retryClasses = append(retryClasses, string(definition.RetryClass))
	}
	registry.RegisterSchema("ErrorCode", map[string]any{
		"type":        "string",
		"enum":        codes,
		"description": "Stable machine-readable Evydence Problem Details code. See docs/reference/error-codes.md.",
	})
	registry.RegisterSchema("RetryClass", map[string]any{
		"type":        "string",
		"enum":        retryClasses,
		"description": "Stable client action classification for Problem Details retry behavior.",
	})
	registry.RegisterSchema("FieldViolation", map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"field": map[string]any{"type": "string", "pattern": "^/(?:[A-Za-z0-9_./-]|~[01])+$", "maxLength": 256},
			"code":  map[string]any{"type": "string", "pattern": "^[a-z0-9_-]+$", "maxLength": 64},
		},
		"required": []string{"field", "code"},
	})
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
		"version":                 map[string]any{"type": "string"},
		"commit":                  map[string]any{"type": "string"},
		"build_time":              map[string]any{"type": "string"},
		"dirty":                   map[string]any{"type": "boolean"},
		"go_version":              map[string]any{"type": "string"},
		"release_manifest_digest": map[string]any{"type": "string"},
	}, "version", "commit", "build_time", "dirty", "go_version", "release_manifest_digest"))
	registry.RegisterSchema("VersionInfoEnvelope", dataEnvelopeSchema("#/components/schemas/VersionInfo"))
	registry.RegisterSchema("MetricsSnapshot", objectSchema(map[string]any{
		"tenant_id":                                    map[string]any{"type": "string"},
		"resource_counts":                              map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"customer_portal_failed_access_count":          map[string]any{"type": "integer"},
		"customer_portal_revoked_access_count":         map[string]any{"type": "integer"},
		"outbox_pending_jobs":                          map[string]any{"type": "integer", "minimum": 0, "description": "Instance-wide queued or retrying jobs; returned only to explicit instance administrators."},
		"outbox_running_jobs":                          map[string]any{"type": "integer", "minimum": 0, "description": "Instance-wide leased jobs; returned only to explicit instance administrators."},
		"outbox_terminal_jobs":                         map[string]any{"type": "integer", "minimum": 0, "description": "Instance-wide dead-letter jobs; returned only to explicit instance administrators."},
		"outbox_oldest_pending_age_seconds":            map[string]any{"type": "integer", "minimum": 0, "description": "Age of the oldest queued or retrying job; returned only to explicit instance administrators."},
		"object_reconciliation_runs":                   map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped completed object reconciliation runs; returned when receipt metrics are configured."},
		"object_reconciliation_scanned_payloads":       map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped payload metadata records scanned by reconciliation."},
		"object_reconciliation_missing_final_objects":  map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped missing final-object findings."},
		"object_reconciliation_missing_staged_objects": map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped missing staging-object findings."},
		"object_reconciliation_digest_mismatches":      map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped object digest or metadata mismatch findings."},
		"object_reconciliation_provider_orphans":       map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped advisory inventory objects without database ownership."},
		"object_reconciliation_quarantined_payloads":   map[string]any{"type": "integer", "minimum": 0, "description": "Tenant-scoped lifecycle records quarantined without provider-object deletion."},
		"object_reconciliation_last_run_age_seconds":   map[string]any{"type": "integer", "minimum": 0, "description": "Age of the latest tenant-scoped reconciliation receipt."},
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
	registry.RegisterSchema("OutboxDiagnostics", objectSchema(map[string]any{
		"pending_jobs":              map[string]any{"type": "integer", "minimum": 0},
		"running_jobs":              map[string]any{"type": "integer", "minimum": 0},
		"terminal_jobs":             map[string]any{"type": "integer", "minimum": 0},
		"oldest_pending_created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "pending_jobs", "running_jobs", "terminal_jobs"))
	registry.RegisterSchema("OutboxDiagnosticsEnvelope", dataEnvelopeSchema("#/components/schemas/OutboxDiagnostics"))
	registry.RegisterSchema("OutboxReplay", objectSchema(map[string]any{
		"job_id":      map[string]any{"type": "string"},
		"status":      map[string]any{"type": "string", "enum": []string{"queued"}},
		"replayed_at": map[string]any{"type": "string", "format": "date-time"},
	}, "job_id", "status", "replayed_at"))
	registry.RegisterSchema("OutboxReplayEnvelope", dataEnvelopeSchema("#/components/schemas/OutboxReplay"))
	registry.RegisterSchema("CreateSSOSessionRequest", objectSchema(map[string]any{
		"user_id":     map[string]any{"type": "string"},
		"provider_id": map[string]any{"type": "string"},
		"expires_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "user_id", "provider_id", "expires_at"))
	registry.RegisterSchema("ExchangeSSOCredentialRequest", objectSchema(map[string]any{
		"provider_id":    map[string]any{"type": "string", "maxLength": 1024, "description": "Nonblank provider ID, bounded at 1024 UTF-8 bytes before trimming."},
		"subject":        map[string]any{"type": "string", "maxLength": 65536, "description": "Nonblank subject, bounded at 65536 UTF-8 bytes before trimming; cannot contain the supplied credential."},
		"id_token":       map[string]any{"type": "string", "maxLength": 65536, "description": "OIDC ID token verified locally against configured public JWKS trust material; bounded at 65536 UTF-8 bytes."},
		"saml_assertion": map[string]any{"type": "string", "maxLength": 65536, "description": "SAML assertion verified locally against configured SAML signing certificates; bounded at 65536 UTF-8 bytes."},
		"expires_at":     map[string]any{"type": "string", "format": "date-time", "description": "Optional session expiry, capped by the server."},
	}, "provider_id", "subject"))
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
	registry.RegisterSchema("UpdateSSOProviderTrustMaterialRequest", objectSchema(map[string]any{
		"jwks":                      map[string]any{"type": "object", "description": "OIDC public JWKS material. Private keys and provider secrets must not be supplied."},
		"saml_signing_certificates": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "PEM-encoded SAML assertion signing certificates. Private keys and provider secrets must not be supplied."},
	}))
	registry.RegisterSchema("VerifyProviderIdentityRequest", objectSchema(map[string]any{
		"provider_type":  map[string]any{"type": "string", "enum": []string{"oidc", "saml"}},
		"provider_id":    map[string]any{"type": "string", "maxLength": 1024, "description": "Nonblank tenant-owned provider ID, bounded at 1024 UTF-8 bytes before trimming."},
		"subject":        map[string]any{"type": "string", "maxLength": 65536, "description": "Nonblank case-sensitive provider subject, bounded at 65536 UTF-8 bytes; cannot contain a supplied credential."},
		"id_token":       map[string]any{"type": "string", "maxLength": 65536, "description": "Optional OIDC ID token verified locally against the provider's configured static JWKS; bounded at 65536 UTF-8 bytes."},
		"saml_assertion": map[string]any{"type": "string", "maxLength": 65536, "description": "Optional SAML assertion verified locally against configured SAML signing certificates; bounded at 65536 UTF-8 bytes."},
		"access_token":   map[string]any{"type": "string", "maxLength": 16384, "description": "Optional OIDC access token used only by the configured live provider validator; bounded at 16384 UTF-8 bytes. It is not persisted and must not be supplied for SAML providers."},
	}, "provider_type", "provider_id", "subject"))
	registry.RegisterSchema("VerifyCheck", objectSchema(map[string]any{
		"name":   map[string]any{"type": "string"},
		"result": map[string]any{"type": "string", "enum": []string{"passed", "failed", "warning", "skipped", "error"}},
		"detail": map[string]any{"type": "string"},
	}, "name", "result"))
	registry.RegisterSchema("VerificationProfile", objectSchema(map[string]any{
		"id":                 map[string]any{"type": "string"},
		"version":            map[string]any{"type": "string"},
		"required_checks":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"trust_material":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Non-secret trust-material identifiers or classes evaluated."},
		"identity_policy":    map[string]any{"type": "string"},
		"transparency_proof": map[string]any{"type": "string"},
		"payload_scope":      map[string]any{"type": "string"},
		"payload_digest":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"limitations":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "id", "version", "required_checks", "limitations"))
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
		"status":      map[string]any{"type": "string", "enum": []string{"ok", "unavailable"}},
		"retryable":   map[string]any{"type": "boolean", "description": "Present for unavailable readiness and indicates whether a retry can help."},
		"retry_class": map[string]any{"$ref": "#/components/schemas/RetryClass"},
		"retry_after_seconds": map[string]any{
			"type":        "integer",
			"minimum":     1,
			"description": "Present for retryable unavailable readiness and mirrored in Retry-After.",
		},
		"checks": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"name":   map[string]any{"type": "string"},
			"status": map[string]any{"type": "string", "enum": []string{"ok", "unavailable"}},
		}, "name", "status")},
	}, "status", "checks"))
	registry.RegisterSchema("ReadinessStatusEnvelope", dataEnvelopeSchema("#/components/schemas/ReadinessStatus"))
	registry.RegisterSchema("ReadinessDiagnostics", objectSchema(map[string]any{
		"status": map[string]any{"type": "string", "enum": []string{"ok", "unavailable"}},
		"checks": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"name":   map[string]any{"type": "string"},
			"status": map[string]any{"type": "string", "enum": []string{"ok", "unavailable"}},
			"detail": map[string]any{"type": "string", "description": "Vetted operator diagnostic; never a raw dependency error."},
		}, "name", "status")},
	}, "status", "checks"))
	registry.RegisterSchema("ReadinessDiagnosticsEnvelope", dataEnvelopeSchema("#/components/schemas/ReadinessDiagnostics"))
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
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"result":         map[string]any{"type": "string", "enum": []string{"passed", "failed", "not_verified", "limited", "skipped", "error"}},
		"checks":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"profile":        map[string]any{"$ref": "#/components/schemas/VerificationProfile"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"verified_at":    map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "result", "checks", "profile", "limitations", "schema_version", "verified_at"))
	registry.RegisterSchema("VerificationResultEnvelope", dataEnvelopeSchema("#/components/schemas/VerificationResult"))
	registry.RegisterSchema("CreateMerkleBatchRequest", objectSchema(map[string]any{
		"from_sequence": map[string]any{"type": "integer", "format": "int64"},
		"to_sequence":   map[string]any{"type": "integer", "format": "int64"},
	}))
	registry.RegisterSchema("MerkleBatch", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"from_sequence":  map[string]any{"type": "integer", "format": "int64"},
		"to_sequence":    map[string]any{"type": "integer", "format": "int64"},
		"entry_count":    map[string]any{"type": "integer"},
		"leaf_hashes":    map[string]any{"type": "array", "items": map[string]any{"type": "string", "pattern": "^sha256:"}},
		"root_hash":      map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "from_sequence", "to_sequence", "entry_count", "leaf_hashes", "root_hash", "schema_version", "created_at"))
	registry.RegisterSchema("MerkleBatchEnvelope", dataEnvelopeSchema("#/components/schemas/MerkleBatch"))
	registry.RegisterSchema("CreateTransparencyCheckpointRequest", objectSchema(map[string]any{
		"batch_id":     map[string]any{"type": "string"},
		"provider":     map[string]any{"type": "string"},
		"external_url": map[string]any{"type": "string"},
		"external_id":  map[string]any{"type": "string"},
	}, "batch_id", "provider"))
	registry.RegisterSchema("TransparencyCheckpoint", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"batch_id":       map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"external_url":   map[string]any{"type": "string"},
		"external_id":    map[string]any{"type": "string"},
		"timestamp_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
		"state":          map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "batch_id", "provider", "timestamp_hash", "state", "schema_version", "created_at"))
	registry.RegisterSchema("TransparencyCheckpointEnvelope", dataEnvelopeSchema("#/components/schemas/TransparencyCheckpoint"))
	registry.RegisterSchema("CreateObjectRetentionPolicyRequest", objectSchema(map[string]any{
		"name":                       map[string]any{"type": "string"},
		"object_prefix":              map[string]any{"type": "string"},
		"object_key":                 map[string]any{"type": "string", "description": "Optional tenant-prefixed sample object key used for object-level retention verification when supported by the object store."},
		"require_legal_hold":         map[string]any{"type": "boolean", "description": "When true, the sample object key must have provider-reported legal hold enabled."},
		"mode":                       map[string]any{"type": "string", "enum": []string{"governance", "compliance"}},
		"retention_days":             map[string]any{"type": "integer", "minimum": 1},
		"max_verification_age_hours": map[string]any{"type": "integer", "minimum": 1, "maximum": 8784, "description": "Maximum age of a successful provider observation before it is reported as stale. Defaults to 24 hours."},
	}, "name", "mode", "retention_days"))
	registry.RegisterSchema("ObjectRetentionPolicy", objectSchema(map[string]any{
		"id":                          map[string]any{"type": "string"},
		"tenant_id":                   map[string]any{"type": "string"},
		"name":                        map[string]any{"type": "string"},
		"object_prefix":               map[string]any{"type": "string"},
		"object_key":                  map[string]any{"type": "string"},
		"require_legal_hold":          map[string]any{"type": "boolean"},
		"mode":                        map[string]any{"type": "string"},
		"retention_days":              map[string]any{"type": "integer"},
		"max_verification_age_hours":  map[string]any{"type": "integer"},
		"status":                      map[string]any{"type": "string", "enum": []string{"configured", "not_verified", "not_enforced", "verified", "stale"}},
		"verified_at":                 map[string]any{"type": "string", "format": "date-time"},
		"verification_hash":           map[string]any{"type": "string", "pattern": "^sha256:"},
		"verification_provider":       map[string]any{"type": "string"},
		"verification_bucket":         map[string]any{"type": "string"},
		"verification_mode":           map[string]any{"type": "string"},
		"verification_retention_days": map[string]any{"type": "integer"},
		"verification_legal_hold":     map[string]any{"type": "boolean"},
		"verification_observed_at":    map[string]any{"type": "string", "format": "date-time"},
		"verification_expires_at":     map[string]any{"type": "string", "format": "date-time"},
		"verification_checks": map[string]any{
			"type":  "array",
			"items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"},
		},
		"verification_limitations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":           map[string]any{"type": "string"},
		"created_at":               map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "object_prefix", "mode", "retention_days", "max_verification_age_hours", "status", "schema_version", "created_at"))
	registry.RegisterSchema("ObjectRetentionPolicyEnvelope", dataEnvelopeSchema("#/components/schemas/ObjectRetentionPolicy"))
	registry.RegisterSchema("CreateLegalHoldRequest", objectSchema(map[string]any{
		"scope_type": map[string]any{"type": "string"},
		"scope_id":   map[string]any{"type": "string"},
		"reason":     map[string]any{"type": "string"},
		"owner":      map[string]any{"type": "string"},
	}, "scope_type", "scope_id", "reason", "owner"))
	registry.RegisterSchema("LegalHold", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"scope_type":     map[string]any{"type": "string"},
		"scope_id":       map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"owner":          map[string]any{"type": "string"},
		"released_at":    map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "scope_type", "scope_id", "reason", "owner", "schema_version", "created_at"))
	registry.RegisterSchema("LegalHoldEnvelope", dataEnvelopeSchema("#/components/schemas/LegalHold"))
	registry.RegisterSchema("CreateRetentionOverrideRequest", objectSchema(map[string]any{
		"scope_type":      map[string]any{"type": "string"},
		"scope_id":        map[string]any{"type": "string"},
		"retention_until": map[string]any{"type": "string", "format": "date-time"},
		"reason":          map[string]any{"type": "string"},
		"owner":           map[string]any{"type": "string"},
	}, "scope_type", "scope_id", "retention_until", "reason", "owner"))
	registry.RegisterSchema("RetentionOverride", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"scope_type":      map[string]any{"type": "string"},
		"scope_id":        map[string]any{"type": "string"},
		"retention_until": map[string]any{"type": "string", "format": "date-time"},
		"reason":          map[string]any{"type": "string"},
		"owner":           map[string]any{"type": "string"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "scope_type", "scope_id", "retention_until", "reason", "owner", "schema_version", "created_at"))
	registry.RegisterSchema("RetentionOverrideEnvelope", dataEnvelopeSchema("#/components/schemas/RetentionOverride"))
	registry.RegisterSchema("RetentionReport", objectSchema(map[string]any{
		"report_type":         map[string]any{"type": "string"},
		"scope_type":          map[string]any{"type": "string"},
		"scope_id":            map[string]any{"type": "string"},
		"legal_holds":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/LegalHold"}},
		"retention_overrides": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/RetentionOverride"}},
		"limitations":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "legal_holds", "retention_overrides", "limitations", "generated_at"))
	registry.RegisterSchema("RetentionReportEnvelope", dataEnvelopeSchema("#/components/schemas/RetentionReport"))
	registry.RegisterSchema("PolicyCheck", objectSchema(map[string]any{
		"name":        map[string]any{"type": "string"},
		"result":      map[string]any{"type": "string", "enum": []string{"passed", "failed", "warning", "skipped"}},
		"severity":    map[string]any{"type": "string"},
		"missing":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"explanation": map[string]any{"type": "string"},
		"remediation": map[string]any{"type": "string"},
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
	registry.RegisterSchema("CreateVulnerabilityDecisionRequest", objectSchema(map[string]any{
		"status":           map[string]any{"type": "string", "enum": []string{"affected", "not_affected", "fixed", "under_investigation"}},
		"justification":    map[string]any{"type": "string"},
		"impact_statement": map[string]any{"type": "string"},
		"action_statement": map[string]any{"type": "string"},
		"customer_visible": map[string]any{"type": "boolean"},
		"internal_notes":   map[string]any{"type": "string", "description": "Tenant-internal notes; excluded from customer-safe package summaries."},
		"evidence_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"supporting_refs":  map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SubjectRef"}, "description": "Optional tenant-scoped first-class decision support records from the same release. Supported types are approval, exception, waiver, remediation_task, release_bundle, and incident."},
		"vex_document_id":  map[string]any{"type": "string", "description": "Optional tenant-scoped VEX document from the same release to link to this manual decision."},
		"reviewed_at":      map[string]any{"type": "string", "format": "date-time", "description": "Optional UTC time when the decision was reviewed. Defaults to creation time."},
		"review_due_at":    map[string]any{"type": "string", "format": "date-time", "description": "Optional UTC time when this decision should be reviewed again."},
	}, "status", "justification"))
	registry.RegisterSchema("VulnerabilityDecision", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"tenant_id":           map[string]any{"type": "string"},
		"finding_id":          map[string]any{"type": "string"},
		"scan_id":             map[string]any{"type": "string"},
		"release_id":          map[string]any{"type": "string"},
		"vulnerability":       map[string]any{"type": "string"},
		"component":           map[string]any{"type": "string"},
		"sbom_id":             map[string]any{"type": "string", "description": "Same-release SBOM that contained the matched component, when available."},
		"sbom_component_purl": map[string]any{"type": "string"},
		"sbom_component_name": map[string]any{"type": "string"},
		"status":              map[string]any{"type": "string"},
		"justification":       map[string]any{"type": "string"},
		"impact_statement":    map[string]any{"type": "string"},
		"action_statement":    map[string]any{"type": "string"},
		"customer_visible":    map[string]any{"type": "boolean"},
		"source":              map[string]any{"type": "string"},
		"evidence_id":         map[string]any{"type": "string"},
		"evidence_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"supporting_refs":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SubjectRef"}},
		"vex_document_id":     map[string]any{"type": "string"},
		"supersedes":          map[string]any{"type": "string"},
		"superseded_by":       map[string]any{"type": "string"},
		"approved_by":         map[string]any{"type": "string"},
		"reviewed_at":         map[string]any{"type": "string", "format": "date-time"},
		"review_due_at":       map[string]any{"type": "string", "format": "date-time"},
		"schema_version":      map[string]any{"type": "string"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "finding_id", "scan_id", "vulnerability", "status", "justification", "source", "schema_version", "created_at"))
	registry.RegisterSchema("VulnerabilityDecisionEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityDecision"))
	registry.RegisterSchema("VulnerabilityDecisionListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/VulnerabilityDecision"))
	registry.RegisterSchema("VulnerabilityDecisionCustomerSummary", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"finding_id":          map[string]any{"type": "string"},
		"scan_id":             map[string]any{"type": "string"},
		"release_id":          map[string]any{"type": "string"},
		"vulnerability":       map[string]any{"type": "string"},
		"component":           map[string]any{"type": "string"},
		"sbom_id":             map[string]any{"type": "string", "description": "Same-release SBOM that contained the matched component, when available."},
		"sbom_component_purl": map[string]any{"type": "string"},
		"sbom_component_name": map[string]any{"type": "string"},
		"status":              map[string]any{"type": "string"},
		"justification":       map[string]any{"type": "string"},
		"impact_statement":    map[string]any{"type": "string"},
		"action_statement":    map[string]any{"type": "string"},
		"source":              map[string]any{"type": "string"},
		"evidence_id":         map[string]any{"type": "string"},
		"evidence_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"supporting_refs":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SubjectRef"}},
		"vex_document_id":     map[string]any{"type": "string"},
		"reviewed_at":         map[string]any{"type": "string", "format": "date-time"},
		"review_due_at":       map[string]any{"type": "string", "format": "date-time"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "finding_id", "scan_id", "release_id", "vulnerability", "status", "impact_statement", "source", "created_at"))
	registry.RegisterSchema("VulnerabilityDecisionSummaryReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"product_id":       map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"decisions":        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VulnerabilityDecisionCustomerSummary"}},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "product_id", "release_id", "decisions", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("VulnerabilityDecisionSummaryReportEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityDecisionSummaryReport"))
	registry.RegisterSchema("RecordVulnerabilityWorkflowRequest", objectSchema(map[string]any{
		"action": map[string]any{"type": "string"},
		"reason": map[string]any{"type": "string"},
	}, "action", "reason"))
	registry.RegisterSchema("VulnerabilityWorkflowRecord", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"finding_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"action":         map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"actor_id":       map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "finding_id", "action", "reason", "actor_id", "schema_version", "created_at"))
	registry.RegisterSchema("VulnerabilityWorkflowRecordEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityWorkflowRecord"))
	registry.RegisterSchema("CreateExceptionRequest", objectSchema(map[string]any{
		"release_id": map[string]any{"type": "string"},
		"finding_id": map[string]any{"type": "string"},
		"control_id": map[string]any{"type": "string"},
		"reason":     map[string]any{"type": "string"},
		"owner":      map[string]any{"type": "string"},
		"expires_at": map[string]any{"type": "string", "format": "date-time"},
	}, "release_id", "reason", "owner", "expires_at"))
	registry.RegisterSchema("Exception", objectSchema(map[string]any{
		"id":          map[string]any{"type": "string"},
		"tenant_id":   map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"finding_id":  map[string]any{"type": "string"},
		"control_id":  map[string]any{"type": "string"},
		"reason":      map[string]any{"type": "string"},
		"owner":       map[string]any{"type": "string"},
		"expires_at":  map[string]any{"type": "string", "format": "date-time"},
		"approved":    map[string]any{"type": "boolean"},
		"approved_by": map[string]any{"type": "string"},
		"approved_at": map[string]any{"type": "string", "format": "date-time"},
		"created_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "reason", "owner", "expires_at", "approved", "created_at"))
	registry.RegisterSchema("ExceptionEnvelope", dataEnvelopeSchema("#/components/schemas/Exception"))
	registry.RegisterSchema("ExceptionListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/Exception"))
	registry.RegisterSchema("PolicyRule", objectSchema(map[string]any{
		"name":          map[string]any{"type": "string"},
		"evidence_type": map[string]any{"type": "string"},
		"severity":      map[string]any{"type": "string"},
		"required":      map[string]any{"type": "boolean"},
	}, "name", "severity", "required"))
	registry.RegisterSchema("CreateCustomPolicyRequest", objectSchema(map[string]any{
		"name":        map[string]any{"type": "string"},
		"version":     map[string]any{"type": "string"},
		"description": map[string]any{"type": "string"},
		"rules":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/PolicyRule"}},
	}, "name", "version", "rules"))
	registry.RegisterSchema("CustomPolicy", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"revision":       map[string]any{"type": "integer", "format": "int64", "minimum": 1},
		"version":        map[string]any{"type": "string"},
		"description":    map[string]any{"type": "string"},
		"rules":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/PolicyRule"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "version", "rules", "schema_version", "created_at"))
	registry.RegisterSchema("CustomPolicyEnvelope", dataEnvelopeSchema("#/components/schemas/CustomPolicy"))
	registry.RegisterSchema("CustomPolicyEvaluation", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"policy_id":      map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"result":         map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"checks":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/PolicyCheck"}},
		"input_hash":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "policy_id", "release_id", "result", "checks", "input_hash", "schema_version", "created_at"))
	registry.RegisterSchema("CustomPolicyEvaluationEnvelope", dataEnvelopeSchema("#/components/schemas/CustomPolicyEvaluation"))
	registry.RegisterSchema("CreateWaiverRequest", objectSchema(map[string]any{
		"scope_type": map[string]any{"type": "string"},
		"scope_id":   map[string]any{"type": "string"},
		"control_id": map[string]any{"type": "string"},
		"policy_id":  map[string]any{"type": "string"},
		"owner":      map[string]any{"type": "string"},
		"risk":       map[string]any{"type": "string"},
		"reason":     map[string]any{"type": "string"},
		"expires_at": map[string]any{"type": "string", "format": "date-time"},
		"supersedes": map[string]any{"type": "string"},
	}, "scope_type", "scope_id", "owner", "risk", "reason", "expires_at"))
	registry.RegisterSchema("Waiver", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"scope_type":     map[string]any{"type": "string"},
		"scope_id":       map[string]any{"type": "string"},
		"control_id":     map[string]any{"type": "string"},
		"policy_id":      map[string]any{"type": "string"},
		"owner":          map[string]any{"type": "string"},
		"risk":           map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"expires_at":     map[string]any{"type": "string", "format": "date-time"},
		"approved":       map[string]any{"type": "boolean"},
		"approved_by":    map[string]any{"type": "string"},
		"approved_at":    map[string]any{"type": "string", "format": "date-time"},
		"supersedes":     map[string]any{"type": "string"},
		"superseded_by":  map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "scope_type", "scope_id", "owner", "risk", "reason", "expires_at", "approved", "schema_version", "created_at"))
	registry.RegisterSchema("WaiverEnvelope", dataEnvelopeSchema("#/components/schemas/Waiver"))
	registry.RegisterSchema("CreateApprovalRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
		"decision":     map[string]any{"type": "string", "enum": []string{"approved", "rejected", "accepted"}},
		"reason":       map[string]any{"type": "string"},
		"evidence_id":  map[string]any{"type": "string"},
	}, "subject_type", "subject_id", "decision", "reason"))
	registry.RegisterSchema("ApprovalRecord", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"decision":       map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"approver_id":    map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "decision", "reason", "approver_id", "schema_version", "created_at"))
	registry.RegisterSchema("ApprovalRecordEnvelope", dataEnvelopeSchema("#/components/schemas/ApprovalRecord"))
	registry.RegisterSchema("UploadOpenAPIContractRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"version":    map[string]any{"type": "string"},
		"spec":       map[string]any{"type": "object", "additionalProperties": true},
	}, "product_id", "release_id", "version", "spec"))
	registry.RegisterSchema("OpenAPIOperationRecord", objectSchema(map[string]any{
		"path":                    map[string]any{"type": "string"},
		"method":                  map[string]any{"type": "string"},
		"operation_id":            map[string]any{"type": "string"},
		"deprecated":              map[string]any{"type": "boolean"},
		"request_body_required":   map[string]any{"type": "boolean"},
		"required_request_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"response_statuses":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "path", "method"))
	registry.RegisterSchema("OpenAPIContract", objectSchema(map[string]any{
		"id":          map[string]any{"type": "string"},
		"tenant_id":   map[string]any{"type": "string"},
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"version":     map[string]any{"type": "string"},
		"hash":        map[string]any{"type": "string", "pattern": "^sha256:"},
		"path_count":  map[string]any{"type": "integer"},
		"operations":  map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/OpenAPIOperationRecord"}},
		"evidence_id": map[string]any{"type": "string"},
		"created_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "version", "hash", "path_count", "evidence_id", "created_at"))
	registry.RegisterSchema("OpenAPIContractEnvelope", dataEnvelopeSchema("#/components/schemas/OpenAPIContract"))
	registry.RegisterSchema("CreateOpenAPIDiffRequest", objectSchema(map[string]any{
		"base_contract_id":   map[string]any{"type": "string"},
		"target_contract_id": map[string]any{"type": "string"},
		"release_id":         map[string]any{"type": "string"},
	}, "base_contract_id", "target_contract_id", "release_id"))
	registry.RegisterSchema("ContractDiff", objectSchema(map[string]any{
		"id":                   map[string]any{"type": "string"},
		"tenant_id":            map[string]any{"type": "string"},
		"base_contract_id":     map[string]any{"type": "string"},
		"target_contract_id":   map[string]any{"type": "string"},
		"product_id":           map[string]any{"type": "string"},
		"release_id":           map[string]any{"type": "string"},
		"result":               map[string]any{"type": "string"},
		"breaking_changes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"non_breaking_changes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":       map[string]any{"type": "string"},
		"created_at":           map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "base_contract_id", "target_contract_id", "product_id", "result", "schema_version", "created_at"))
	registry.RegisterSchema("ContractDiffEnvelope", dataEnvelopeSchema("#/components/schemas/ContractDiff"))
	registry.RegisterSchema("SigningKey", objectSchema(map[string]any{
		"id":                         map[string]any{"type": "string"},
		"tenant_id":                  map[string]any{"type": "string"},
		"kid":                        map[string]any{"type": "string"},
		"version":                    map[string]any{"type": "integer", "minimum": 1},
		"provider":                   map[string]any{"type": "string"},
		"algorithm":                  map[string]any{"type": "string"},
		"status":                     map[string]any{"type": "string", "enum": []string{"active", "retiring", "revoked"}},
		"public_key":                 map[string]any{"type": "string"},
		"public_key_fingerprint":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"valid_from":                 map[string]any{"type": "string", "format": "date-time"},
		"valid_until":                map[string]any{"type": "string", "format": "date-time"},
		"created_at":                 map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":                 map[string]any{"type": "string", "format": "date-time"},
		"revocation_reason":          map[string]any{"type": "string"},
		"revocation_semantics":       map[string]any{"type": "string", "enum": []string{"ordinary", "compromised"}},
		"historical_validity_policy": map[string]any{"type": "string", "enum": []string{"preserve", "invalidate_from_compromise", "invalidate_all"}},
		"compromised_at":             map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "kid", "version", "provider", "algorithm", "status", "public_key", "valid_from", "created_at"))
	registry.RegisterSchema("SigningKeyEnvelope", dataEnvelopeSchema("#/components/schemas/SigningKey"))
	registry.RegisterSchema("SigningKeyListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/SigningKey"))
	registry.RegisterSchema("SigningKeyTransitionRequest", objectSchema(map[string]any{
		"reason":                     map[string]any{"type": "string", "minLength": 1},
		"semantics":                  map[string]any{"type": "string", "enum": []string{"ordinary", "compromised"}},
		"historical_validity_policy": map[string]any{"type": "string", "enum": []string{"preserve", "invalidate_from_compromise", "invalidate_all"}},
	}, "reason"))
	registry.RegisterSchema("CreateSigningProviderRequest", objectSchema(map[string]any{
		"name":      map[string]any{"type": "string"},
		"type":      map[string]any{"type": "string"},
		"key_ref":   map[string]any{"type": "string"},
		"encrypted": map[string]any{"type": "boolean"},
	}, "name", "type", "key_ref"))
	registry.RegisterSchema("SigningProvider", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"type":           map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"key_ref":        map[string]any{"type": "string"},
		"encrypted":      map[string]any{"type": "boolean"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "type", "status", "key_ref", "encrypted", "schema_version", "created_at"))
	registry.RegisterSchema("SigningProviderEnvelope", dataEnvelopeSchema("#/components/schemas/SigningProvider"))
	registry.RegisterSchema("SigningCustodyReviewReport", objectSchema(map[string]any{
		"report_type": map[string]any{"type": "string"},
		"tenant_id":   map[string]any{"type": "string"},
		"signing_providers": map[string]any{
			"type":  "array",
			"items": map[string]any{"$ref": "#/components/schemas/SigningProvider"},
		},
		"object_retention_policies": map[string]any{
			"type":  "array",
			"items": map[string]any{"$ref": "#/components/schemas/ObjectRetentionPolicy"},
		},
		"checks": map[string]any{
			"type":  "array",
			"items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"},
		},
		"assumptions":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at": map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "tenant_id", "checks", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("SigningCustodyReviewReportEnvelope", dataEnvelopeSchema("#/components/schemas/SigningCustodyReviewReport"))
	registry.RegisterSchema("CreateSigningOperationRequest", objectSchema(map[string]any{
		"provider_id":  map[string]any{"type": "string", "minLength": 1, "maxLength": verificationapp.MaxSigningOperationIDBytes, "description": "Tenant-owned current active provider; raw NUL-free UTF-8 is capped at 1024 bytes before trimming, including replay."},
		"subject_type": map[string]any{"type": "string", "enum": []string{"tenant", "product", "release", "evidence", "build", "customer_package"}, "maxLength": 128, "description": "Canonical supported subject; raw UTF-8 is capped at 128 bytes before trimming."},
		"subject_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": verificationapp.MaxSigningOperationIDBytes, "description": "Current tenant-owned subject; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"payload_hash": map[string]any{"type": "string", "maxLength": 128, "pattern": "^\\s*sha256:[0-9a-fA-F]{64}\\s*$", "description": "Declared SHA-256 payload digest, not raw payload bytes; raw NUL-free UTF-8 is capped at 128 bytes before trimming."},
	}, "provider_id", "subject_type", "subject_id", "payload_hash"))
	registry.RegisterSchema("SigningOperation", objectSchema(map[string]any{
		"id":                     map[string]any{"type": "string"},
		"tenant_id":              map[string]any{"type": "string"},
		"provider_id":            map[string]any{"type": "string"},
		"subject_type":           map[string]any{"type": "string"},
		"subject_id":             map[string]any{"type": "string"},
		"payload_hash":           map[string]any{"type": "string", "pattern": "^sha256:"},
		"canonical_payload_hash": map[string]any{"type": "string", "pattern": "^sha256:", "description": "Hash of the canonical provider-signing request; no raw payload bytes are stored."},
		"request_id":             map[string]any{"type": "string", "description": "Evydence signing-request identifier for safe retry correlation."},
		"provider_request_id":    map[string]any{"type": "string", "description": "Provider receipt identifier when returned by the signing provider; credentials and raw provider responses are never stored."},
		"signature_ref":          map[string]any{"type": "string"},
		"result":                 map[string]any{"type": "string"},
		"checks":                 map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"schema_version":         map[string]any{"type": "string"},
		"created_at":             map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "provider_id", "subject_type", "subject_id", "payload_hash", "result", "checks", "schema_version", "created_at"))
	registry.RegisterSchema("SigningOperationEnvelope", dataEnvelopeSchema("#/components/schemas/SigningOperation"))
	registry.RegisterSchema("CreateArtifactSignatureRequest", objectSchema(map[string]any{
		"artifact_id":        map[string]any{"type": "string"},
		"algorithm":          map[string]any{"type": "string"},
		"key_id":             map[string]any{"type": "string"},
		"signature":          map[string]any{"type": "string"},
		"payload":            map[string]any{"type": "object", "additionalProperties": true},
		"payload_media_type": map[string]any{"type": "string"},
	}, "artifact_id", "algorithm", "signature"))
	registry.RegisterSchema("ArtifactSignature", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"tenant_id":           map[string]any{"type": "string"},
		"artifact_id":         map[string]any{"type": "string"},
		"subject_digest":      map[string]any{"type": "string"},
		"algorithm":           map[string]any{"type": "string"},
		"key_id":              map[string]any{"type": "string"},
		"signature":           map[string]any{"type": "string"},
		"payload_ref":         map[string]any{"type": "string"},
		"payload_hash":        map[string]any{"type": "string", "pattern": "^sha256:"},
		"verification_status": map[string]any{"type": "string"},
		"schema_version":      map[string]any{"type": "string"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "artifact_id", "subject_digest", "algorithm", "signature", "verification_status", "schema_version", "created_at"))
	registry.RegisterSchema("ArtifactSignatureEnvelope", dataEnvelopeSchema("#/components/schemas/ArtifactSignature"))
	registry.RegisterSchema("VerifyCosignSignatureRequest", objectSchema(map[string]any{
		"expected_identity": map[string]any{"type": "string", "description": "Exact expected Fulcio certificate identity for keyless verification."},
		"expected_issuer":   map[string]any{"type": "string", "description": "Exact expected Fulcio OIDC issuer for keyless verification."},
		"mode":              map[string]any{"type": "string", "enum": []string{"keyless", "key"}, "description": "keyless requires expected_identity and expected_issuer; key rejects them and uses configured public-key trust material."},
		"offline":           map[string]any{"type": "boolean", "description": "Must be true for the currently supported explicit-offline bundle profile. The bundle must contain a verified Rekor inclusion proof."},
	}, "mode", "offline"))
	registry.RegisterSchema("CosignVerification", objectSchema(map[string]any{
		"id":                       map[string]any{"type": "string"},
		"tenant_id":                map[string]any{"type": "string"},
		"artifact_id":              map[string]any{"type": "string"},
		"container_image_id":       map[string]any{"type": "string"},
		"artifact_signature_id":    map[string]any{"type": "string"},
		"subject_digest":           map[string]any{"type": "string"},
		"rekor_uuid":               map[string]any{"type": "string"},
		"rekor_log_index":          map[string]any{"type": "string"},
		"certificate_identity":     map[string]any{"type": "string"},
		"certificate_issuer":       map[string]any{"type": "string"},
		"verifier_library_version": map[string]any{"type": "string"},
		"trust_root_version":       map[string]any{"type": "string"},
		"verification_mode":        map[string]any{"type": "string", "enum": []string{"keyless", "key"}},
		"result":                   map[string]any{"type": "string", "enum": []string{"passed", "failed", "not_verified", "limited", "skipped", "error"}, "description": "passed requires every profile check, including cryptographic signature, digest, trust, and embedded Rekor inclusion proof verification."},
		"checks":                   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"profile":                  map[string]any{"$ref": "#/components/schemas/VerificationProfile"},
		"limitations":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":           map[string]any{"type": "string"},
		"created_at":               map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "artifact_signature_id", "subject_digest", "result", "checks", "profile", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("CosignVerificationEnvelope", dataEnvelopeSchema("#/components/schemas/CosignVerification"))
	registry.RegisterSchema("DSSEEnvelope", objectSchema(map[string]any{
		"payloadType": map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "string"},
		"signatures": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"keyid": map[string]any{"type": "string"},
			"sig":   map[string]any{"type": "string"},
		}, "sig")},
	}, "payloadType", "payload", "signatures"))
	registry.RegisterSchema("BuildAttestation", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"tenant_id":           map[string]any{"type": "string"},
		"build_id":            map[string]any{"type": "string"},
		"evidence_id":         map[string]any{"type": "string"},
		"payload_ref":         map[string]any{"type": "string"},
		"payload_hash":        map[string]any{"type": "string", "pattern": "^sha256:"},
		"payload_size":        map[string]any{"type": "integer"},
		"payload_type":        map[string]any{"type": "string"},
		"predicate_type":      map[string]any{"type": "string"},
		"subject_digests":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"builder_id":          map[string]any{"type": "string"},
		"build_type":          map[string]any{"type": "string"},
		"materials_count":     map[string]any{"type": "integer"},
		"signature_count":     map[string]any{"type": "integer"},
		"verification_status": map[string]any{"type": "string"},
		"schema_version":      map[string]any{"type": "string"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "build_id", "evidence_id", "payload_hash", "payload_size", "payload_type", "predicate_type", "subject_digests", "signature_count", "verification_status", "schema_version", "created_at"))
	registry.RegisterSchema("BuildAttestationEnvelope", dataEnvelopeSchema("#/components/schemas/BuildAttestation"))
	registry.RegisterSchema("CreateDSSETrustRootRequest", objectSchema(map[string]any{
		"name":                    map[string]any{"type": "string"},
		"key_id":                  map[string]any{"type": "string"},
		"algorithm":               map[string]any{"type": "string", "enum": []string{"Ed25519"}},
		"public_key":              map[string]any{"type": "string", "description": "Base64-encoded Ed25519 public key."},
		"allowed_predicate_types": map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "enum": []string{"https://slsa.dev/provenance/v1"}}},
		"expected_builder_ids":    map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "minLength": 1}},
		"required_claims":         map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "enum": []string{"builder_id", "build_type", "external_parameters"}}},
	}, "name", "key_id", "algorithm", "public_key", "allowed_predicate_types", "expected_builder_ids", "required_claims"))
	registry.RegisterSchema("DSSETrustRoot", objectSchema(map[string]any{
		"id":                      map[string]any{"type": "string"},
		"tenant_id":               map[string]any{"type": "string"},
		"name":                    map[string]any{"type": "string"},
		"key_id":                  map[string]any{"type": "string"},
		"algorithm":               map[string]any{"type": "string"},
		"public_key":              map[string]any{"type": "string"},
		"allowed_predicate_types": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"expected_builder_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"required_claims":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"status":                  map[string]any{"type": "string"},
		"schema_version":          map[string]any{"type": "string"},
		"created_at":              map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "key_id", "algorithm", "public_key", "allowed_predicate_types", "expected_builder_ids", "required_claims", "status", "schema_version", "created_at"))
	registry.RegisterSchema("DSSETrustRootEnvelope", dataEnvelopeSchema("#/components/schemas/DSSETrustRoot"))
	createCandidateRequest := objectSchema(map[string]any{
		"release_id":   map[string]any{"type": "string"},
		"name":         map[string]any{"type": "string"},
		"build_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"artifact_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"sbom_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"scan_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"vex_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"contract_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"bundle_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "release_id", "name")
	createCandidateRequest["description"] = "PostgreSQL candidate creation uses a focused durable command requiring release:write and a matching tenant/product/release grant for human sessions. Current tenant-owned parent coordinates and all supplied reference IDs are validated in the active transaction without foreign-context payload or cached Ledger reads. Builds and parsed evidence/bundle references must belong to the same release; artifacts are tenant-scoped and human reuse needs a current authorized build/evidence association. Missing, foreign, wrong-release, or inconsistent source-evidence references return 404, and grant denial returns 403. Trimmed names and IDs are non-empty, NUL-free UTF-8: new names are bounded at 64 KiB, parent/reference IDs at 1024 bytes, and the combined reference arrays at 4096 entries and 64 KiB of identifier bytes. Sorting preserves duplicates. The whole HTTP JSON body is capped at 64 KiB including syntax/escapes. Invalid input returns 400 without candidate/audit writes. New snapshots start open at revision 1 with microsecond-precision UTC timestamps and the existing versioned normalized-JSON snapshot hash; candidate/audit effects commit together. Same-key replay returns the original snapshot and changed request bytes conflict. Local-memory creation retains its explicit compatibility binding."
	registry.RegisterSchema("CreateReleaseCandidateRequest", createCandidateRequest)
	candidateTransitionRequest := objectSchema(map[string]any{
		"reason": map[string]any{"type": "string"},
	}, "reason")
	candidateTransitionRequest["description"] = "Promotion/rejection requires a non-empty trimmed reason and a strong If-Match revision. In PostgreSQL, reason must be NUL-free UTF-8 and at most 64 KiB of UTF-8 bytes; the entire HTTP JSON body is also capped at 64 KiB. A focused command reads one locked candidate and its tenant-owned release/product coordinate, requires release:write and a matching tenant/product/release grant for human sessions, and authorizes before exposing revision conflicts. Only open candidates at the expected revision transition. State/revision/time changes and audit commit together; name, reference lists, snapshot hash, schema version, and creation metadata remain unchanged. Stored names are bounded at 64 KiB, IDs/schema identifiers at 1024 bytes, state at 32 bytes, hash at 128 bytes, and JSON snapshots at 1 MiB; unsupported stored snapshots fail with 409 rather than truncation. Local-memory transitions keep the explicit compatibility binding."
	registry.RegisterSchema("ReleaseCandidateTransitionRequest", candidateTransitionRequest)
	registry.RegisterSchema("ReleaseCandidate", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"revision":       map[string]any{"type": "integer", "format": "int64", "minimum": 1},
		"state":          map[string]any{"type": "string"},
		"build_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"artifact_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"sbom_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"scan_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"vex_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"contract_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"bundle_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"snapshot_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
		"promoted_at":    map[string]any{"type": "string", "format": "date-time"},
		"rejected_at":    map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "name", "revision", "state", "snapshot_hash", "schema_version", "created_at"))
	registry.RegisterSchema("ReleaseCandidateEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseCandidate"))
	registry.RegisterSchema("ReleaseCandidateListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/ReleaseCandidate"))
	registry.RegisterSchema("SupersedeEvidenceRequest", objectSchema(map[string]any{
		"replacement_evidence_id": map[string]any{"type": "string"},
		"reason":                  map[string]any{"type": "string"},
	}, "replacement_evidence_id", "reason"))
	registry.RegisterSchema("LinkEvidenceRequest", objectSchema(map[string]any{
		"target_type": map[string]any{"type": "string"},
		"target_id":   map[string]any{"type": "string"},
	}, "target_type", "target_id"))
	registry.RegisterSchema("RecordEvidenceLifecycleEventRequest", objectSchema(map[string]any{
		"action":         map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"details":        map[string]any{"type": "object", "additionalProperties": true},
		"replacement_id": map[string]any{"type": "string"},
	}, "action", "reason"))
	registry.RegisterSchema("EvidenceLifecycleEvent", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"action":         map[string]any{"type": "string"},
		"reason":         map[string]any{"type": "string"},
		"details":        map[string]any{"type": "object", "additionalProperties": true},
		"replacement_id": map[string]any{"type": "string"},
		"actor_id":       map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "evidence_id", "action", "reason", "actor_id", "schema_version", "created_at"))
	registry.RegisterSchema("EvidenceLifecycleEventEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceLifecycleEvent"))
	registry.RegisterSchema("EvidenceLifecycleEventListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/EvidenceLifecycleEvent"))
	registry.RegisterSchema("CreateSourceRepositoryRequest", objectSchema(map[string]any{
		"project_id":     map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"full_name":      map[string]any{"type": "string"},
		"clone_url":      map[string]any{"type": "string"},
		"default_branch": map[string]any{"type": "string"},
	}, "provider", "full_name"))
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
	registry.RegisterSchema("SourceRepositoryEnvelope", dataEnvelopeSchema("#/components/schemas/SourceRepository"))
	registry.RegisterSchema("SourceRepositoryListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/SourceRepository"))
	registry.RegisterSchema("RecordSourceCommitRequest", objectSchema(map[string]any{
		"repository_id": map[string]any{"type": "string"},
		"sha":           map[string]any{"type": "string"},
		"author":        map[string]any{"type": "string"},
		"message":       map[string]any{"type": "string", "description": "Commit message is hashed before storage."},
		"committed_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "repository_id", "sha"))
	registry.RegisterSchema("SourceCommit", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"repository_id":  map[string]any{"type": "string"},
		"sha":            map[string]any{"type": "string"},
		"author":         map[string]any{"type": "string"},
		"message_hash":   map[string]any{"type": "string", "pattern": "^sha256:"},
		"committed_at":   map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "repository_id", "sha", "committed_at", "schema_version", "created_at"))
	registry.RegisterSchema("SourceCommitEnvelope", dataEnvelopeSchema("#/components/schemas/SourceCommit"))
	registry.RegisterSchema("UpsertSourceBranchRequest", objectSchema(map[string]any{
		"repository_id":   map[string]any{"type": "string"},
		"name":            map[string]any{"type": "string"},
		"head_commit_id":  map[string]any{"type": "string"},
		"protected":       map[string]any{"type": "boolean"},
		"protection_hash": map[string]any{"type": "string"},
	}, "repository_id", "name"))
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
	registry.RegisterSchema("SourceBranchEnvelope", dataEnvelopeSchema("#/components/schemas/SourceBranch"))
	registry.RegisterSchema("RecordPullRequestRequest", objectSchema(map[string]any{
		"repository_id":   map[string]any{"type": "string"},
		"provider":        map[string]any{"type": "string"},
		"provider_id":     map[string]any{"type": "string"},
		"title":           map[string]any{"type": "string"},
		"state":           map[string]any{"type": "string"},
		"source_branch":   map[string]any{"type": "string"},
		"target_branch":   map[string]any{"type": "string"},
		"head_commit_id":  map[string]any{"type": "string"},
		"review_decision": map[string]any{"type": "string"},
	}, "repository_id", "provider_id", "title", "state"))
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
	}, "id", "tenant_id", "repository_id", "provider", "provider_id", "title", "state", "schema_version", "created_at"))
	registry.RegisterSchema("PullRequestEnvelope", dataEnvelopeSchema("#/components/schemas/PullRequest"))
	registry.RegisterSchema("CreateDeploymentEnvironmentRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
		"kind":       map[string]any{"type": "string"},
	}, "product_id", "name", "kind"))
	registry.RegisterSchema("DeploymentEnvironment", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"kind":           map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "name", "kind", "schema_version", "created_at"))
	registry.RegisterSchema("DeploymentEnvironmentEnvelope", dataEnvelopeSchema("#/components/schemas/DeploymentEnvironment"))
	registry.RegisterSchema("DeploymentEnvironmentListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/DeploymentEnvironment"))
	registry.RegisterSchema("RecordDeploymentRequest", objectSchema(map[string]any{
		"environment_id": map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"artifact_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"status":         map[string]any{"type": "string"},
		"started_at":     map[string]any{"type": "string", "format": "date-time"},
		"finished_at":    map[string]any{"type": "string", "format": "date-time"},
		"rollback_of":    map[string]any{"type": "string"},
	}, "environment_id", "release_id", "status"))
	registry.RegisterSchema("DeploymentEvent", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"environment_id": map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"artifact_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"status":         map[string]any{"type": "string"},
		"started_at":     map[string]any{"type": "string", "format": "date-time"},
		"finished_at":    map[string]any{"type": "string", "format": "date-time"},
		"rollback_of":    map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "environment_id", "release_id", "status", "started_at", "schema_version", "created_at"))
	registry.RegisterSchema("DeploymentEventEnvelope", dataEnvelopeSchema("#/components/schemas/DeploymentEvent"))
	registry.RegisterSchema("DeploymentEventListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/DeploymentEvent"))
	registry.RegisterSchema("RecordCollectorReleaseRequest", objectSchema(map[string]any{
		"version":         map[string]any{"type": "string"},
		"artifact_digest": map[string]any{"type": "string"},
		"signature_id":    map[string]any{"type": "string"},
		"sbom_id":         map[string]any{"type": "string"},
		"scan_id":         map[string]any{"type": "string"},
		"pinned":          map[string]any{"type": "boolean"},
	}, "version", "artifact_digest"))
	registry.RegisterSchema("CollectorRelease", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"tenant_id":           map[string]any{"type": "string"},
		"collector_id":        map[string]any{"type": "string"},
		"version":             map[string]any{"type": "string"},
		"artifact_digest":     map[string]any{"type": "string"},
		"signature_id":        map[string]any{"type": "string"},
		"sbom_id":             map[string]any{"type": "string"},
		"scan_id":             map[string]any{"type": "string"},
		"pinned":              map[string]any{"type": "boolean"},
		"verification_status": map[string]any{"type": "string"},
		"health_status":       map[string]any{"type": "string"},
		"limitations":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":      map[string]any{"type": "string"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "collector_id", "version", "artifact_digest", "pinned", "verification_status", "health_status", "schema_version", "created_at"))
	registry.RegisterSchema("CollectorReleaseEnvelope", dataEnvelopeSchema("#/components/schemas/CollectorRelease"))
	registry.RegisterSchema("CollectorHealthReport", objectSchema(map[string]any{
		"report_type":         map[string]any{"type": "string"},
		"collector_id":        map[string]any{"type": "string"},
		"collector_status":    map[string]any{"type": "string"},
		"version":             map[string]any{"type": "string"},
		"pinned_release_id":   map[string]any{"type": "string"},
		"supply_chain_status": map[string]any{"type": "string"},
		"checks":              map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"latest_release":      map[string]any{"$ref": "#/components/schemas/CollectorRelease"},
		"assumptions":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "collector_id", "collector_status", "supply_chain_status", "checks", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("CollectorHealthReportEnvelope", dataEnvelopeSchema("#/components/schemas/CollectorHealthReport"))
	registry.RegisterSchema("CreateCommercialCollectorRequest", objectSchema(map[string]any{
		"name":           map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"revision":       map[string]any{"type": "integer", "format": "int64", "minimum": 1},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"allowed_scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "name", "provider", "version", "manifest_hash"))
	registry.RegisterSchema("CommercialCollectorDefinition", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"allowed_scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"status":         map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "provider", "version", "manifest_hash", "allowed_scopes", "status", "schema_version", "created_at"))
	registry.RegisterSchema("CommercialCollectorDefinitionEnvelope", dataEnvelopeSchema("#/components/schemas/CommercialCollectorDefinition"))
	registry.RegisterSchema("CommercialCollectorDefinitionListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/CommercialCollectorDefinition"))
	registry.RegisterSchema("CreateMarketplaceCollectorRequest", objectSchema(map[string]any{
		"name":          map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxMarketplaceLabelBytes, "description": "Nonblank package label; raw NUL-free UTF-8 is capped at 256 bytes before trimming."},
		"provider":      map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxMarketplaceLabelBytes, "description": "Nonblank provider label; raw NUL-free UTF-8 is capped at 256 bytes before trimming. Registration does not endorse a provider."},
		"version":       map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxMarketplaceVersionBytes, "description": "Nonblank package version; raw NUL-free UTF-8 is capped at 128 bytes before trimming."},
		"publisher":     map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxMarketplaceLabelBytes, "description": "Nonblank publisher label; raw NUL-free UTF-8 is capped at 256 bytes before trimming."},
		"manifest_hash": map[string]any{"type": "string", "maxLength": experimentalapp.MaxMarketplaceDigestBytes, "pattern": `^\s*sha256:[A-Fa-f0-9]{64}\s*$`, "description": "Raw NUL-free UTF-8 is capped at 128 bytes before trimming; sha256: plus 64 hexadecimal characters, preserving hex case. This records a declared digest without verifying package bytes."},
		"signature_id":  map[string]any{"type": "string", "maxLength": experimentalapp.MaxMarketplaceIDBytes, "description": "Optional current tenant-owned signature reference; omission or empty string is allowed, whitespace-only is rejected. Raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"sbom_id":       map[string]any{"type": "string", "maxLength": experimentalapp.MaxMarketplaceIDBytes, "description": "Optional current tenant-owned SBOM reference; omission or empty string is allowed, whitespace-only is rejected. Raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"scan_id":       map[string]any{"type": "string", "maxLength": experimentalapp.MaxMarketplaceIDBytes, "description": "Optional current tenant-owned scan reference; omission or empty string is allowed, whitespace-only is rejected. Raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
	}, "name", "provider", "version", "publisher", "manifest_hash"))
	registry.RegisterSchema("MarketplaceCollector", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"publisher":      map[string]any{"type": "string"},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_id":   map[string]any{"type": "string"},
		"sbom_id":        map[string]any{"type": "string"},
		"scan_id":        map[string]any{"type": "string"},
		"state":          map[string]any{"type": "string"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "provider", "version", "publisher", "manifest_hash", "state", "schema_version", "created_at"))
	registry.RegisterSchema("MarketplaceCollectorEnvelope", dataEnvelopeSchema("#/components/schemas/MarketplaceCollector"))
	registry.RegisterSchema("MarketplaceCollectorListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/MarketplaceCollector"))
	registry.RegisterSchema("MarketplaceCollectorHealthReport", objectSchema(map[string]any{
		"report_type":         map[string]any{"type": "string"},
		"collector_id":        map[string]any{"type": "string"},
		"name":                map[string]any{"type": "string"},
		"provider":            map[string]any{"type": "string"},
		"version":             map[string]any{"type": "string"},
		"supply_chain_status": map[string]any{"type": "string"},
		"checks":              map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"collector":           map[string]any{"$ref": "#/components/schemas/MarketplaceCollector"},
		"assumptions":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "collector_id", "name", "provider", "version", "supply_chain_status", "checks", "collector", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("MarketplaceCollectorHealthReportEnvelope", dataEnvelopeSchema("#/components/schemas/MarketplaceCollectorHealthReport"))
	registry.RegisterSchema("ControlFrameworkTemplatePack", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"slug":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"description":    map[string]any{"type": "string"},
		"controls":       map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SecurityControl"}},
		"schema_version": map[string]any{"type": "string"},
	}, "id", "name", "slug", "version", "controls", "schema_version"))
	registry.RegisterSchema("ControlFrameworkTemplatePackListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/ControlFrameworkTemplatePack"))
	registerContainerImageRequest := objectSchema(map[string]any{
		"artifact_id": map[string]any{"type": "string"},
		"repository":  map[string]any{"type": "string"},
		"tag":         map[string]any{"type": "string"},
		"digest":      map[string]any{"type": "string"},
		"platform":    map[string]any{"type": "string"},
	}, "repository", "digest")
	registerContainerImageRequest["description"] = "PostgreSQL profile: normalized artifact IDs are limited to 1024 UTF-8 bytes and repository text to 65536 bytes. Newly stored tag and platform text are limited to 65536 UTF-8 bytes. Stored text must be NUL-free. Reuse of a tenant/repository/digest identity returns the original immutable image, ignoring submitted tag and platform. Registration records submitted metadata; it does not download or verify a registry image."
	registry.RegisterSchema("RegisterContainerImageRequest", registerContainerImageRequest)
	registry.RegisterSchema("ContainerImage", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"artifact_id":    map[string]any{"type": "string"},
		"repository":     map[string]any{"type": "string"},
		"tag":            map[string]any{"type": "string"},
		"digest":         map[string]any{"type": "string"},
		"platform":       map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "repository", "digest", "schema_version", "created_at"))
	registry.RegisterSchema("ContainerImageEnvelope", dataEnvelopeSchema("#/components/schemas/ContainerImage"))
	registry.RegisterSchema("CreateRedactionProfileRequest", objectSchema(map[string]any{
		"name":            map[string]any{"type": "string"},
		"description":     map[string]any{"type": "string"},
		"preset":          map[string]any{"type": "string", "enum": []string{"customer_safe", "security_review"}, "description": "Optional standard profile preset. When set, allowed_types and excluded_fields are server-defined and must be omitted."},
		"allowed_types":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"excluded_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}))
	registry.RegisterSchema("RedactionProfile", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"name":            map[string]any{"type": "string"},
		"description":     map[string]any{"type": "string"},
		"allowed_types":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"excluded_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "schema_version", "created_at"))
	registry.RegisterSchema("RedactionProfileEnvelope", dataEnvelopeSchema("#/components/schemas/RedactionProfile"))
	registry.RegisterSchema("CreateCustomerPackageRequest", objectSchema(map[string]any{
		"product_id":           map[string]any{"type": "string"},
		"release_id":           map[string]any{"type": "string"},
		"redaction_profile_id": map[string]any{"type": "string"},
		"title":                map[string]any{"type": "string"},
		"expires_at":           map[string]any{"type": "string", "format": "date-time"},
	}, "product_id", "redaction_profile_id", "title", "expires_at"))
	registry.RegisterSchema("CustomerSecurityPackage", objectSchema(map[string]any{
		"id":                     map[string]any{"type": "string"},
		"tenant_id":              map[string]any{"type": "string"},
		"product_id":             map[string]any{"type": "string"},
		"release_id":             map[string]any{"type": "string"},
		"redaction_profile_id":   map[string]any{"type": "string"},
		"title":                  map[string]any{"type": "string"},
		"state":                  map[string]any{"type": "string"},
		"manifest":               map[string]any{"type": "object", "additionalProperties": true},
		"manifest_hash":          map[string]any{"type": "string", "pattern": "^sha256:"},
		"distribution_watermark": map[string]any{"type": "string"},
		"expires_at":             map[string]any{"type": "string", "format": "date-time"},
		"access_count":           map[string]any{"type": "integer"},
		"schema_version":         map[string]any{"type": "string"},
		"created_at":             map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "redaction_profile_id", "title", "state", "manifest", "manifest_hash", "expires_at", "access_count", "schema_version", "created_at"))
	registry.RegisterSchema("CustomerSecurityPackageEnvelope", dataEnvelopeSchema("#/components/schemas/CustomerSecurityPackage"))
	registry.RegisterSchema("SecurityReviewPackageReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"package_id":       map[string]any{"type": "string"},
		"product_id":       map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"evidence_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "package_id", "product_id", "evidence_ids", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("SecurityReviewPackageReportEnvelope", dataEnvelopeSchema("#/components/schemas/SecurityReviewPackageReport"))
	registry.RegisterSchema("HTMLReportPackage", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"report_type":    map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"html":           map[string]any{"type": "string"},
		"hash":           map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "report_type", "product_id", "html", "hash", "schema_version", "created_at"))
	registry.RegisterSchema("HTMLReportPackageEnvelope", dataEnvelopeSchema("#/components/schemas/HTMLReportPackage"))
	registry.RegisterSchema("CreateReportTemplateRequest", objectSchema(map[string]any{
		"name":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"report_type":    map[string]any{"type": "string"},
		"allowed_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"template":       map[string]any{"type": "string"},
	}, "name", "version", "report_type", "allowed_fields", "template"))
	registry.RegisterSchema("CustomReportTemplate", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"report_type":    map[string]any{"type": "string"},
		"allowed_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"template":       map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "version", "report_type", "allowed_fields", "template", "schema_version", "created_at"))
	registry.RegisterSchema("CustomReportTemplateEnvelope", dataEnvelopeSchema("#/components/schemas/CustomReportTemplate"))
	registry.RegisterSchema("RenderReportTemplateRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
	}, "subject_type", "subject_id"))
	registry.RegisterSchema("RenderedCustomReport", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"template_id":    map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"output":         map[string]any{"type": "object", "additionalProperties": true},
		"hash":           map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "template_id", "subject_type", "subject_id", "output", "hash", "schema_version", "created_at"))
	registry.RegisterSchema("RenderedCustomReportEnvelope", dataEnvelopeSchema("#/components/schemas/RenderedCustomReport"))
	registry.RegisterSchema("ExportEvidenceBundleRequest", objectSchema(map[string]any{
		"release_id":   map[string]any{"type": "string"},
		"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}))
	registry.RegisterSchema("EvidenceBundle", objectSchema(map[string]any{
		"id":                map[string]any{"type": "string"},
		"tenant_id":         map[string]any{"type": "string"},
		"release_id":        map[string]any{"type": "string"},
		"evidence_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"manifest":          map[string]any{"type": "object", "additionalProperties": true},
		"manifest_hash":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_refs":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"verification_text": map[string]any{"type": "string"},
		"schema_version":    map[string]any{"type": "string"},
		"created_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "evidence_ids", "manifest", "manifest_hash", "verification_text", "schema_version", "created_at"))
	registry.RegisterSchema("EvidenceBundleEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceBundle"))
	registry.RegisterSchema("EvidenceBundleImport", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"bundle_hash":    map[string]any{"type": "string", "pattern": "^sha256:"},
		"result":         map[string]any{"type": "string"},
		"imported_count": map[string]any{"type": "integer"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "bundle_hash", "result", "imported_count", "schema_version", "created_at"))
	registry.RegisterSchema("EvidenceBundleImportEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceBundleImport"))
	registry.RegisterSchema("CreateEvidenceSummaryRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string", "enum": []string{"tenant", "product", "release", "evidence", "build", "customer_package"}},
		"subject_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxEvidenceSummaryIDBytes, "description": "Non-blank, NUL-free UTF-8 identifier, at most 1024 bytes after trimming."},
		"evidence_ids": map[string]any{"type": "array", "maxItems": packageapp.MaxEvidenceSummaryItems, "uniqueItems": true, "description": "Omit or use [] for automatic selection; explicit identifiers must remain unique and non-blank after trimming, with at most 1024 bytes each.", "items": map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxEvidenceSummaryIDBytes}},
	}, "subject_type", "subject_id"))
	registry.RegisterSchema("EvidenceCitation", objectSchema(map[string]any{
		"evidence_id":    map[string]any{"type": "string"},
		"type":           map[string]any{"type": "string"},
		"title":          map[string]any{"type": "string"},
		"canonical_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
	}, "evidence_id", "type", "title", "canonical_hash"))
	registry.RegisterSchema("EvidenceSummary", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"evidence_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"summary":        map[string]any{"type": "string"},
		"citations":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/EvidenceCitation"}},
		"assumptions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "evidence_ids", "summary", "citations", "assumptions", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("EvidenceSummaryEnvelope", dataEnvelopeSchema("#/components/schemas/EvidenceSummary"))
	registry.RegisterSchema("QuestionnaireQuestion", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"prompt":         map[string]any{"type": "string"},
		"evidence_type":  map[string]any{"type": "string"},
		"control_id":     map[string]any{"type": "string"},
		"allowed_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "id", "prompt"))
	registry.RegisterSchema("QuestionnaireResponse", objectSchema(map[string]any{
		"question_id":  map[string]any{"type": "string"},
		"answer":       map[string]any{"type": "string"},
		"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "question_id", "answer"))
	registry.RegisterSchema("CreateQuestionnaireTemplateRequest", objectSchema(map[string]any{
		"name":      map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Required nonblank name; trimmed after a 1024-byte UTF-8/NUL-free raw input bound."},
		"version":   map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Required nonblank version; trimmed after a 1024-byte UTF-8/NUL-free raw input bound."},
		"questions": map[string]any{"type": "array", "minItems": 1, "maxItems": packageapp.MaxQuestionnaireTemplateQuestions, "description": "Ordered questions with unique trimmed IDs; aggregate input text and encoded template are each limited to 4 MiB.", "items": map[string]any{"$ref": "#/components/schemas/CreateQuestionnaireQuestion"}},
	}, "name", "version", "questions"))
	registry.RegisterSchema("CreateQuestionnaireQuestion", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Nonblank and unique after trimming; raw UTF-8/NUL-free input is limited to 1024 bytes."},
		"prompt":         map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireTemplatePromptBytes, "description": "Nonblank prompt, trimmed after a 64 KiB raw UTF-8/NUL-free input bound."},
		"evidence_type":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Optional trimmed evidence selector; raw UTF-8/NUL-free input is limited to 1024 bytes."},
		"control_id":     map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Optional trimmed tenant-owned control with a current same-tenant framework; raw UTF-8/NUL-free input is limited to 1024 bytes."},
		"allowed_fields": map[string]any{"type": "array", "maxItems": packageapp.MaxQuestionnaireTemplateFields, "description": "Inert metadata, trimmed and sorted; duplicates and blank strings retain their existing meaning.", "items": map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireTemplateTextBytes, "description": "Raw UTF-8/NUL-free input is limited to 1024 bytes."}},
	}, "id", "prompt"))
	registry.RegisterSchema("QuestionnaireTemplate", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"version":        map[string]any{"type": "string"},
		"questions":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/QuestionnaireQuestion"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "version", "questions", "schema_version", "created_at"))
	registry.RegisterSchema("QuestionnaireTemplateEnvelope", dataEnvelopeSchema("#/components/schemas/QuestionnaireTemplate"))
	registry.RegisterSchema("CreateQuestionnairePackageRequest", objectSchema(map[string]any{
		"template_id": map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Required tenant-owned template; raw UTF-8/NUL-free bytes are bounded before trimming."},
		"package_id":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Optional current tenant-owned customer package association, independently authorized and coherent with explicit selection coordinates. It never supplies an implicit evidence filter or redaction."},
		"product_id":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Optional tenant-owned product selection; must agree with release_id and package_id when supplied."},
		"release_id":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Optional tenant-owned release selection; its product is resolved for authorization only, not added to the stored selection."},
	}, "template_id"))
	registry.RegisterSchema("QuestionnairePackage", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"template_id":    map[string]any{"type": "string"},
		"package_id":     map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"responses":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/QuestionnaireResponse"}},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "template_id", "responses", "manifest_hash", "schema_version", "created_at"))
	registry.RegisterSchema("QuestionnairePackageEnvelope", dataEnvelopeSchema("#/components/schemas/QuestionnairePackage"))
	registry.RegisterSchema("CreateQuestionnaireDraftRequest", objectSchema(map[string]any{
		"template_id": map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Required tenant-owned template identifier; trimmed after a 1024-byte UTF-8/NUL-free input bound."},
		"product_id":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Optional tenant-owned product; must agree with release_id when both are supplied."},
		"release_id":  map[string]any{"type": "string", "maxLength": packageapp.MaxQuestionnaireDraftIDBytes, "description": "Optional tenant-owned release; current parent ownership is checked."},
	}, "template_id"))
	registry.RegisterSchema("QuestionnaireDraft", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"template_id":    map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"responses":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/QuestionnaireResponse"}},
		"manifest_hash":  map[string]any{"type": "string", "pattern": "^sha256:"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "template_id", "responses", "manifest_hash", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("QuestionnaireDraftEnvelope", dataEnvelopeSchema("#/components/schemas/QuestionnaireDraft"))
	answerLibraryRequest := objectSchema(map[string]any{
		"question_id":   map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryIDBytes, "description": "Optional question selector; at least one nonblank question_id, evidence_type or control_id is required. Raw input is bounded to 1024 UTF-8/NUL-free bytes before trimming."},
		"evidence_type": map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryIDBytes, "description": "Optional inert evidence-type selector, not a validation or trust claim."},
		"control_id":    map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryIDBytes, "description": "Optional current same-tenant control with a same-tenant framework."},
		"product_id":    map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryIDBytes, "description": "Optional current tenant-owned product; must agree with release_id. Citation filtering uses stored product_id, not inferred evidence parents."},
		"release_id":    map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryIDBytes, "description": "Optional current tenant-owned release; its product is resolved for authorization only, not added to the response."},
		"answer":        map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxAnswerLibraryTextBytes, "description": "Required nonblank draft answer, trimmed after a 64 KiB raw UTF-8/NUL-free byte bound. The complete HTTP body retains its 64 KiB limit."},
		"evidence_ids":  map[string]any{"type": "array", "maxItems": packageapp.MaxAnswerLibraryEvidenceIDs, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxAnswerLibraryIDBytes}, "description": "Optional current same-tenant evidence references, sorted with duplicates preserved; each ID is nonblank and bounded to 1024 raw bytes. All stored parents must be coherent."},
		"limitations":   map[string]any{"type": "array", "maxItems": packageapp.MaxAnswerLibraryLimitations, "items": map[string]any{"type": "string", "maxLength": packageapp.MaxAnswerLibraryTextBytes}, "description": "Optional limitations, each bounded to 64 KiB raw bytes, trimmed/sorted with duplicates and blanks preserved. Omitted or empty arrays use the existing human-review warning."},
	}, "answer")
	answerLibraryRequest["anyOf"] = []any{
		map[string]any{"required": []string{"question_id"}, "properties": map[string]any{"question_id": map[string]any{"minLength": 1}}},
		map[string]any{"required": []string{"evidence_type"}, "properties": map[string]any{"evidence_type": map[string]any{"minLength": 1}}},
		map[string]any{"required": []string{"control_id"}, "properties": map[string]any{"control_id": map[string]any{"minLength": 1}}},
	}
	registry.RegisterSchema("CreateQuestionnaireAnswerLibraryEntryRequest", answerLibraryRequest)
	registry.RegisterSchema("QuestionnaireAnswerLibraryEntry", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"question_id":    map[string]any{"type": "string"},
		"evidence_type":  map[string]any{"type": "string"},
		"control_id":     map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"answer":         map[string]any{"type": "string"},
		"evidence_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "answer", "schema_version", "created_at"))
	registry.RegisterSchema("QuestionnaireAnswerLibraryEntryEnvelope", dataEnvelopeSchema("#/components/schemas/QuestionnaireAnswerLibraryEntry"))
	registry.RegisterSchema("QuestionnaireAnswerLibraryEntryListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/QuestionnaireAnswerLibraryEntry"))
	registry.RegisterSchema("CreatePDFReportPackageRequest", objectSchema(map[string]any{
		"report_type": map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "description": "Nonblank trimmed descriptive metadata, not a renderer selector. Raw single-line UTF-8 is capped at 128 bytes and excludes control characters."},
		"product_id":  map[string]any{"type": "string", "maxLength": 1024, "description": "Optional submitted product coordinate. At least one product/release ID must be nonblank. Raw UTF-8 IDs are capped at 1024 bytes, trimmed and NUL-free; a supplied product must own the supplied release."},
		"release_id":  map[string]any{"type": "string", "maxLength": 1024, "description": "Optional submitted release coordinate. Release-only creation checks the current product parent without adding a product_id to the record."},
		"title":       map[string]any{"type": "string", "minLength": 1, "maxLength": 65536, "description": "Nonblank single-line title, trimmed after validating at most 64 KiB raw UTF-8 without control characters or Unicode line/paragraph separators. The existing payload is a minimal title-only envelope, not a full evidence report."},
	}, "report_type", "title"))
	registry.RegisterSchema("PDFReportPackage", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"report_type":    map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"title":          map[string]any{"type": "string"},
		"payload_ref":    map[string]any{"type": "string"},
		"payload_hash":   map[string]any{"type": "string", "pattern": "^sha256:"},
		"payload_size":   map[string]any{"type": "integer"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "report_type", "title", "payload_hash", "payload_size", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("PDFReportPackageEnvelope", dataEnvelopeSchema("#/components/schemas/PDFReportPackage"))
	registry.RegisterSchema("ReadinessReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"product_id":       map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"result":           map[string]any{"type": "string"},
		"policy_set":       map[string]any{"type": "string"},
		"summary": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"headline":      map[string]any{"type": "string"},
			"result":        map[string]any{"type": "string"},
			"human_summary": map[string]any{"type": "string"},
			"policy_set":    map[string]any{"type": "string"},
		}},
		"checks": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"sections": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
			"id":      map[string]any{"type": "string"},
			"title":   map[string]any{"type": "string"},
			"status":  map[string]any{"type": "string"},
			"summary": map[string]any{"type": "string"},
			"questions": map[string]any{"type": "array", "items": map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
				"id":                map[string]any{"type": "string"},
				"question":          map[string]any{"type": "string"},
				"answer":            map[string]any{"type": "string"},
				"status":            map[string]any{"type": "string"},
				"evidence":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"checks":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"missing_evidence":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"failed_policies":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"known_limitations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			}}},
		}}},
		"gaps":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"missing_evidence":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"failed_policies":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"known_limitations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"non_claims":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":      map[string]any{"type": "string", "format": "date-time"},
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
		"trust_material_updated_at": map[string]any{"type": "string", "format": "date-time"},
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
		"result":         map[string]any{"type": "string", "enum": []string{"passed", "failed", "not_verified", "limited", "skipped", "error"}},
		"checks":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"profile":        map[string]any{"$ref": "#/components/schemas/VerificationProfile"},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "provider_type", "provider_id", "subject", "result", "checks", "profile", "limitations", "schema_version", "created_at"))
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
		"verified":    map[string]any{"type": "boolean", "enum": []bool{true}},
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
		"groups":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Provider group claim values captured for session-scoped role mapping."},
		"expires_at":     map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":     map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "user_id", "provider_id", "prefix", "expires_at", "schema_version", "created_at"))
	registry.RegisterSchema("SSOSessionEnvelope", dataEnvelopeSchema("#/components/schemas/SSOSession"))
	registry.RegisterSchema("SSOSessionCreateResponse", objectSchema(map[string]any{
		"session": map[string]any{"$ref": "#/components/schemas/SSOSession"},
		"secret":  map[string]any{"type": "string", "description": "One-time SSO session bearer secret; not returned by list/read operations. Present only in the initial successful response and omitted from idempotency replays."},
	}, "session"))
	registry.RegisterSchema("SSOSessionCreateEnvelope", dataEnvelopeSchema("#/components/schemas/SSOSessionCreateResponse"))
	registry.RegisterSchema("SSOCredentialExchangeResponse", objectSchema(map[string]any{
		"verification": map[string]any{"$ref": "#/components/schemas/ProviderVerification"},
		"session":      map[string]any{"$ref": "#/components/schemas/SSOSession"},
		"secret":       map[string]any{"type": "string", "description": "One-time SSO session bearer secret; also set as an HttpOnly cookie for browser clients."},
	}, "verification", "session", "secret"))
	registry.RegisterSchema("SSOCredentialExchangeEnvelope", dataEnvelopeSchema("#/components/schemas/SSOCredentialExchangeResponse"))
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
		"secret":  map[string]any{"type": "string", "description": "One-time API key secret; stored only as a peppered HMAC hash. Present only in the initial successful response and omitted from idempotency replays."},
	}, "api_key"))
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
		"secret":    map[string]any{"type": "string", "description": "One-time collector API key secret; stored only as a peppered HMAC hash. Present only in the initial successful response and omitted from idempotency replays."},
	}, "collector", "api_key"))
	registry.RegisterSchema("CollectorCreateEnvelope", dataEnvelopeSchema("#/components/schemas/CollectorCreateResponse"))
	registry.RegisterSchema("CollectorListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/Collector"))
	createControlFrameworkRequest := objectSchema(map[string]any{
		"name":        map[string]any{"type": "string"},
		"slug":        map[string]any{"type": "string"},
		"version":     map[string]any{"type": "string"},
		"description": map[string]any{"type": "string"},
	}, "name", "version")
	createControlFrameworkRequest["description"] = "Creates a versioned framework with controls:admin. PostgreSQL uses a focused transaction with a tenant-scoped existence check and atomic audit; human sessions need a current tenant-level grant. Name/version are trimmed and non-empty; an omitted or blank slug is derived from the name using the existing ASCII slug rule. Explicit slugs are retained. New name/description text is NUL-free UTF-8 bounded at 64 KiB each; slug/version together are bounded at 1024 UTF-8 bytes. The HTTP body is capped at 64 KiB including JSON syntax/escapes. Supplied fields cannot be null. Duplicate tenant/slug/version keys return 409; same-key retry returns the original result, and changed request bytes conflict. Creation timestamps use microsecond-precision UTC in PostgreSQL. Local-memory mode retains its compatibility command."
	registry.RegisterSchema("CreateControlFrameworkRequest", createControlFrameworkRequest)
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
	createSecurityControlRequest := objectSchema(map[string]any{
		"framework_id":          map[string]any{"type": "string"},
		"code":                  map[string]any{"type": "string"},
		"title":                 map[string]any{"type": "string"},
		"objective":             map[string]any{"type": "string"},
		"evidence_requirements": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ControlEvidenceRequirement"}},
		"applicability":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "framework_id", "code", "title", "objective")
	createSecurityControlRequest["description"] = "Creates a control under a current tenant-owned framework with controls:admin. PostgreSQL human sessions need a current tenant-level grant; ownership, code uniqueness, insertion, and audit use one focused transaction without Ledger inventory reads. Missing/foreign frameworks return 404, grant denial 403, and duplicate framework/code keys 409. Trimmed IDs/code/title/objective are non-empty NUL-free UTF-8. Framework IDs and codes are bounded at 1024 bytes each, and tenant ID plus framework ID plus code at 2048 bytes; title/objective are bounded at 64 KiB each. At most ten unique supported evidence requirement types are accepted, in request order, with freshness_days from 0 through 3650. Each requirement must supply its non-null required boolean (false is valid). Optional arrays may be omitted, but supplied fields/items cannot be null. Applicability is trimmed/sorted with duplicates and empty entries retained; limitations are trimmed in order with blank entries omitted. These two lists together are bounded at 1024 input entries and 64 KiB of input text. The entire HTTP JSON body is capped at 64 KiB including syntax/escapes. Invalid input returns 400 without control/audit writes. Same-key retry returns the original result; changed request bytes conflict. Local-memory mode retains its compatibility command."
	registry.RegisterSchema("CreateSecurityControlRequest", createSecurityControlRequest)
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
	linkControlEvidenceRequest := objectSchema(map[string]any{
		"evidence_type": map[string]any{"type": "string"},
		"subject_type":  map[string]any{"type": "string"},
		"subject_id":    map[string]any{"type": "string"},
		"product_id":    map[string]any{"type": "string"},
		"release_id":    map[string]any{"type": "string"},
		"confidence":    map[string]any{"type": "string", "enum": []string{"high", "medium", "low", "unsupported"}},
		"notes":         map[string]any{"type": "string"},
	}, "evidence_type", "subject_type", "subject_id", "confidence")
	linkControlEvidenceRequest["description"] = "Creates an append-only control evidence link with controls:write. PostgreSQL resolves the current tenant-owned control/framework, subject, typed source evidence, and scoped parents inside the idempotent command transaction without Ledger inventory reads. Human sessions need a current matching resource grant. Product/release IDs are optional association filters, not ownership proof; artifact grants require a matching current evidence/build association. Supported subject types are evidence, evidence_item, product, release, artifact, sbom, vulnerability_scan, vex, vulnerability_decision, finding, vulnerability_finding, exception, build, build_attestation, openapi_contract, and release_bundle. Missing, foreign, or unsupported subjects return 404; grant denial returns 403; ambiguous findings return 409. Required fields must be supplied; no supplied field may be null. Trimmed IDs/types/confidence are NUL-free UTF-8, each identity field is bounded at 1024 bytes, and the natural key (tenant, control, evidence type, subject type, subject ID, supplied product and release) at 2048 bytes. Notes are trimmed, NUL-free UTF-8, and bounded at 64 KiB. The entire HTTP JSON body is capped at 64 KiB including syntax/escapes. Natural-key duplicates return the original link unchanged, even with different confidence/notes, after current subject authorization; they append no audit entry. Same idempotency key and request bytes replay the original response; changed request bytes conflict. Link, audit, and completed replay commit together. Invalid input returns 400; failed writes leave no link/audit pair. Local-memory mode retains its explicit compatibility command."
	registry.RegisterSchema("LinkControlEvidenceRequest", linkControlEvidenceRequest)
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
	createProductRequest := objectSchema(map[string]any{
		"name": map[string]any{"type": "string"},
		"slug": map[string]any{"type": "string", "description": "Nonempty product slug, trimmed before validation; at most 1024 UTF-8 bytes so the tenant/slug natural identity fits the supported PostgreSQL index."},
	}, "name", "slug")
	createProductRequest["description"] = "Product creation accepts name and slug and requires product:write. PostgreSQL human sessions also need a matching tenant-level grant, not a grant on an existing product. Authorization is rechecked before a tenant-scoped boolean slug-existence query, and product/audit effects commit together; cached Ledger products are not used. Slugs are unique within a tenant: a different-key request for an existing slug returns 409, while same-key replay returns the original product. Trimmed names and slugs must be non-empty, NUL-free UTF-8; new names are bounded at 64 KiB of UTF-8 bytes and slugs at 1024 bytes. The entire HTTP JSON body is limited to 64 KiB, including syntax and escapes. Invalid input returns 400 without product/audit writes. Creation timestamps use microsecond-precision UTC. Explicit local-memory mode retains its compatibility binding."
	registry.RegisterSchema("CreateProductRequest", createProductRequest)
	registry.RegisterSchema("Product", objectSchema(map[string]any{
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
		"slug":       map[string]any{"type": "string"},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "slug", "created_at"))
	registry.RegisterSchema("ProductEnvelope", dataEnvelopeSchema("#/components/schemas/Product"))
	registry.RegisterSchema("ProductListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/Product"))
	createProjectRequest := objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
	}, "product_id", "name")
	createProjectRequest["description"] = "Project creation accepts only product_id and name and requires project:write. PostgreSQL human sessions also need a tenant or matching product grant. The current tenant-owned product is rechecked in the write transaction and project/audit effects commit together; cached Ledger products are not used. Trimmed product IDs and names must be non-empty, NUL-free UTF-8; product IDs are bounded at 1024 UTF-8 bytes and new project names at 64 KiB of UTF-8 bytes. Unsupported input returns 400 and oversized stored parent coordinates return 409, never truncated values. Explicit local-memory mode retains its compatibility path."
	registry.RegisterSchema("CreateProjectRequest", createProjectRequest)
	registry.RegisterSchema("Project", objectSchema(map[string]any{
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"product_id": map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "name", "created_at"))
	registry.RegisterSchema("ProjectEnvelope", dataEnvelopeSchema("#/components/schemas/Project"))
	createReleaseRequest := objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"version":    map[string]any{"type": "string"},
	}, "product_id", "version")
	createReleaseRequest["description"] = "Release creation accepts product_id and version and requires release:write. PostgreSQL human sessions also need a tenant or matching product grant. The current tenant-owned product is rechecked in the write transaction and release/audit effects commit together; cached Ledger products and releases are not used. New releases start in draft at revision 1. Versions are unique within each product: a different-key request for an existing version returns 409, while same-key replay returns the original release. Trimmed product IDs and versions must be non-empty, NUL-free UTF-8; product IDs are bounded at 1024 UTF-8 bytes and new release versions at 64 KiB of UTF-8 bytes. Unsupported input returns 400 and oversized stored parent coordinates return 409, never truncated values. Explicit local-memory mode retains its compatibility path. Recording a release does not assert approval, verification, or compliance."
	registry.RegisterSchema("CreateReleaseRequest", createReleaseRequest)
	registry.RegisterSchema("Release", objectSchema(map[string]any{
		"id":          map[string]any{"type": "string"},
		"tenant_id":   map[string]any{"type": "string"},
		"product_id":  map[string]any{"type": "string"},
		"version":     map[string]any{"type": "string"},
		"revision":    map[string]any{"type": "integer", "minimum": 1},
		"state":       map[string]any{"type": "string", "enum": []string{"draft", "frozen", "approved"}},
		"created_at":  map[string]any{"type": "string", "format": "date-time"},
		"frozen_at":   map[string]any{"type": "string", "format": "date-time"},
		"approved_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "version", "revision", "state", "created_at"))
	registry.RegisterSchema("ReleaseEnvelope", dataEnvelopeSchema("#/components/schemas/Release"))
	registry.RegisterSchema("ReleaseEvidenceFlowStep", objectSchema(map[string]any{
		"id":                   map[string]any{"type": "string"},
		"title":                map[string]any{"type": "string"},
		"status":               map[string]any{"type": "string", "enum": []string{"present", "missing", "optional"}},
		"required":             map[string]any{"type": "boolean"},
		"method":               map[string]any{"type": "string"},
		"path":                 map[string]any{"type": "string"},
		"required_scopes":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"idempotency_required": map[string]any{"type": "boolean"},
		"description":          map[string]any{"type": "string"},
		"next_reference":       map[string]any{"type": "string"},
	}, "id", "title", "status", "required", "method", "path", "required_scopes", "idempotency_required", "description"))
	registry.RegisterSchema("ReleaseEvidenceFlow", objectSchema(map[string]any{
		"release_id":     map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string", "enum": []string{"needs_evidence", "ready_for_review"}},
		"counts":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"steps":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ReleaseEvidenceFlowStep"}},
		"assumptions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"generated_at":   map[string]any{"type": "string", "format": "date-time"},
	}, "release_id", "product_id", "status", "counts", "steps", "assumptions", "limitations", "schema_version", "generated_at"))
	registry.RegisterSchema("ReleaseEvidenceFlowEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseEvidenceFlow"))
	registry.RegisterSchema("ReleaseSecurityProductSummary", objectSchema(map[string]any{
		"id":   map[string]any{"type": "string"},
		"name": map[string]any{"type": "string"},
		"slug": map[string]any{"type": "string"},
	}, "id", "name", "slug"))
	registry.RegisterSchema("ReleaseSecurityReleaseSummary", objectSchema(map[string]any{
		"id":      map[string]any{"type": "string"},
		"version": map[string]any{"type": "string"},
		"state":   map[string]any{"type": "string"},
	}, "id", "version", "state"))
	registry.RegisterSchema("ReleaseSecurityMissingDecision", objectSchema(map[string]any{
		"finding_id":    map[string]any{"type": "string"},
		"scan_id":       map[string]any{"type": "string"},
		"vulnerability": map[string]any{"type": "string"},
		"component":     map[string]any{"type": "string"},
		"severity":      map[string]any{"type": "string"},
		"state":         map[string]any{"type": "string"},
	}, "finding_id", "scan_id", "vulnerability", "severity", "state"))
	registry.RegisterSchema("ReleaseSecurityApprovalSummary", objectSchema(map[string]any{
		"total":    map[string]any{"type": "integer"},
		"approved": map[string]any{"type": "integer"},
	}, "total", "approved"))
	registry.RegisterSchema("ReleaseSecurityExceptionSummary", objectSchema(map[string]any{
		"total":              map[string]any{"type": "integer"},
		"approved_unexpired": map[string]any{"type": "integer"},
		"unapproved":         map[string]any{"type": "integer"},
		"expired":            map[string]any{"type": "integer"},
	}, "total", "approved_unexpired", "unapproved", "expired"))
	registry.RegisterSchema("ReleaseSecuritySummary", objectSchema(map[string]any{
		"product":                    map[string]any{"$ref": "#/components/schemas/ReleaseSecurityProductSummary"},
		"release":                    map[string]any{"$ref": "#/components/schemas/ReleaseSecurityReleaseSummary"},
		"artifact_count":             map[string]any{"type": "integer"},
		"sbom_status":                map[string]any{"type": "string", "enum": []string{"present", "missing"}},
		"vulnerability_scan_status":  map[string]any{"type": "string", "enum": []string{"present", "missing"}},
		"open_findings_by_severity":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"decisions_by_status":        map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"missing_required_decisions": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/ReleaseSecurityMissingDecision"}},
		"approval_summary":           map[string]any{"$ref": "#/components/schemas/ReleaseSecurityApprovalSummary"},
		"exception_summary":          map[string]any{"$ref": "#/components/schemas/ReleaseSecurityExceptionSummary"},
		"readiness_status":           map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"package_status":             map[string]any{"type": "string", "enum": []string{"generated", "not_generated"}},
		"counts":                     map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"assumptions":                map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":                map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":             map[string]any{"type": "string"},
		"generated_at":               map[string]any{"type": "string", "format": "date-time"},
	}, "product", "release", "artifact_count", "sbom_status", "vulnerability_scan_status", "open_findings_by_severity", "decisions_by_status", "approval_summary", "exception_summary", "readiness_status", "package_status", "counts", "assumptions", "limitations", "schema_version", "generated_at"))
	registry.RegisterSchema("ReleaseSecuritySummaryEnvelope", dataEnvelopeSchema("#/components/schemas/ReleaseSecuritySummary"))
	registerArtifactRequest := objectSchema(map[string]any{
		"name":       map[string]any{"type": "string"},
		"media_type": map[string]any{"type": "string"},
		"digest":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"size":       map[string]any{"type": "integer", "minimum": 0},
	}, "name", "media_type", "digest")
	registerArtifactRequest["description"] = "Artifact metadata registration requires evidence:write. Names and media types are trimmed and non-empty; digest is sha256: followed by 64 hexadecimal digits; size defaults to zero and must be non-negative. PostgreSQL reuse of a tenant digest requires current artifact authorization and returns the original immutable metadata without another audit entry. New stored names and media types must be NUL-free UTF-8, each at most 64 KiB of UTF-8 bytes; unsupported new text returns 400 and oversized existing metadata returns 409, never truncated values. Explicit local-memory mode retains its compatibility path. Registration does not upload bytes or establish digest, signature, or provenance trust."
	registry.RegisterSchema("RegisterArtifactRequest", registerArtifactRequest)
	registry.RegisterSchema("Artifact", objectSchema(map[string]any{
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"name":       map[string]any{"type": "string"},
		"media_type": map[string]any{"type": "string"},
		"digest":     map[string]any{"type": "string"},
		"size":       map[string]any{"type": "integer", "minimum": 0},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "media_type", "digest", "size", "created_at"))
	registry.RegisterSchema("ArtifactEnvelope", dataEnvelopeSchema("#/components/schemas/Artifact"))
	registry.RegisterSchema("BuildOutput", objectSchema(map[string]any{
		"artifact_id": map[string]any{"type": "string"},
		"digest":      map[string]any{"type": "string"},
	}, "digest"))
	createBuildRequest := objectSchema(map[string]any{
		"project_id":        map[string]any{"type": "string"},
		"release_id":        map[string]any{"type": "string"},
		"provider":          map[string]any{"type": "string"},
		"commit_sha":        map[string]any{"type": "string"},
		"repository":        map[string]any{"type": "string"},
		"workflow_ref":      map[string]any{"type": "string"},
		"run_id":            map[string]any{"type": "string"},
		"run_attempt":       map[string]any{"type": "integer", "minimum": 0},
		"job_id":            map[string]any{"type": "string"},
		"actor":             map[string]any{"type": "string"},
		"ref":               map[string]any{"type": "string"},
		"oidc_subject":      map[string]any{"type": "string"},
		"status":            map[string]any{"type": "string", "enum": []string{"queued", "running", "passed", "failed", "cancelled"}},
		"started_at":        map[string]any{"type": "string", "format": "date-time"},
		"finished_at":       map[string]any{"type": "string", "format": "date-time"},
		"parameters_hash":   map[string]any{"type": "string"},
		"environment_hash":  map[string]any{"type": "string"},
		"provider_metadata": map[string]any{"type": "object"},
		"outputs":           map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/BuildOutput"}},
	}, "project_id", "release_id", "provider", "commit_sha", "status", "started_at")
	createBuildRequest["description"] = "Scalar text must be valid UTF-8 without NUL characters. Provider metadata must be JSON-serializable, with no NUL characters in keys or string values. Invalid input returns 400. Submitted CI identity is unverified metadata."
	registry.RegisterSchema("CreateBuildRequest", createBuildRequest)
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
	}, "sha"))
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
	}, "provider_id", "title", "state"))
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
		"product_id": map[string]any{"type": "string", "maxLength": 1024, "description": "Optional stored product filter and graph root. At least one product/release ID must be non-blank. Raw IDs are capped at 1024 UTF-8 bytes, trimmed, and NUL-free. A supplied product must own the supplied release."},
		"release_id": map[string]any{"type": "string", "maxLength": 1024, "description": "Optional stored release filter and graph root. Raw IDs are capped at 1024 UTF-8 bytes, trimmed, and NUL-free. Release-only graphs authorize the current product parent without adding an inferred product filter or node. PostgreSQL commits bounded adjacency, audit, and replay atomically."},
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
	registry.RegisterSchema("SBOMComponent", objectSchema(map[string]any{
		"identity": map[string]any{"type": "string"},
		"name":     map[string]any{"type": "string"},
		"version":  map[string]any{"type": "string"},
		"purl":     map[string]any{"type": "string"},
		"hashes":   map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
	}, "name"))
	registry.RegisterSchema("SBOMComponentRecord", objectSchema(map[string]any{
		"id":          map[string]any{"type": "string", "description": "Stable record identity for cursor pagination within an SBOM."},
		"sbom_id":     map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"component":   map[string]any{"$ref": "#/components/schemas/SBOMComponent"},
	}, "id", "sbom_id", "component"))
	registry.RegisterSchema("SBOMComponentRecordListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/SBOMComponentRecord"))
	registry.RegisterSchema("UploadSPDXSBOMRequest", objectSchema(map[string]any{
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "object", "additionalProperties": true},
	}, "release_id", "payload"))
	registry.RegisterSchema("CreateSBOMDiffRequest", objectSchema(map[string]any{
		"base_sbom_id":   map[string]any{"type": "string"},
		"target_sbom_id": map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
	}, "base_sbom_id", "target_sbom_id"))
	registry.RegisterSchema("DependencyChange", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"sbom_diff_id":   map[string]any{"type": "string"},
		"change_type":    map[string]any{"type": "string", "enum": []string{"added", "removed", "changed"}},
		"component":      map[string]any{"$ref": "#/components/schemas/SBOMComponent"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "sbom_diff_id", "change_type", "component", "schema_version", "created_at"))
	registry.RegisterSchema("SBOMDiff", objectSchema(map[string]any{
		"id":                 map[string]any{"type": "string"},
		"tenant_id":          map[string]any{"type": "string"},
		"base_sbom_id":       map[string]any{"type": "string"},
		"target_sbom_id":     map[string]any{"type": "string"},
		"release_id":         map[string]any{"type": "string"},
		"added_components":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SBOMComponent"}},
		"removed_components": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/SBOMComponent"}},
		"unchanged_count":    map[string]any{"type": "integer"},
		"dependency_changes": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/DependencyChange"}},
		"schema_version":     map[string]any{"type": "string"},
		"created_at":         map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "base_sbom_id", "target_sbom_id", "unchanged_count", "schema_version", "created_at"))
	registry.RegisterSchema("SBOMDiffEnvelope", dataEnvelopeSchema("#/components/schemas/SBOMDiff"))
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
	registry.RegisterSchema("VEXImportIssue", objectSchema(map[string]any{
		"statement_index": map[string]any{"type": "integer"},
		"code":            map[string]any{"type": "string"},
		"detail":          map[string]any{"type": "string"},
	}, "code", "detail"))
	registry.RegisterSchema("VEXImportReport", objectSchema(map[string]any{
		"id":                   map[string]any{"type": "string"},
		"tenant_id":            map[string]any{"type": "string"},
		"vex_document_id":      map[string]any{"type": "string"},
		"evidence_id":          map[string]any{"type": "string"},
		"release_id":           map[string]any{"type": "string"},
		"artifact_id":          map[string]any{"type": "string"},
		"parser_version":       map[string]any{"type": "string"},
		"status":               map[string]any{"type": "string", "enum": []string{"accepted", "parsed", "failed"}},
		"statement_count":      map[string]any{"type": "integer"},
		"decisions_created":    map[string]any{"type": "integer"},
		"decisions_superseded": map[string]any{"type": "integer"},
		"unsupported_fields":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"warnings":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"invalid_statements":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VEXImportIssue"}},
		"mapping_failures":     map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VEXImportIssue"}},
		"failure_code":         map[string]any{"type": "string"},
		"failure_detail":       map[string]any{"type": "string"},
		"schema_version":       map[string]any{"type": "string"},
		"created_at":           map[string]any{"type": "string", "format": "date-time"},
		"updated_at":           map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "vex_document_id", "evidence_id", "parser_version", "status", "statement_count", "decisions_created", "decisions_superseded", "schema_version", "created_at", "updated_at"))
	registry.RegisterSchema("VEXImportReportEnvelope", dataEnvelopeSchema("#/components/schemas/VEXImportReport"))
	registry.RegisterSchema("VEXImportPreview", objectSchema(map[string]any{
		"tenant_id":                 map[string]any{"type": "string"},
		"release_id":                map[string]any{"type": "string"},
		"artifact_id":               map[string]any{"type": "string"},
		"format":                    map[string]any{"type": "string", "enum": []string{"openvex", "cyclonedx"}},
		"parser_version":            map[string]any{"type": "string"},
		"advisory":                  map[string]any{"type": "boolean"},
		"statement_count":           map[string]any{"type": "integer"},
		"status_summary":            map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"decisions_would_create":    map[string]any{"type": "integer"},
		"decisions_would_supersede": map[string]any{"type": "integer"},
		"warnings":                  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"invalid_statements":        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VEXImportIssue"}},
		"mapping_failures":          map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VEXImportIssue"}},
		"assumptions":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":               map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":            map[string]any{"type": "string"},
		"generated_at":              map[string]any{"type": "string", "format": "date-time"},
	}, "tenant_id", "release_id", "format", "parser_version", "advisory", "statement_count", "status_summary", "decisions_would_create", "decisions_would_supersede", "assumptions", "limitations", "schema_version", "generated_at"))
	registry.RegisterSchema("VEXImportPreviewEnvelope", dataEnvelopeSchema("#/components/schemas/VEXImportPreview"))
	registry.RegisterSchema("VulnerabilityScan", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"release_id":      map[string]any{"type": "string"},
		"scanner":         map[string]any{"type": "string"},
		"adapter":         map[string]any{"type": "string"},
		"adapter_version": map[string]any{"type": "string"},
		"source_schema":   map[string]any{"type": "string"},
		"target_ref":      map[string]any{"type": "string"},
		"summary":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"findings":        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VulnerabilityFinding"}},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "release_id", "scanner", "target_ref", "summary", "findings", "created_at"))
	registry.RegisterSchema("VulnerabilityScanEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityScan"))
	registry.RegisterSchema("VulnerabilityIdentity", objectSchema(map[string]any{
		"cve": map[string]any{"type": "string"}, "ghsa": map[string]any{"type": "string"}, "osv": map[string]any{"type": "string"}, "vendor_advisory": map[string]any{"type": "string"}, "purl": map[string]any{"type": "string"}, "cpe": map[string]any{"type": "string"},
	}))
	registry.RegisterSchema("VulnerabilityFinding", objectSchema(map[string]any{
		"id": map[string]any{"type": "string"}, "vulnerability": map[string]any{"type": "string"}, "component": map[string]any{"type": "string"}, "severity": map[string]any{"type": "string"}, "state": map[string]any{"type": "string"}, "severity_source": map[string]any{"type": "string"}, "fix_version": map[string]any{"type": "string"}, "identity": map[string]any{"$ref": "#/components/schemas/VulnerabilityIdentity"},
	}, "id", "vulnerability", "severity", "state"))
	registry.RegisterSchema("ScannerAdapterEnvelope", objectSchema(map[string]any{
		"scanner":       map[string]any{"type": "string", "enum": []string{"grype", "trivy", "osv-scanner", "dependency-track"}},
		"target_ref":    map[string]any{"type": "string"},
		"release_id":    map[string]any{"type": "string"},
		"source_schema": map[string]any{"type": "string", "enum": []string{"grype-json.v1", "trivy-json.v1", "osv-scanner-json.v1", "dependency-track-json.v1"}},
		"payload":       map[string]any{"type": "object", "description": "Unmodified native scanner JSON. The selected scanner and source_schema determine the bounded adapter."},
	}, "scanner", "target_ref", "release_id", "source_schema", "payload"))
	registry.RegisterSchema("UploadVulnerabilityScanRequest", objectSchema(map[string]any{
		"scanner":    map[string]any{"type": "string"},
		"target_ref": map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"findings": map[string]any{"type": "array", "items": objectSchema(map[string]any{
			"vulnerability":   map[string]any{"type": "string"},
			"component":       map[string]any{"type": "string"},
			"severity":        map[string]any{"type": "string"},
			"state":           map[string]any{"type": "string"},
			"severity_source": map[string]any{"type": "string"},
			"fix_version":     map[string]any{"type": "string"},
			"identity":        map[string]any{"$ref": "#/components/schemas/VulnerabilityIdentity"},
		}, "vulnerability", "severity")},
	}, "scanner", "target_ref", "release_id", "findings"))
	registry.RegisterSchema("UploadVulnerabilityScanBody", map[string]any{
		"oneOf": []any{map[string]any{"$ref": "#/components/schemas/UploadVulnerabilityScanRequest"}, map[string]any{"$ref": "#/components/schemas/ScannerAdapterEnvelope"}},
	})
	registry.RegisterSchema("CreateIncidentRequest", objectSchema(map[string]any{
		"product_id": map[string]any{"type": "string"},
		"release_id": map[string]any{"type": "string"},
		"title":      map[string]any{"type": "string"},
		"severity":   map[string]any{"type": "string", "enum": []string{"low", "medium", "high", "critical"}},
		"opened_at":  map[string]any{"type": "string", "format": "date-time"},
	}, "product_id", "title", "severity"))
	registry.RegisterSchema("Incident", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"title":          map[string]any{"type": "string"},
		"severity":       map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"opened_at":      map[string]any{"type": "string", "format": "date-time"},
		"closed_at":      map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "product_id", "title", "severity", "status", "opened_at", "schema_version", "created_at"))
	registry.RegisterSchema("IncidentEnvelope", dataEnvelopeSchema("#/components/schemas/Incident"))
	registry.RegisterSchema("RecordIncidentTimelineRequest", objectSchema(map[string]any{
		"event_type":  map[string]any{"type": "string"},
		"summary":     map[string]any{"type": "string"},
		"evidence_id": map[string]any{"type": "string"},
		"occurred_at": map[string]any{"type": "string", "format": "date-time"},
	}, "event_type", "summary"))
	registry.RegisterSchema("IncidentTimelineEvent", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"incident_id":    map[string]any{"type": "string"},
		"event_type":     map[string]any{"type": "string"},
		"summary":        map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"occurred_at":    map[string]any{"type": "string", "format": "date-time"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "incident_id", "event_type", "summary", "occurred_at", "schema_version", "created_at"))
	registry.RegisterSchema("IncidentTimelineEventEnvelope", dataEnvelopeSchema("#/components/schemas/IncidentTimelineEvent"))
	registry.RegisterSchema("CreateIncidentWebhookReceiverRequest", objectSchema(map[string]any{
		"name":       map[string]any{"type": "string"},
		"provider":   map[string]any{"type": "string"},
		"public_key": map[string]any{"type": "string", "description": "Ed25519 public key used to verify signed incident webhook events."},
	}, "name", "provider", "public_key"))
	registry.RegisterSchema("IncidentWebhookReceiver", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"incident_id":    map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"provider":       map[string]any{"type": "string"},
		"public_key":     map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "incident_id", "name", "provider", "public_key", "status", "schema_version", "created_at"))
	registry.RegisterSchema("IncidentWebhookReceiverEnvelope", dataEnvelopeSchema("#/components/schemas/IncidentWebhookReceiver"))
	registry.RegisterSchema("SignedIncidentWebhookPayload", objectSchema(map[string]any{
		"event_type":  map[string]any{"type": "string"},
		"summary":     map[string]any{"type": "string"},
		"evidence_id": map[string]any{"type": "string"},
		"occurred_at": map[string]any{"type": "string", "format": "date-time"},
	}, "event_type", "summary"))
	registry.RegisterSchema("IncidentWebhookEvent", objectSchema(map[string]any{
		"id":                map[string]any{"type": "string"},
		"tenant_id":         map[string]any{"type": "string"},
		"receiver_id":       map[string]any{"type": "string"},
		"incident_id":       map[string]any{"type": "string"},
		"provider":          map[string]any{"type": "string"},
		"event_id":          map[string]any{"type": "string"},
		"payload_hash":      map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_hash":    map[string]any{"type": "string", "pattern": "^sha256:"},
		"timeline_event_id": map[string]any{"type": "string"},
		"result":            map[string]any{"type": "string"},
		"schema_version":    map[string]any{"type": "string"},
		"created_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "receiver_id", "incident_id", "provider", "event_id", "payload_hash", "signature_hash", "result", "schema_version", "created_at"))
	registry.RegisterSchema("IncidentWebhookDelivery", objectSchema(map[string]any{
		"webhook_event":  map[string]any{"$ref": "#/components/schemas/IncidentWebhookEvent"},
		"timeline_event": map[string]any{"$ref": "#/components/schemas/IncidentTimelineEvent"},
	}, "webhook_event", "timeline_event"))
	registry.RegisterSchema("IncidentWebhookDeliveryEnvelope", dataEnvelopeSchema("#/components/schemas/IncidentWebhookDelivery"))
	registry.RegisterSchema("CreateRemediationTaskRequest", objectSchema(map[string]any{
		"incident_id": map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"title":       map[string]any{"type": "string"},
		"owner":       map[string]any{"type": "string"},
		"due_at":      map[string]any{"type": "string", "format": "date-time"},
		"evidence_id": map[string]any{"type": "string"},
	}, "title", "owner"))
	registry.RegisterSchema("RemediationTask", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"incident_id":    map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"title":          map[string]any{"type": "string"},
		"owner":          map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"due_at":         map[string]any{"type": "string", "format": "date-time"},
		"evidence_id":    map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "title", "owner", "status", "schema_version", "created_at"))
	registry.RegisterSchema("RemediationTaskEnvelope", dataEnvelopeSchema("#/components/schemas/RemediationTask"))
	registry.RegisterSchema("IncidentReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"incident_id":      map[string]any{"type": "string"},
		"result":           map[string]any{"type": "string"},
		"timeline":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/IncidentTimelineEvent"}},
		"tasks":            map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/RemediationTask"}},
		"linked_evidence":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "incident_id", "result", "timeline", "tasks", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("IncidentReportEnvelope", dataEnvelopeSchema("#/components/schemas/IncidentReport"))
	registry.RegisterSchema("UploadSecurityScanRequest", objectSchema(map[string]any{
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"category":    map[string]any{"type": "string", "enum": []string{"sast", "dast", "secret_scan", "license_scan", "api_security"}},
		"format":      map[string]any{"type": "string", "default": "generic"},
		"scanner":     map[string]any{"type": "string"},
		"target_ref":  map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "object", "additionalProperties": true},
	}, "category", "scanner", "target_ref", "payload"))
	registry.RegisterSchema("UploadAPISecurityScanRequest", objectSchema(map[string]any{
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"format":      map[string]any{"type": "string", "default": "generic"},
		"scanner":     map[string]any{"type": "string"},
		"target_ref":  map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "object", "additionalProperties": true},
	}, "scanner", "target_ref", "payload"))
	registry.RegisterSchema("SecurityScan", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"artifact_id":    map[string]any{"type": "string"},
		"category":       map[string]any{"type": "string"},
		"format":         map[string]any{"type": "string"},
		"scanner":        map[string]any{"type": "string"},
		"target_ref":     map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"payload_ref":    map[string]any{"type": "string", "description": "Tenant-scoped object metadata, not a public download URL; omitted on idempotent replay by the central privacy policy."},
		"payload_hash":   map[string]any{"type": "string", "pattern": "^sha256:"},
		"finding_count":  map[string]any{"type": "integer"},
		"summary":        map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"redacted":       map[string]any{"type": "boolean"},
		"quarantined":    map[string]any{"type": "boolean"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "category", "format", "scanner", "target_ref", "evidence_id", "payload_hash", "finding_count", "redacted", "quarantined", "schema_version", "created_at"))
	registry.RegisterSchema("SecurityScanEnvelope", dataEnvelopeSchema("#/components/schemas/SecurityScan"))
	registry.RegisterSchema("UploadManualSecurityDocumentRequest", objectSchema(map[string]any{
		"product_id":    map[string]any{"type": "string"},
		"release_id":    map[string]any{"type": "string"},
		"document_type": map[string]any{"type": "string", "enum": []string{"threat_model", "security_review", "pen_test_report"}},
		"title":         map[string]any{"type": "string"},
		"sensitivity":   map[string]any{"type": "string", "enum": []string{"internal", "restricted", "confidential"}},
		"payload": map[string]any{"oneOf": []any{
			map[string]any{"type": "object", "additionalProperties": true},
			map[string]any{"type": "array", "items": map[string]any{}},
			map[string]any{"type": "string"},
			map[string]any{"type": "number"},
			map[string]any{"type": "boolean"},
		}, "description": "Opaque non-null JSON value; its exact encoded bytes are retained. Responses never contain raw payload bytes."},
		"media_type": map[string]any{"type": "string"},
	}, "document_type", "title", "sensitivity", "payload"))
	registry.RegisterSchema("ManualSecurityDocument", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"product_id":     map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"document_type":  map[string]any{"type": "string"},
		"title":          map[string]any{"type": "string"},
		"sensitivity":    map[string]any{"type": "string"},
		"evidence_id":    map[string]any{"type": "string"},
		"payload_ref":    map[string]any{"type": "string", "description": "Tenant-scoped object metadata, not a public download URL; omitted on idempotent replay by the central privacy policy."},
		"payload_hash":   map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "document_type", "title", "sensitivity", "evidence_id", "payload_hash", "schema_version", "created_at"))
	registry.RegisterSchema("ManualSecurityDocumentEnvelope", dataEnvelopeSchema("#/components/schemas/ManualSecurityDocument"))
	registry.RegisterSchema("VulnerabilityPostureReport", objectSchema(map[string]any{
		"report_type":      map[string]any{"type": "string"},
		"template_version": map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"summary":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"open_critical":    map[string]any{"type": "integer"},
		"assumptions":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "summary", "open_critical", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("VulnerabilityPostureReportEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityPostureReport"))
	registry.RegisterSchema("CRAVulnerabilityHandlingReport", objectSchema(map[string]any{
		"report_type":         map[string]any{"type": "string"},
		"template_version":    map[string]any{"type": "string"},
		"product_id":          map[string]any{"type": "string"},
		"release_id":          map[string]any{"type": "string"},
		"summary":             map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"decisions":           map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VulnerabilityDecisionCustomerSummary"}},
		"accepted_exceptions": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Exception"}},
		"evidence_ids":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "product_id", "release_id", "summary", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("CRAVulnerabilityHandlingReportEnvelope", dataEnvelopeSchema("#/components/schemas/CRAVulnerabilityHandlingReport"))
	registry.RegisterSchema("SecurityUpdateEvidenceReport", objectSchema(map[string]any{
		"report_type":       map[string]any{"type": "string"},
		"template_version":  map[string]any{"type": "string"},
		"product_id":        map[string]any{"type": "string"},
		"release_id":        map[string]any{"type": "string"},
		"summary":           map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
		"fixed_decisions":   map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VulnerabilityDecisionCustomerSummary"}},
		"incidents":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/Incident"}},
		"remediation_tasks": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/RemediationTask"}},
		"evidence_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"assumptions":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"generated_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "report_type", "template_version", "product_id", "release_id", "summary", "assumptions", "limitations", "generated_at"))
	registry.RegisterSchema("SecurityUpdateEvidenceReportEnvelope", dataEnvelopeSchema("#/components/schemas/SecurityUpdateEvidenceReport"))
	registry.RegisterSchema("CreateAnomalyReportRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string", "enum": []string{"tenant", "product", "release", "evidence", "build", "customer_package"}, "maxLength": 128, "description": "Canonical subject kind; raw NUL-free UTF-8 is capped at 128 bytes before trimming. Only release subjects currently receive anomaly checks."},
		"subject_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Current tenant-owned subject ID; raw NUL-free UTF-8 is capped at 1024 bytes before trimming. Current ownership and grants are rechecked before replay."},
	}, "subject_type", "subject_id"))
	registry.RegisterSchema("AnomalySignal", objectSchema(map[string]any{
		"name":     map[string]any{"type": "string"},
		"severity": map[string]any{"type": "string"},
		"detail":   map[string]any{"type": "string"},
	}, "name", "severity", "detail"))
	registry.RegisterSchema("AnomalyReport", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"result":         map[string]any{"type": "string"},
		"signals":        map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/AnomalySignal"}},
		"assumptions":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"limitations":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "subject_type", "subject_id", "result", "assumptions", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("AnomalyReportEnvelope", dataEnvelopeSchema("#/components/schemas/AnomalyReport"))
	registry.RegisterSchema("CreatePublicTransparencyLogRequest", objectSchema(map[string]any{
		"name":       map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyNameBytes, "description": "Nonblank log label; raw NUL-free UTF-8 is capped at 256 bytes before trimming."},
		"endpoint":   map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyEndpointBytes, "description": "Absolute HTTPS URL with a host, without userinfo or fragment; raw NUL-free UTF-8 is capped at 4096 bytes before trimming. Registration makes no network request."},
		"public_key": map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyKeyBytes, "description": "Nonblank operator-supplied public key metadata, not cryptographically verified by registration; raw NUL-free UTF-8 is capped at 16384 bytes before trimming. Do not submit private key material."},
	}, "name", "endpoint", "public_key"))
	registry.RegisterSchema("PublicTransparencyLog", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"endpoint":       map[string]any{"type": "string"},
		"public_key":     map[string]any{"type": "string"},
		"state":          map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "endpoint", "public_key", "state", "schema_version", "created_at"))
	registry.RegisterSchema("PublicTransparencyLogEnvelope", dataEnvelopeSchema("#/components/schemas/PublicTransparencyLog"))
	registry.RegisterSchema("PublishPublicTransparencyLogEntryRequest", objectSchema(map[string]any{
		"log_id":        map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyIDBytes, "description": "Current tenant-owned log ID; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"checkpoint_id": map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyIDBytes, "description": "Current tenant-owned checkpoint linked to an owned Merkle batch; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"external_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxPublicTransparencyIDBytes, "description": "Nonblank operator-supplied external reference, not external publication proof; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
	}, "log_id", "checkpoint_id", "external_id"))
	registry.RegisterSchema("VerifyPublicTransparencyLogEntryRequest", objectSchema(map[string]any{
		"leaf_hash":       map[string]any{"type": "string", "pattern": "^sha256:"},
		"root_hash":       map[string]any{"type": "string", "pattern": "^sha256:"},
		"leaf_index":      map[string]any{"type": "integer", "minimum": 0},
		"tree_size":       map[string]any{"type": "integer", "minimum": 1},
		"inclusion_proof": map[string]any{"type": "array", "items": map[string]any{"type": "string", "pattern": "^sha256:"}},
	}, "root_hash", "leaf_index", "tree_size", "inclusion_proof"))
	registry.RegisterSchema("PublicTransparencyLogEntry", objectSchema(map[string]any{
		"id":                       map[string]any{"type": "string"},
		"tenant_id":                map[string]any{"type": "string"},
		"log_id":                   map[string]any{"type": "string"},
		"checkpoint_id":            map[string]any{"type": "string"},
		"merkle_batch_id":          map[string]any{"type": "string"},
		"external_id":              map[string]any{"type": "string"},
		"entry_hash":               map[string]any{"type": "string", "pattern": "^sha256:"},
		"inclusion_root_hash":      map[string]any{"type": "string", "pattern": "^sha256:"},
		"inclusion_proof_hash":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"inclusion_verified_at":    map[string]any{"type": "string", "format": "date-time"},
		"verification_checks":      map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"verification_limitations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"state":                    map[string]any{"type": "string"},
		"schema_version":           map[string]any{"type": "string"},
		"created_at":               map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "log_id", "checkpoint_id", "merkle_batch_id", "external_id", "entry_hash", "state", "schema_version", "created_at"))
	registry.RegisterSchema("PublicTransparencyLogEntryEnvelope", dataEnvelopeSchema("#/components/schemas/PublicTransparencyLogEntry"))
	registry.RegisterSchema("CreateSaaSEditionProfileRequest", objectSchema(map[string]any{
		"name":            map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxSaaSProfileNameBytes, "description": "Nonblank intent label; raw NUL-free UTF-8 is capped at 256 bytes before trimming."},
		"region":          map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxSaaSProfileRegionBytes, "description": "Nonblank region label; raw NUL-free UTF-8 is capped at 128 bytes before trimming. No region provisioning is performed."},
		"admin_tenant_id": map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxSaaSProfileIDBytes, "description": "Current existing tenant; an explicit instance administrator may reference another tenant. Raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"isolation_model": map[string]any{"type": "string", "minLength": 1, "maxLength": experimentalapp.MaxSaaSProfileIsolationBytes, "description": "Nonblank intent label; raw NUL-free UTF-8 is capped at 256 bytes before trimming. It does not prove deployment isolation."},
	}, "name", "region", "admin_tenant_id", "isolation_model"))
	registry.RegisterSchema("SaaSEditionProfile", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"name":            map[string]any{"type": "string"},
		"region":          map[string]any{"type": "string"},
		"admin_tenant_id": map[string]any{"type": "string"},
		"isolation_model": map[string]any{"type": "string"},
		"status":          map[string]any{"type": "string"},
		"config_hash":     map[string]any{"type": "string", "pattern": "^sha256:"},
		"limitations":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "region", "admin_tenant_id", "isolation_model", "status", "config_hash", "limitations", "schema_version", "created_at"))
	registry.RegisterSchema("SaaSEditionProfileEnvelope", dataEnvelopeSchema("#/components/schemas/SaaSEditionProfile"))
	registry.RegisterSchema("VerifySubjectRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string", "description": "Verification target. Audit-chain checkpoints use audit_chain_checkpoint (Merkle batch id) or audit_chain_release_manifest (release bundle id)."},
		"subject_id":   map[string]any{"type": "string", "description": "Target id; audit_chain does not require an id."},
	}, "subject_type"))
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
	registry.RegisterSchema("EvidenceSearchEnvelope", dataArrayEnvelopeSchema("#/components/schemas/EvidenceItem"))
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
		"package_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Current tenant-owned package ID; at most 1024 UTF-8 bytes."},
		"customer_name":  map[string]any{"type": "string", "minLength": 1, "maxLength": 640, "description": "Recipient label; at most 640 UTF-8 bytes before 160-rune/control-character normalization."},
		"reviewer_name":  map[string]any{"type": "string", "maxLength": 640, "description": "Optional external reviewer display name; at most 640 UTF-8 bytes before label normalization."},
		"reviewer_email": map[string]any{"type": "string", "maxLength": 640, "description": "Optional external reviewer email label, lowercased; at most 640 UTF-8 bytes. It is not an authentication secret."},
		"require_nda":    map[string]any{"type": "boolean"},
		"watermark":      map[string]any{"type": "string", "maxLength": 640, "description": "Optional customer-visible distribution watermark; at most 640 UTF-8 bytes before label normalization. ZIP rendering rejects sensitive content, including email-shaped watermark text."},
		"expires_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "package_id", "customer_name", "expires_at"))
	registry.RegisterSchema("CustomerPortalAccess", objectSchema(map[string]any{
		"id":                  map[string]any{"type": "string"},
		"tenant_id":           map[string]any{"type": "string"},
		"package_id":          map[string]any{"type": "string"},
		"customer_name":       map[string]any{"type": "string"},
		"reviewer_name":       map[string]any{"type": "string"},
		"reviewer_email":      map[string]any{"type": "string"},
		"require_nda":         map[string]any{"type": "boolean"},
		"nda_accepted_at":     map[string]any{"type": "string", "format": "date-time"},
		"nda_accepted_by":     map[string]any{"type": "string"},
		"watermark":           map[string]any{"type": "string"},
		"prefix":              map[string]any{"type": "string", "description": "Non-secret portal token prefix for operational lookup."},
		"expires_at":          map[string]any{"type": "string", "format": "date-time"},
		"revoked_at":          map[string]any{"type": "string", "format": "date-time"},
		"access_count":        map[string]any{"type": "integer"},
		"failed_access_count": map[string]any{"type": "integer"},
		"last_accessed_at":    map[string]any{"type": "string", "format": "date-time"},
		"last_failed_at":      map[string]any{"type": "string", "format": "date-time"},
		"schema_version":      map[string]any{"type": "string"},
		"created_at":          map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "package_id", "customer_name", "prefix", "expires_at", "access_count", "failed_access_count", "schema_version", "created_at"))
	registry.RegisterSchema("CustomerPortalAccessCreateResponse", objectSchema(map[string]any{
		"access": map[string]any{"$ref": "#/components/schemas/CustomerPortalAccess"},
		"secret": map[string]any{"type": "string", "description": "One-time portal token; stored only as a HMAC hash. Present only in the initial successful response and omitted from idempotency replays."},
	}, "access"))
	registry.RegisterSchema("CustomerPortalAccessCreateEnvelope", dataEnvelopeSchema("#/components/schemas/CustomerPortalAccessCreateResponse"))
	registry.RegisterSchema("CustomerPortalAccessEnvelope", dataEnvelopeSchema("#/components/schemas/CustomerPortalAccess"))
	registry.RegisterSchema("CustomerPortalAccessListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/CustomerPortalAccess"))
	registry.RegisterSchema("CustomerPortalPackageRequest", objectSchema(map[string]any{
		"token":           map[string]any{"type": "string", "maxLength": 1024, "description": "Customer portal token issued by createCustomerPortalAccess; raw input is limited to 1024 UTF-8 bytes in PostgreSQL mode. Sent only in the request body."},
		"nda_accepted":    map[string]any{"type": "boolean", "description": "Set true to record acceptance for NDA-gated portal access."},
		"nda_accepted_by": map[string]any{"type": "string", "maxLength": 640, "description": "Reviewer label recorded when NDA acceptance is required; at most 640 UTF-8 bytes before normalization. Do not include secrets."},
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
			"page_size":   map[string]any{"type": "integer", "minimum": 1, "maximum": 500},
			"sort":        map[string]any{"type": "string", "enum": []string{"created_at", "id"}},
			"direction":   map[string]any{"type": "string", "enum": []string{"asc", "desc"}},
			"next_cursor": map[string]any{"type": "string", "description": "Opaque cursor for the next page; absent when no additional page exists."},
		}, "api_version", "page_size", "sort", "direction"),
	}, "data", "meta")
}

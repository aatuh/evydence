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
		"name":           map[string]any{"type": "string"},
		"object_prefix":  map[string]any{"type": "string"},
		"mode":           map[string]any{"type": "string", "enum": []string{"governance", "compliance"}},
		"retention_days": map[string]any{"type": "integer", "minimum": 1},
	}, "name", "mode", "retention_days"))
	registry.RegisterSchema("ObjectRetentionPolicy", objectSchema(map[string]any{
		"id":                map[string]any{"type": "string"},
		"tenant_id":         map[string]any{"type": "string"},
		"name":              map[string]any{"type": "string"},
		"object_prefix":     map[string]any{"type": "string"},
		"mode":              map[string]any{"type": "string"},
		"retention_days":    map[string]any{"type": "integer"},
		"status":            map[string]any{"type": "string"},
		"verified_at":       map[string]any{"type": "string", "format": "date-time"},
		"verification_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
		"schema_version":    map[string]any{"type": "string"},
		"created_at":        map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "object_prefix", "mode", "retention_days", "status", "schema_version", "created_at"))
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
	}, "status", "justification"))
	registry.RegisterSchema("VulnerabilityDecision", objectSchema(map[string]any{
		"id":               map[string]any{"type": "string"},
		"tenant_id":        map[string]any{"type": "string"},
		"finding_id":       map[string]any{"type": "string"},
		"scan_id":          map[string]any{"type": "string"},
		"release_id":       map[string]any{"type": "string"},
		"vulnerability":    map[string]any{"type": "string"},
		"component":        map[string]any{"type": "string"},
		"status":           map[string]any{"type": "string"},
		"justification":    map[string]any{"type": "string"},
		"impact_statement": map[string]any{"type": "string"},
		"action_statement": map[string]any{"type": "string"},
		"source":           map[string]any{"type": "string"},
		"evidence_id":      map[string]any{"type": "string"},
		"vex_document_id":  map[string]any{"type": "string"},
		"supersedes":       map[string]any{"type": "string"},
		"superseded_by":    map[string]any{"type": "string"},
		"approved_by":      map[string]any{"type": "string"},
		"schema_version":   map[string]any{"type": "string"},
		"created_at":       map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "finding_id", "scan_id", "vulnerability", "status", "justification", "source", "schema_version", "created_at"))
	registry.RegisterSchema("VulnerabilityDecisionEnvelope", dataEnvelopeSchema("#/components/schemas/VulnerabilityDecision"))
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
		"id":         map[string]any{"type": "string"},
		"tenant_id":  map[string]any{"type": "string"},
		"kid":        map[string]any{"type": "string"},
		"algorithm":  map[string]any{"type": "string"},
		"status":     map[string]any{"type": "string"},
		"public_key": map[string]any{"type": "string"},
		"created_at": map[string]any{"type": "string", "format": "date-time"},
		"revoked_at": map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "kid", "algorithm", "status", "public_key", "created_at"))
	registry.RegisterSchema("SigningKeyEnvelope", dataEnvelopeSchema("#/components/schemas/SigningKey"))
	registry.RegisterSchema("SigningKeyListEnvelope", dataArrayEnvelopeSchema("#/components/schemas/SigningKey"))
	registry.RegisterSchema("SigningKeyTransitionRequest", objectSchema(map[string]any{
		"reason": map[string]any{"type": "string"},
	}))
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
	registry.RegisterSchema("CreateSigningOperationRequest", objectSchema(map[string]any{
		"provider_id":        map[string]any{"type": "string"},
		"subject_type":       map[string]any{"type": "string"},
		"subject_id":         map[string]any{"type": "string"},
		"payload_hash":       map[string]any{"type": "string", "pattern": "^sha256:"},
		"external_signature": map[string]any{"type": "string"},
	}, "provider_id", "subject_type", "subject_id", "payload_hash"))
	registry.RegisterSchema("SigningOperation", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"provider_id":    map[string]any{"type": "string"},
		"subject_type":   map[string]any{"type": "string"},
		"subject_id":     map[string]any{"type": "string"},
		"payload_hash":   map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_ref":  map[string]any{"type": "string"},
		"result":         map[string]any{"type": "string"},
		"checks":         map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
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
		"rekor_uuid":           map[string]any{"type": "string"},
		"rekor_log_index":      map[string]any{"type": "string"},
		"certificate_identity": map[string]any{"type": "string"},
		"certificate_issuer":   map[string]any{"type": "string"},
	}))
	registry.RegisterSchema("CosignVerification", objectSchema(map[string]any{
		"id":                    map[string]any{"type": "string"},
		"tenant_id":             map[string]any{"type": "string"},
		"artifact_id":           map[string]any{"type": "string"},
		"container_image_id":    map[string]any{"type": "string"},
		"artifact_signature_id": map[string]any{"type": "string"},
		"subject_digest":        map[string]any{"type": "string"},
		"rekor_uuid":            map[string]any{"type": "string"},
		"rekor_log_index":       map[string]any{"type": "string"},
		"certificate_identity":  map[string]any{"type": "string"},
		"certificate_issuer":    map[string]any{"type": "string"},
		"result":                map[string]any{"type": "string", "enum": []string{"passed", "failed"}},
		"checks":                map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/VerifyCheck"}},
		"schema_version":        map[string]any{"type": "string"},
		"created_at":            map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "artifact_signature_id", "subject_digest", "result", "checks", "schema_version", "created_at"))
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
		"name":       map[string]any{"type": "string"},
		"key_id":     map[string]any{"type": "string"},
		"algorithm":  map[string]any{"type": "string", "enum": []string{"Ed25519"}},
		"public_key": map[string]any{"type": "string", "description": "Base64-encoded Ed25519 public key."},
	}, "name", "key_id", "algorithm", "public_key"))
	registry.RegisterSchema("DSSETrustRoot", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
		"key_id":         map[string]any{"type": "string"},
		"algorithm":      map[string]any{"type": "string"},
		"public_key":     map[string]any{"type": "string"},
		"status":         map[string]any{"type": "string"},
		"schema_version": map[string]any{"type": "string"},
		"created_at":     map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "name", "key_id", "algorithm", "public_key", "status", "schema_version", "created_at"))
	registry.RegisterSchema("DSSETrustRootEnvelope", dataEnvelopeSchema("#/components/schemas/DSSETrustRoot"))
	registry.RegisterSchema("CreateReleaseCandidateRequest", objectSchema(map[string]any{
		"release_id":   map[string]any{"type": "string"},
		"name":         map[string]any{"type": "string"},
		"build_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"artifact_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"sbom_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"scan_ids":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"vex_ids":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"contract_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"bundle_ids":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "release_id", "name"))
	registry.RegisterSchema("ReleaseCandidateTransitionRequest", objectSchema(map[string]any{
		"reason": map[string]any{"type": "string"},
	}))
	registry.RegisterSchema("ReleaseCandidate", objectSchema(map[string]any{
		"id":             map[string]any{"type": "string"},
		"tenant_id":      map[string]any{"type": "string"},
		"release_id":     map[string]any{"type": "string"},
		"name":           map[string]any{"type": "string"},
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
	}, "id", "tenant_id", "release_id", "name", "state", "snapshot_hash", "schema_version", "created_at"))
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
	}, "repository_id", "sha", "committed_at"))
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
	}, "repository_id", "provider", "provider_id", "title", "state"))
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
	}, "environment_id", "release_id", "status", "started_at"))
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
		"name":          map[string]any{"type": "string"},
		"provider":      map[string]any{"type": "string"},
		"version":       map[string]any{"type": "string"},
		"publisher":     map[string]any{"type": "string"},
		"manifest_hash": map[string]any{"type": "string", "pattern": "^sha256:"},
		"signature_id":  map[string]any{"type": "string"},
		"sbom_id":       map[string]any{"type": "string"},
		"scan_id":       map[string]any{"type": "string"},
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
	registry.RegisterSchema("RegisterContainerImageRequest", objectSchema(map[string]any{
		"artifact_id": map[string]any{"type": "string"},
		"repository":  map[string]any{"type": "string"},
		"tag":         map[string]any{"type": "string"},
		"digest":      map[string]any{"type": "string"},
		"platform":    map[string]any{"type": "string"},
	}, "repository", "digest"))
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
		"allowed_types":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"excluded_fields": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "name"))
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
		"id":                   map[string]any{"type": "string"},
		"tenant_id":            map[string]any{"type": "string"},
		"product_id":           map[string]any{"type": "string"},
		"release_id":           map[string]any{"type": "string"},
		"redaction_profile_id": map[string]any{"type": "string"},
		"title":                map[string]any{"type": "string"},
		"state":                map[string]any{"type": "string"},
		"manifest":             map[string]any{"type": "object", "additionalProperties": true},
		"manifest_hash":        map[string]any{"type": "string", "pattern": "^sha256:"},
		"expires_at":           map[string]any{"type": "string", "format": "date-time"},
		"access_count":         map[string]any{"type": "integer"},
		"schema_version":       map[string]any{"type": "string"},
		"created_at":           map[string]any{"type": "string", "format": "date-time"},
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
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
		"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	}, "subject_type", "subject_id", "evidence_ids"))
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
		"name":      map[string]any{"type": "string"},
		"version":   map[string]any{"type": "string"},
		"questions": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/components/schemas/QuestionnaireQuestion"}},
	}, "name", "version", "questions"))
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
		"template_id": map[string]any{"type": "string"},
		"package_id":  map[string]any{"type": "string"},
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
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
		"template_id": map[string]any{"type": "string"},
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
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
	registry.RegisterSchema("CreatePDFReportPackageRequest", objectSchema(map[string]any{
		"report_type": map[string]any{"type": "string"},
		"product_id":  map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"title":       map[string]any{"type": "string"},
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
	registry.RegisterSchema("SBOMComponent", objectSchema(map[string]any{
		"name":    map[string]any{"type": "string"},
		"version": map[string]any{"type": "string"},
		"purl":    map[string]any{"type": "string"},
		"hashes":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
	}, "name"))
	registry.RegisterSchema("SBOMComponentRecord", objectSchema(map[string]any{
		"sbom_id":     map[string]any{"type": "string"},
		"release_id":  map[string]any{"type": "string"},
		"artifact_id": map[string]any{"type": "string"},
		"component":   map[string]any{"$ref": "#/components/schemas/SBOMComponent"},
	}, "sbom_id", "component"))
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
		"category":    map[string]any{"type": "string", "enum": []string{"sast", "dast", "secret", "license", "api_security"}},
		"format":      map[string]any{"type": "string"},
		"scanner":     map[string]any{"type": "string"},
		"target_ref":  map[string]any{"type": "string"},
		"payload":     map[string]any{"type": "object", "additionalProperties": true},
	}, "category", "format", "scanner", "target_ref", "payload"))
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
		"payload_ref":    map[string]any{"type": "string"},
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
		"document_type": map[string]any{"type": "string", "enum": []string{"threat_model", "security_review", "pentest_report"}},
		"title":         map[string]any{"type": "string"},
		"sensitivity":   map[string]any{"type": "string", "enum": []string{"internal", "restricted", "confidential"}},
		"payload":       map[string]any{"type": "string", "description": "Document payload or text supplied for object storage; responses expose only payload hash/ref metadata."},
		"media_type":    map[string]any{"type": "string"},
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
		"payload_ref":    map[string]any{"type": "string"},
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
	registry.RegisterSchema("CreateAnomalyReportRequest", objectSchema(map[string]any{
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
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
		"name":       map[string]any{"type": "string"},
		"endpoint":   map[string]any{"type": "string"},
		"public_key": map[string]any{"type": "string"},
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
		"log_id":        map[string]any{"type": "string"},
		"checkpoint_id": map[string]any{"type": "string"},
		"external_id":   map[string]any{"type": "string"},
	}, "log_id", "checkpoint_id", "external_id"))
	registry.RegisterSchema("PublicTransparencyLogEntry", objectSchema(map[string]any{
		"id":              map[string]any{"type": "string"},
		"tenant_id":       map[string]any{"type": "string"},
		"log_id":          map[string]any{"type": "string"},
		"checkpoint_id":   map[string]any{"type": "string"},
		"merkle_batch_id": map[string]any{"type": "string"},
		"external_id":     map[string]any{"type": "string"},
		"entry_hash":      map[string]any{"type": "string", "pattern": "^sha256:"},
		"state":           map[string]any{"type": "string"},
		"schema_version":  map[string]any{"type": "string"},
		"created_at":      map[string]any{"type": "string", "format": "date-time"},
	}, "id", "tenant_id", "log_id", "checkpoint_id", "merkle_batch_id", "external_id", "entry_hash", "state", "schema_version", "created_at"))
	registry.RegisterSchema("PublicTransparencyLogEntryEnvelope", dataEnvelopeSchema("#/components/schemas/PublicTransparencyLogEntry"))
	registry.RegisterSchema("CreateSaaSEditionProfileRequest", objectSchema(map[string]any{
		"name":            map[string]any{"type": "string"},
		"region":          map[string]any{"type": "string"},
		"admin_tenant_id": map[string]any{"type": "string"},
		"isolation_model": map[string]any{"type": "string"},
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
		"subject_type": map[string]any{"type": "string"},
		"subject_id":   map[string]any{"type": "string"},
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

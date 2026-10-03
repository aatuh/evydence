package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/specs"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
)

const focusedVEXIngestionDescription = " In PostgreSQL mode, a focused command checks current tenant-owned release parents and human release/artifact grants before parsing or staging. IDs are NUL-free UTF-8 bounded at 1024 bytes; wrapped JSON remains capped at 64 KiB and rejects null, duplicate, and unknown fields. Declared source size and SHA-256 are verified. Normalized projections are limited to 100,000 statements, 1 MiB per string, and 64 MiB combined projection strings; the versioned post-commit decision request permits at most 1,000,000 values and 20 MiB combined decision text. Overflow fails validation rather than truncating. VEX, accepted report, evidence, audit, payload metadata, outbox jobs, and idempotency completion commit together; decisions are never written during upload. Replay checks current grants without parsing or staging. Retained body-only native OpenVEX receipts require exact tenant, release, optional artifact, and format and never execute a new upload. Normalized VEX metadata and the accepted report are always retained, regardless of worker-owned parsing. Acceptance does not establish source authority, signature trust, or legal sufficiency."

const focusedVEXPreviewDescription = " In PostgreSQL mode, one read-only repeatable-read snapshot resolves current tenant-owned release parents and optional artifact ownership, then checks human release and artifact grants before parsing or candidate selection. The wrapped JSON request is limited to 64 KiB and rejects null, duplicate, and unknown fields. IDs are NUL-free UTF-8 bounded at 1024 bytes. Reads select only relevant finding coordinates and active-decision presence, never private notes or evidence metadata; at most 4096 release scans, 4096 candidate findings, and 8 MiB of combined candidate text are allowed. Oversized or malformed stored projections fail closed without a partial preview. Matching preserves duplicate and ambiguity policy and original statement indexes. Results remain advisory and create no audit, outbox, or idempotency records; Idempotency-Key is not required."

const focusedSecurityDocumentDescription = " In PostgreSQL mode, focused security:write commands check current tenant-owned product/release parents and human resource grants before parsing or staging; scoped human artifact grants require a current authorized evidence/build association, while tenant-wide grants and issued credentials do not need a narrower association. No request reloads the Ledger aggregate. Wrapped JSON remains limited to 64 KiB and rejects null metadata/payload, duplicate keys, and unknown envelope fields. IDs are NUL-free UTF-8 bounded at 1024 bytes. Evidence, accepted document metadata, payload metadata, finalizer job, two audit entries, and safe idempotency completion commit in one transaction. Same-key replay rechecks current grants without parsing or staging and preserves safe metadata; payload_ref is omitted on replay by the central privacy policy. Raw payload bytes are never included in responses. Failed commands roll back document effects; a response-free failed-key record can remain. Local-memory mode retains its explicit compatibility command."

func withCriticalOperationDetails(operation specs.Operation) specs.Operation {
	addProblemResponses(&operation)
	switch operation.OperationID {
	case "health":
		operation.Description = "Returns low-detail liveness status without touching tenant evidence or secret material."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Liveness status envelope.", "#/components/schemas/HealthStatusEnvelope")
	case "ready":
		operation.Description = "Runs bounded PostgreSQL, migration, writer-lease, object-store, and signing-configuration probes configured for this process. The public result contains no tenant data, credentials, paths, or raw dependency errors. An unavailable result includes typed dependency retry metadata and Retry-After."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Readiness status envelope.", "#/components/schemas/ReadinessStatusEnvelope")
		operation.Responses[http.StatusServiceUnavailable] = jsonResponse("Required dependency unavailable; low-detail readiness status envelope.", "#/components/schemas/ReadinessStatusEnvelope")
	case "version":
		operation.Description = "Returns immutable build identity injected at build time: version, source commit, build time, dirty marker, Go version, and release-manifest digest."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Version information envelope.", "#/components/schemas/VersionInfoEnvelope")
	case "readinessDiagnostics":
		operation.Description = "Returns vetted per-dependency readiness diagnostics. Requires the explicit instance:admin scope; raw dependency errors, credentials, paths, and tenant data are excluded."
		operation.Responses[http.StatusOK] = jsonResponse("Instance readiness diagnostics envelope.", "#/components/schemas/ReadinessDiagnosticsEnvelope")
	case "metrics":
		operation.Description = "Returns safe tenant-scoped resource and object-reconciliation metrics for admin actors. Reconciliation metrics contain counters only: no object keys, digests, raw payloads, or provider errors. An explicit instance:admin actor also receives bounded aggregate outbox gauges without tenant labels, payloads, or failure details. A Prometheus text response is available when requested with Accept: text/plain."
		operation.Responses[http.StatusOK] = specs.Response{
			Description:  "Tenant metrics envelope or Prometheus text metrics.",
			ContentTypes: []string{"application/json", "text/plain"},
			Content: map[string]specs.MediaType{
				"application/json": {SchemaRef: "#/components/schemas/MetricsSnapshotEnvelope"},
				"text/plain":       {Schema: map[string]any{"type": "string"}},
			},
		}
	case "openapi":
		operation.Description = "Returns the generated OpenAPI 3.1 document served by this process."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("OpenAPI document.", "#/components/schemas/OpenAPIDocument")
	case "instanceAdminSnapshot":
		operation.Description = "Returns instance-level diagnostic counts from one current database snapshot in the PostgreSQL profile. Requires the explicit instance:admin scope; tenant admin and ordinary wildcard tenant keys are insufficient. The response omits tenant identifiers, evidence payloads, and credential material."
		operation.Responses[http.StatusOK] = jsonResponse("Instance admin snapshot envelope.", "#/components/schemas/InstanceAdminSnapshotEnvelope")
	case "outboxOperatorDiagnostics":
		operation.Description = "Returns aggregate outbox backlog, running, and terminal-job counts without tenant IDs, payloads, or raw failure details. Requires the explicit instance:admin scope."
		operation.Responses[http.StatusOK] = jsonResponse("Outbox operator diagnostics envelope.", "#/components/schemas/OutboxDiagnosticsEnvelope")
	case "replayTerminalOutboxJob":
		operation.Description = "Requeues one dead-letter outbox job and appends an audit record. Requires the explicit instance:admin scope and an idempotency key; raw payload and failure details are never returned."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Terminal outbox job id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		delete(operation.Responses, http.StatusCreated)
		operation.Responses[http.StatusOK] = jsonResponse("Requeued outbox job envelope.", "#/components/schemas/OutboxReplayEnvelope")
	case "createOrganization":
		operation.Description = "Creates a tenant-scoped organization record for human identity grouping. PostgreSQL uses focused Identity commands with current tenant-wide human authority and atomic audit/replay; slugs are trimmed and case-sensitive."
		operation.RequestBody = jsonRequest("Organization creation request.", "#/components/schemas/CreateOrganizationRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created organization envelope.", "#/components/schemas/OrganizationEnvelope")
	case "createUser":
		operation.Description = "Creates a tenant-scoped human user metadata record. Authentication is still controlled by API keys or configured SSO/session flows. PostgreSQL uses focused Identity commands with current tenant-wide human authority and current optional organization ownership. Email is trimmed/lowercased and must be a plain mailbox address; this does not verify ownership. The fixed public user DTO, including required email, survives authorized durable replay without broadening log or customer-package redaction."
		operation.RequestBody = jsonRequest("Human user creation request.", "#/components/schemas/CreateUserRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created human user envelope.", "#/components/schemas/HumanUserEnvelope")
	case "deactivateUser":
		operation.Description = "Deactivates a tenant-scoped human user as an audited lifecycle transition. PostgreSQL uses a bounded current-user projection with tenant-wide human authority and current organization ownership; status, audit and replay commit atomically. Committed deactivation invalidates current-user session authentication. A completed matching request replays the public DTO without another transition; a new transition of an inactive user conflicts."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Human user id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Deactivated human user envelope.", "#/components/schemas/HumanUserEnvelope")
	case "createRoleBinding":
		operation.Description = "Creates a tenant-scoped role binding for a user or collector subject. PostgreSQL uses focused Identity commands with current tenant-wide human admin authority and bounded current subject/resource ownership checks before writes and replay. Binding, audit and safe replay completion commit atomically. Empty/omitted resource type with an empty ID, or tenant with an empty/current tenant ID, remains tenant-wide; supported scoped resources require a nonempty owned ID. A package's optional release must match its product. Reusing a completed key/body returns the original public binding; a new key intentionally permits another assignment with identical grant coordinates. No credential hashes, target metadata or evidence manifests are loaded."
		operation.RequestBody = jsonRequest("Role binding creation request.", "#/components/schemas/CreateRoleBindingRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created role binding envelope.", "#/components/schemas/RoleBindingEnvelope")
	case "listRoleBindings":
		operation.Description = "Lists tenant-scoped role bindings visible to the identity administrator."
		operation.Responses[http.StatusOK] = jsonResponse("Role binding list envelope.", "#/components/schemas/RoleBindingListEnvelope")
	case "createSSOSession":
		operation.Description = "Creates an admin-managed human SSO session record and returns a one-time bearer secret."
		operation.RequestBody = jsonRequest("SSO session creation request.", "#/components/schemas/CreateSSOSessionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO session and one-time secret envelope.", "#/components/schemas/SSOSessionCreateEnvelope")
	case "exchangeSSOCredential":
		operation.Description = "Exchanges a locally verified OIDC ID token or SAML assertion for an SSO session and HttpOnly browser cookie using configured tenant trust material and verified identity links. No live provider API or group synchronization call is made."
		operation.Security = nil
		operation.Scopes = nil
		operation.RequestBody = jsonRequest("SSO credential exchange request.", "#/components/schemas/ExchangeSSOCredentialRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO session, verification receipt, and one-time secret envelope.", "#/components/schemas/SSOCredentialExchangeEnvelope")
	case "revokeSSOSession":
		operation.Description = "Revokes a tenant-scoped SSO session as an audited lifecycle transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SSO session id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked SSO session envelope.", "#/components/schemas/SSOSessionEnvelope")
	case "logoutSSOSession":
		operation.Description = "Revokes the currently authenticated SSO session without requiring identity administrator privileges. API keys and collector keys cannot use this route."
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked current SSO session envelope.", "#/components/schemas/SSOSessionEnvelope")
	case "createSSOProvider":
		operation.Description = "Records tenant SSO provider metadata. PostgreSQL uses focused Identity commands with current tenant-wide administration and input validation before reservation or completed replay, and atomic provider/audit/replay writes without Ledger reloads. Required issuer metadata is an absolute HTTPS URL with a host, no userinfo and no fragment; stored text is bounded, UTF-8 and NUL-free. Explicit null fields/items are rejected. Another key creates another provider for identical metadata. Authorized replay preserves harmless group names within the public provider DTO without weakening generic privacy redaction. Optional static JWKS public keys and SAML signing certificates can be supplied for local token/assertion verification without live provider calls. Shared stateless Identity normalization rejects private/symmetric JOSE members, retains supported public JWK fields only, and normalizes parsed RSA certificates without trailing PEM blocks. This validates supported metadata shapes, not provider ownership or key custody; historical rows and backups are not scrubbed."
		operation.RequestBody = jsonRequest("SSO provider creation request.", "#/components/schemas/CreateSSOProviderRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO provider envelope.", "#/components/schemas/SSOProviderEnvelope")
	case "updateSSOProviderTrustMaterial":
		operation.Description = "Rotates tenant SSO provider public trust material for local OIDC ID-token or SAML assertion verification. PostgreSQL uses focused Identity commands and one bounded tenant-owned provider read, not Ledger state or provider inventories. Current tenant-wide administration, input and provider checks run before reservation or completed replay; update, canonical-hash audit and safe replay completion commit together. Foreign/missing providers return 404; oversized or ill-typed stored metadata returns 409 without truncation. OIDC requires nonempty JWKS only; SAML requires signing certificates only. Strict decoding rejects invalid UTF-8, duplicate/unknown fields, trailing JSON and explicit null fields/items; retained public-key text is NUL-free. Shared stateless Identity normalization rejects private/symmetric JOSE members and retains supported public JWK fields only; parsed RSA certificates exclude trailing PEM blocks. Authorized replay preserves normalized public PEM and harmless public group names without weakening generic privacy redaction. Invalid trust material does not replace current trust or append an audit. No live provider call is made; provider ownership and key custody are not proved. Historical records, receipts and backups are not scrubbed or repaired."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SSO provider id."))
		operation.RequestBody = jsonRequest("SSO provider trust material update request.", "#/components/schemas/UpdateSSOProviderTrustMaterialRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Updated SSO provider envelope.", "#/components/schemas/SSOProviderEnvelope")
	case "refreshSSOProviderOIDCTrustMaterial":
		operation.Description = "Fetches the OIDC discovery document and public JWKS for the tenant provider issuer, then stores normalized public trust material. Private/symmetric JOSE members or malformed supported fields fail verification without replacing current trust or appending an audit; unsupported extension metadata is not retained. This does not authenticate users, prove provider ownership, scrub historical records/backups, or synchronize groups."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SSO provider id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Refreshed SSO provider envelope.", "#/components/schemas/SSOProviderEnvelope")
	case "verifyProviderIdentity":
		operation.Description = "Verifies stored provider identity metadata and, when supplied, locally verifies OIDC ID-token or SAML assertion issuer, audience, subject, time bounds, and signature against configured tenant trust material."
		operation.RequestBody = jsonRequest("Provider identity verification request.", "#/components/schemas/VerifyProviderIdentityRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Provider verification envelope.", "#/components/schemas/ProviderVerificationEnvelope")
	case "linkSSOIdentity":
		operation.Description = "Links a verified provider subject to a tenant-scoped human user."
		operation.RequestBody = jsonRequest("SSO identity link request.", "#/components/schemas/LinkSSOIdentityRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO identity link envelope.", "#/components/schemas/UserIdentityLinkEnvelope")
	case "createAPIKey":
		operation.Description = "Creates a tenant-scoped API key atomically with audit and replay state. PostgreSQL uses a focused Identity command and current tenant-wide admin authority. Delegating instance:admin requires explicit instance authority, not a tenant wildcard. The first response returns the secret once; restart replay retains only the public key metadata, never its secret or hash. Names are not unique; scopes retain existing trimming, sorting and duplicate/blank/unknown-string behavior."
		operation.RequestBody = jsonRequest("API key creation request.", "#/components/schemas/CreateAPIKeyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created API key and one-time secret envelope.", "#/components/schemas/APIKeyCreateEnvelope")
	case "listAPIKeys":
		operation.Description = "Lists tenant-scoped API key metadata without key hashes or one-time secrets."
		operation.Responses[http.StatusOK] = jsonResponse("API key list envelope.", "#/components/schemas/APIKeyListEnvelope")
	case "createCollector":
		operation.Description = "Creates a tenant-scoped collector identity and scoped API key atomically with audit and replay state. PostgreSQL uses focused commands; human sessions require a current tenant-wide collector:admin grant. The secret is returned only in the first response; durable replay preserves public collector/key metadata without the secret or hash. Omitted or empty scopes default to build:write and evidence:write; read scopes require explicit opt-in."
		operation.RequestBody = jsonRequest("Collector creation request.", "#/components/schemas/CreateCollectorRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created collector and one-time key secret envelope.", "#/components/schemas/CollectorCreateEnvelope")
	case "listCollectors":
		operation.Description = "Lists tenant-scoped collector metadata without API key hashes or one-time secrets."
		operation.Responses[http.StatusOK] = jsonResponse("Collector list envelope.", "#/components/schemas/CollectorListEnvelope")
	case "createControlFramework":
		operation.Description = "Creates a tenant-scoped versioned control framework."
		operation.RequestBody = jsonRequest("Control framework creation request.", "#/components/schemas/CreateControlFrameworkRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created control framework envelope.", "#/components/schemas/ControlFrameworkEnvelope")
	case "listControlFrameworks":
		operation.Description = "Lists tenant-scoped control frameworks."
		operation.Responses[http.StatusOK] = jsonResponse("Control framework list envelope.", "#/components/schemas/ControlFrameworkListEnvelope")
	case "createSecurityControl":
		operation.Description = "Creates a framework-owned security control with deterministic evidence requirements."
		operation.RequestBody = jsonRequest("Security control creation request.", "#/components/schemas/CreateSecurityControlRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created security control envelope.", "#/components/schemas/SecurityControlEnvelope")
	case "getSecurityControl":
		operation.Description = "Returns a tenant-scoped security control by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Security control id."))
		operation.Responses[http.StatusOK] = jsonResponse("Security control envelope.", "#/components/schemas/SecurityControlEnvelope")
	case "linkControlEvidence":
		operation.Description = "Creates an append-only link between a security control and tenant-scoped evidence or related release resource."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Security control id."))
		operation.RequestBody = jsonRequest("Control evidence link request.", "#/components/schemas/LinkControlEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created control evidence link envelope.", "#/components/schemas/ControlEvidenceEnvelope")
	case "listControlEvidence":
		operation.Description = "Keyset-pages tenant and grant-visible control evidence links with optional control, product, and release filters. PostgreSQL validates current control, framework, scope, and subject ownership before the page limit; broken links are excluded."
		operation.Parameters = append(operation.Parameters,
			queryParam("control_id", "Filter by security control id.", "string"),
			queryParam("product_id", "Filter by product id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Control evidence list envelope.", "#/components/schemas/ControlEvidenceListEnvelope")
	case "createProduct":
		operation.Description = "Creates a tenant-scoped product. Product slugs must be unique per tenant."
		operation.RequestBody = jsonRequest("Product creation request.", "#/components/schemas/CreateProductRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created product envelope.", "#/components/schemas/ProductEnvelope")
	case "listProducts":
		operation.Description = "Lists tenant-scoped products visible to the authenticated actor."
		operation.Responses[http.StatusOK] = jsonResponse("Product list envelope.", "#/components/schemas/ProductListEnvelope")
	case "getProduct":
		operation.Description = "Returns a tenant-scoped product by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Product id."))
		operation.Responses[http.StatusOK] = jsonResponse("Product envelope.", "#/components/schemas/ProductEnvelope")
	case "createProject":
		operation.Description = "Creates a tenant-scoped project under a product."
		operation.RequestBody = jsonRequest("Project creation request.", "#/components/schemas/CreateProjectRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created project envelope.", "#/components/schemas/ProjectEnvelope")
	case "getProject":
		operation.Description = "Returns a tenant-scoped project by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Project id."))
		operation.Responses[http.StatusOK] = jsonResponse("Project envelope.", "#/components/schemas/ProjectEnvelope")
	case "createRelease":
		operation.Description = "Creates an append-only release record under a product."
		operation.RequestBody = jsonRequest("Release creation request.", "#/components/schemas/CreateReleaseRequest")
		addJSONRequestExamples(operation.RequestBody, map[string]any{
			"release-candidate": specs.Example{
				Summary: "Create a release for evidence collection",
				Value: map[string]any{
					"product_id": "prod_20260527120000",
					"version":    "1.0.0-rc.1",
				},
			},
		})
		operation.Responses[http.StatusCreated] = jsonResponse("Created release envelope.", "#/components/schemas/ReleaseEnvelope")
		addJSONResponseExamples(&operation, http.StatusCreated, map[string]any{
			"created-release": specs.Example{
				Summary: "Created release response",
				Value: map[string]any{
					"data": map[string]any{
						"id":         "rel_20260527120000",
						"tenant_id":  "ten_20260527120000",
						"product_id": "prod_20260527120000",
						"version":    "1.0.0-rc.1",
						"revision":   1,
						"state":      "draft",
						"created_at": "2026-05-27T12:00:00Z",
					},
					"meta": map[string]any{"api_version": "v1"},
				},
			},
		})
	case "getRelease":
		operation.Description = "Returns a tenant-scoped release by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "startReleaseEvidenceFlow":
		operation.Description = "Returns a high-level release evidence workflow plan, current evidence counts, required scopes, assumptions, and limitations. This read-only convenience operation does not create evidence."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		delete(operation.Responses, http.StatusCreated)
		operation.Responses[http.StatusOK] = jsonResponse("Release evidence flow envelope.", "#/components/schemas/ReleaseEvidenceFlowEnvelope")
	case "releaseSecuritySummary":
		operation.Description = "Returns a tenant-scoped release security summary for review surfaces without raw evidence payload bytes."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release security summary envelope.", "#/components/schemas/ReleaseSecuritySummaryEnvelope")
	case "freezeRelease":
		operation.Description = "Freezes a release as an append-only transition. Supply the current revision as a strong decimal ETag in If-Match."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."), revisionIfMatchParam())
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Frozen release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "approveRelease":
		operation.Description = "Approves a release as an append-only transition. Supply the current revision as a strong decimal ETag in If-Match."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."), revisionIfMatchParam())
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Approved release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "registerArtifact":
		operation.Description = "Registers a tenant-scoped artifact digest for later evidence, build, and attestation matching."
		operation.RequestBody = jsonRequest("Artifact registration request.", "#/components/schemas/RegisterArtifactRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Registered artifact envelope.", "#/components/schemas/ArtifactEnvelope")
	case "getArtifact":
		operation.Description = "Returns a tenant-scoped artifact by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Artifact id."))
		operation.Responses[http.StatusOK] = jsonResponse("Artifact envelope.", "#/components/schemas/ArtifactEnvelope")
	case "createBuild":
		operation.Description = "Records an immutable CI build run. Collector identity is derived from the authenticated key when present."
		operation.RequestBody = jsonRequest("Build run creation request.", "#/components/schemas/CreateBuildRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created build run envelope.", "#/components/schemas/BuildRunEnvelope")
	case "getBuild":
		operation.Description = "Returns a tenant-scoped build run by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build run id."))
		operation.Responses[http.StatusOK] = jsonResponse("Build run envelope.", "#/components/schemas/BuildRunEnvelope")
	case "uploadGitHubSourceSnapshot":
		operation.Description = "Records a strict GitHub source snapshot. PostgreSQL checks current project and repository ownership and commits all supplied source components and audit entries in one transaction. Repository and commit identities are reused, branches are current state, and each executed pull-request recording appends a new snapshot. Stores only the exact-byte message hash; omitted commit time defaults to server time. Optional components must be omitted rather than null. Request replay adds no effects. The provider label is submitted metadata and does not verify GitHub origin, signatures, or review authority."
		operation.RequestBody = jsonRequest("GitHub source snapshot upload request.", "#/components/schemas/SourceSnapshotRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source snapshot resources envelope.", "#/components/schemas/SourceSnapshotEnvelope")
	case "uploadGitLabSourceSnapshot":
		operation.Description = "Records a strict GitLab source snapshot. PostgreSQL checks current project and repository ownership and commits all supplied source components and audit entries in one transaction. Repository and commit identities are reused, branches are current state, and each executed pull-request recording appends a new snapshot. Stores only the exact-byte message hash; omitted commit time defaults to server time. Optional components must be omitted rather than null. Request replay adds no effects. The provider label is submitted metadata and does not verify GitLab origin, signatures, or review authority."
		operation.RequestBody = jsonRequest("GitLab source snapshot upload request.", "#/components/schemas/SourceSnapshotRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source snapshot resources envelope.", "#/components/schemas/SourceSnapshotEnvelope")
	case "uploadSBOM":
		operation.Description = "Uploads a CycloneDX SBOM payload, stores raw bytes in object storage, and records normalized SBOM metadata. Use application/vnd.cyclonedx+json with the explicit metadata headers for streaming uploads up to 20 MiB; the JSON envelope remains limited to small requests."
		operation.Description += focusedSBOMIngestionDescription
		operation.RequestBody = streamingDocumentRequest("CycloneDX SBOM upload request.", "#/components/schemas/EvidenceUploadRequest", "application/vnd.cyclonedx+json", app.EvidenceDocumentLimit)
		operation.Parameters = append(operation.Parameters, optionalHeaderParam("X-Evydence-Release-ID", "Required for a native CycloneDX document upload."), optionalHeaderParam("X-Evydence-Artifact-ID", "Optional artifact id for a native CycloneDX document upload."))
		setRequestBodyLimit(&operation, app.EvidenceDocumentLimit)
		addJSONRequestExamples(operation.RequestBody, map[string]any{
			"cyclonedx-release-sbom": specs.Example{
				Summary: "Upload a CycloneDX SBOM linked to the release artifact",
				Value:   cyclonedxSBOMUploadExample(),
			},
		})
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "getSBOM":
		operation.Description = "Returns a tenant-scoped SBOM record and its stored components when parsed; an accepted pending record may have an empty spec version and no components. In the PostgreSQL profile, source evidence and optional release/artifact parents must resolve within the same tenant, and the optional artifact must match the source evidence's sole artifact subject, before current resource grants are applied."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SBOM id."))
		operation.Responses[http.StatusOK] = jsonResponse("SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "uploadVEX":
		operation.Description = "Uploads OpenVEX payload bytes and atomically records normalized VEX metadata, an accepted import report, and a versioned bounded decision request. Decision mapping always runs asynchronously after commit. When a durable object payload is available, the worker replays it and verifies that it matches the normalized request; otherwise the worker consumes the normalized request directly. Poll the import-report endpoint for parsed or failed status. Use application/vnd.openvex+json with the explicit metadata headers for streaming uploads up to 20 MiB; the JSON envelope remains limited to small requests."
		operation.Description += focusedVEXIngestionDescription
		operation.RequestBody = streamingDocumentRequest("OpenVEX upload request.", "#/components/schemas/EvidenceUploadRequest", "application/vnd.openvex+json", app.EvidenceDocumentLimit)
		operation.Parameters = append(operation.Parameters, optionalHeaderParam("X-Evydence-Release-ID", "Required for a native OpenVEX document upload."), optionalHeaderParam("X-Evydence-Artifact-ID", "Optional artifact id for a native OpenVEX document upload."))
		setRequestBodyLimit(&operation, app.EvidenceDocumentLimit)
		operation.RequestBody.Content["application/json"] = specs.MediaType{
			SchemaRef: "#/components/schemas/EvidenceUploadRequest",
			Examples: map[string]any{
				"openvex-fixed-decision": specs.Example{
					Summary: "Upload OpenVEX for asynchronous decision mapping",
					Value:   openVEXUploadExample(),
				},
			},
		}
		operation.Responses[http.StatusCreated] = jsonResponse("Created VEX document envelope.", "#/components/schemas/VEXDocumentEnvelope")
	case "previewVEXImport":
		operation.Description = "Validates an OpenVEX payload and returns advisory mapping counts without storing raw payloads, creating evidence, creating decisions, or enqueueing parser jobs."
		operation.Description += focusedVEXPreviewDescription
		operation.RequestBody = jsonRequest("OpenVEX import preview request.", "#/components/schemas/EvidenceUploadRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Advisory VEX import preview envelope.", "#/components/schemas/VEXImportPreviewEnvelope")
	case "uploadCycloneDXVEX":
		operation.Description = "Uploads CycloneDX VEX JSON and atomically records normalized VEX metadata, an accepted import report, and a versioned bounded decision request. Decision mapping always runs asynchronously after commit. When a durable object payload is available, the worker replays it and verifies that it matches the normalized request; otherwise the worker consumes the normalized request directly. Poll the import-report endpoint for parsed or failed status."
		operation.Description += focusedVEXIngestionDescription
		operation.RequestBody = jsonRequest("CycloneDX VEX upload request.", "#/components/schemas/EvidenceUploadRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created VEX document envelope.", "#/components/schemas/VEXDocumentEnvelope")
	case "previewCycloneDXVEXImport":
		operation.Description = "Validates a CycloneDX VEX payload and returns advisory mapping counts without storing raw payloads, creating evidence, creating decisions, or enqueueing parser jobs."
		operation.Description += focusedVEXPreviewDescription
		operation.RequestBody = jsonRequest("CycloneDX VEX import preview request.", "#/components/schemas/EvidenceUploadRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Advisory VEX import preview envelope.", "#/components/schemas/VEXImportPreviewEnvelope")
	case "getVEX":
		operation.Description = "Returns a tenant-scoped VEX document metadata record by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "VEX document id."))
		operation.Responses[http.StatusOK] = jsonResponse("VEX document envelope.", "#/components/schemas/VEXDocumentEnvelope")
	case "getVEXImportReport":
		operation.Description = "Returns the persisted parser report for a tenant-scoped VEX import. Uploads begin as accepted and become parsed or failed after asynchronous decision processing; the report includes safe counts, warnings, and mapping failures without raw payload bytes."
		operation.Parameters = append(operation.Parameters, pathParam("id", "VEX document id."))
		operation.Responses[http.StatusOK] = jsonResponse("VEX import report envelope.", "#/components/schemas/VEXImportReportEnvelope")
	case "uploadVulnerabilityScan":
		operation.Description = "Uploads either the Evydence generic scan schema or a versioned native-scanner envelope (Grype, Trivy, OSV-Scanner, or Dependency-Track). Scanner output is preserved as raw evidence and is not treated as authoritative. The request is streamed to a private temporary file while hashing and is limited to 20 MiB."
		operation.Description += " In PostgreSQL mode, scope-only authorization precedes a complete bounded, size/SHA-256-checked release-ID probe. Normalized release IDs are NUL-free UTF-8 bounded at 1024 bytes. A focused command checks current tenant-owned release parents and human resource grants before full findings normalization or object staging. Normalized projections allow 100,000 findings, 1 MiB per string, and 64 MiB of combined projection strings; severity summaries must match findings. Scan, evidence, audit, payload metadata, outbox, and idempotency completion commit together. Same-byte replay checks current grants and exact tenant/release coordinates without findings normalization or staging. With worker-owned parsing and object storage, the response contains parsed findings while the stored projection stays accepted until its parser job runs."
		operation.RequestBody = jsonRequest("Generic scan or versioned native-scanner envelope.", "#/components/schemas/UploadVulnerabilityScanBody")
		setRequestBodyLimit(&operation, app.EvidenceDocumentLimit)
		addJSONRequestExamples(operation.RequestBody, map[string]any{
			"generic-critical-finding": specs.Example{
				Summary: "Upload a generic scanner finding for release triage",
				Value:   vulnerabilityScanUploadExample(),
			},
			"grype-envelope": specs.Example{Summary: "Preserve a Grype JSON report with explicit release scope", Value: map[string]any{"scanner": "grype", "target_ref": "pkg:oci/payments-api@sha256-ca978112", "release_id": "rel_20260527120000", "source_schema": "grype-json.v1", "payload": map[string]any{"matches": []any{}}}},
		})
		operation.Responses[http.StatusCreated] = jsonResponse("Created vulnerability scan envelope.", "#/components/schemas/VulnerabilityScanEnvelope")
	case "getVulnerabilityScan":
		operation.Description = "Returns a tenant-scoped vulnerability scan by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Vulnerability scan id."))
		operation.Responses[http.StatusOK] = jsonResponse("Vulnerability scan envelope.", "#/components/schemas/VulnerabilityScanEnvelope")
	case "createEvidence":
		operation.Description = "Creates immutable evidence metadata and optional raw payload evidence. Evidence core fields are append-only after creation."
		operation.RequestBody = jsonRequest("Evidence creation request.", "#/components/schemas/CreateEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "listEvidence":
		operation.Description = "Lists tenant-scoped evidence by optional release and evidence type filters."
		operation.Parameters = append(operation.Parameters,
			queryParam("release_id", "Filter by release id.", "string"),
			queryParam("type", "Filter by evidence type.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Evidence item list envelope.", "#/components/schemas/EvidenceItemListEnvelope")
	case "searchEvidence":
		operation.Description = "Searches tenant-scoped evidence with deterministic filters. The legacy source alias remains supported for source_system."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Filter by product id.", "string"),
			queryParam("project_id", "Filter by project id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
			queryParam("build_id", "Filter by build id.", "string"),
			queryParam("deployment_id", "Filter by deployment id.", "string"),
			queryParam("type", "Filter by evidence type.", "string"),
			queryParam("subtype", "Filter by evidence subtype.", "string"),
			queryParam("source", "Deprecated alias for source_system.", "string"),
			queryParam("source_system", "Filter by evidence source system.", "string"),
			queryParam("collector_id", "Filter by collector id.", "string"),
			queryParam("verification_status", "Filter by verification status.", "string"),
			queryParam("subject_type", "Filter by subject type.", "string"),
			queryParam("subject_id", "Filter by subject id.", "string"),
			queryParam("tag", "Filter by a single evidence tag.", "string"),
			queryParam("created_after", "Filter by an RFC3339 creation timestamp inclusive lower bound.", "string"),
			queryParam("created_before", "Filter by an RFC3339 creation timestamp inclusive upper bound.", "string"),
			queryParam("limit", "Maximum returned records.", "integer"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Evidence search result envelope.", "#/components/schemas/EvidenceSearchEnvelope")
	case "getEvidence":
		operation.Description = "Returns a tenant-scoped immutable evidence item by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.Responses[http.StatusOK] = jsonResponse("Evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "createGraphSnapshot":
		operation.Description = "Creates a deterministic product/release evidence adjacency snapshot from stored tenant-scoped evidence records."
		operation.RequestBody = jsonRequest("Evidence graph snapshot creation request.", "#/components/schemas/CreateGraphSnapshotRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence graph snapshot envelope.", "#/components/schemas/EvidenceGraphSnapshotEnvelope")
	case "listSBOMComponents":
		operation.Description = "Lists tenant- and resource-grant-scoped SBOM components by SBOM, release, artifact, name/version/PURL query, or exact PURL. In the PostgreSQL profile, results use durable keyset pages without the legacy 500-component preselection cap. Source evidence must be an SBOM with matching release and artifact subject; an inaccessible, missing, or inconsistently linked filtered SBOM returns 404."
		operation.Parameters = append(operation.Parameters,
			queryParam("sbom_id", "Filter by SBOM id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
			queryParam("artifact_id", "Filter by artifact id.", "string"),
			queryParam("query", "Case-insensitive component name, version, or PURL search.", "string"),
			queryParam("purl", "Exact package URL filter.", "string"),
			queryParam("limit", "Maximum returned component records.", "integer"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("SBOM component result envelope.", "#/components/schemas/SBOMComponentRecordListEnvelope")
	case "createIncident":
		operation.Description = "Creates an append-only incident linked to a current tenant-owned product and optional matching release. PostgreSQL uses a focused Operations command; incident:write and current human tenant/product/release grants are checked before creation or replay. Record, principal-attributed audit, and replay completion commit together. Omitted opened_at defaults to creation time; timestamps are UTC with microsecond precision. Null fields and NUL/invalid UTF-8 are rejected; IDs are capped at 1024 bytes and title at 64 KiB."
		operation.RequestBody = jsonRequest("Incident creation request.", "#/components/schemas/CreateIncidentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident envelope.", "#/components/schemas/IncidentEnvelope")
	case "recordIncidentTimeline":
		operation.Description = "Appends a timeline event to a current tenant-owned incident. PostgreSQL uses a focused Operations command and independently checks incident:write grants for the incident and optional current evidence parents before creation or replay. Event, audit, and replay completion commit together. Omitted occurred_at defaults to creation time; timestamps are UTC with microsecond precision. Null fields and NUL/invalid UTF-8 are rejected; IDs are capped at 1024 bytes and event_type/summary at 64 KiB each. Linked evidence organizes recorded references without proving remediation completeness."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Incident id."))
		operation.RequestBody = jsonRequest("Incident timeline event request.", "#/components/schemas/RecordIncidentTimelineRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident timeline event envelope.", "#/components/schemas/IncidentTimelineEventEnvelope")
	case "createIncidentWebhookReceiver":
		operation.Description = "Creates an incident-scoped Ed25519 webhook receiver. PostgreSQL uses a focused Operations command, current tenant-owned incident parents, and incident:write grants before creation or HTTP idempotency replay. Receiver, principal audit, and replay completion commit together. Public keys accept raw or padded standard base64 and are stored as raw standard base64; private keys stay with the external incident tool. JSON bodies are limited to 64 KiB; null/duplicate/unknown fields, NUL, and invalid UTF-8 are rejected. IDs are capped at 1024 UTF-8 bytes, name/provider at 64 KiB each, and encoded keys at 1024 bytes. New timestamps use UTC microsecond precision."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Incident id."))
		operation.RequestBody = jsonRequest("Incident webhook receiver creation request.", "#/components/schemas/CreateIncidentWebhookReceiverRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident webhook receiver envelope.", "#/components/schemas/IncidentWebhookReceiverEnvelope")
	case "receiveIncidentWebhook":
		operation.Description = "Public incident timeline webhook: no bearer token or HTTP Idempotency-Key is required. PostgreSQL uses focused Operations commands and bounded tenant/receiver/event point reads. A single event-id, timestamp, and signature header is required. The Ed25519 signature covers UTC RFC3339 seconds, newline, trimmed event id, newline, and exact body bytes; timestamps must be within five minutes. Verification precedes payload parsing. Event-id retries with the same bytes return the original event/timeline, including after a fresh signature; changed bytes conflict. Current receiver status/key, incident parents, and linked evidence ownership are rechecked on replay. Evidence must belong to the incident product and, if release-scoped, its release. Event, timeline, and webhook-attributed audit commit together. JSON bodies are limited to 64 KiB and reject null/duplicate/unknown fields, NUL, and invalid UTF-8. IDs are capped at 1024 UTF-8 bytes; the tenant/receiver/event replay key is capped at 2304 combined bytes. New timestamps use UTC microsecond precision."
		operation.Parameters = append(operation.Parameters,
			pathParam("receiver_id", "Incident webhook receiver id."),
			headerParam("X-Evydence-Webhook-Event-ID", "Provider event id used for replay detection."),
			headerParam("X-Evydence-Webhook-Timestamp", "RFC3339 timestamp included in the signed payload."),
			headerParam("X-Evydence-Webhook-Signature", "ed25519=<base64 signature> over timestamp, event id, and raw body."),
		)
		operation.RequestBody = jsonRequest("Signed incident timeline event payload.", "#/components/schemas/SignedIncidentWebhookPayload")
		operation.Security = nil
		operation.Scopes = nil
		operation.Extensions = withStability(operation.OperationID, nil)
		operation.Responses[http.StatusCreated] = jsonResponse("Accepted webhook event and timeline event envelope.", "#/components/schemas/IncidentWebhookDeliveryEnvelope")
	case "createRemediationTask":
		operation.Description = "Creates a remediation task with at least one incident or release reference and optional evidence. PostgreSQL uses a focused Operations command and independently checks incident:write grants for every current tenant-owned reference before creation or replay. Authorized incident and release references need not share a product. Task, audit, and replay completion commit together. Omitted due_at is absent; explicit null is rejected as published. Timestamps are UTC with microsecond precision. IDs are capped at 1024 bytes and title/owner at 64 KiB each; NUL/invalid UTF-8 are rejected. Recording a task does not prove remediation completeness."
		operation.RequestBody = jsonRequest("Remediation task creation request.", "#/components/schemas/CreateRemediationTaskRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created remediation task envelope.", "#/components/schemas/RemediationTaskEnvelope")
	case "incidentReport":
		operation.Description = "Returns a deterministic incident package report with timeline, remediation tasks, linked evidence, assumptions, and limitations."
		operation.Parameters = append(operation.Parameters, queryParam("incident_id", "Incident id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Incident package report envelope.", "#/components/schemas/IncidentReportEnvelope")
	case "createReleaseBundle":
		operation.Description = "Creates an immutable signed release bundle for a release."
		operation.RequestBody = jsonRequest("Release bundle creation request.", "#/components/schemas/CreateReleaseBundleRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created release bundle envelope.", "#/components/schemas/ReleaseBundleEnvelope")
	case "getReleaseBundle":
		operation.Description = "Returns an immutable release bundle by id only when its current tenant-owned release is covered by the caller's bundle:read grant."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle envelope.", "#/components/schemas/ReleaseBundleEnvelope")
	case "getReleaseBundleManifest":
		operation.Description = "Returns the deterministic release bundle manifest by id under the same current-release and bundle:read authorization as the bundle read."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle manifest envelope.", "#/components/schemas/ReleaseBundleManifestEnvelope")
	case "verifyReleaseBundle":
		operation.Description = "Verifies a tenant-scoped release bundle and returns a deterministic verification result."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "verifyAuditChain":
		operation.Description = "Recomputes tenant audit-chain entry hashes, continuity, schema versions, and referenced signatures. This local verification does not by itself prove protection from an administrator able to rewrite all history and signing material."
		operation.Responses[http.StatusOK] = jsonResponse("Audit chain verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "verify":
		operation.Description = "Verifies a supported tenant-scoped subject. Audit-chain checkpoint verification supports audit_chain_checkpoint with a Merkle batch id and audit_chain_release_manifest with a release bundle id."
		operation.RequestBody = jsonRequest("Subject verification request.", "#/components/schemas/VerifySubjectRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Subject verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "listAuditLog":
		operation.Description = "Lists tenant-scoped append-only audit-chain entries in reverse chronological order. Human sessions require a tenant-wide admin grant."
		operation.Parameters = append(operation.Parameters,
			queryParam("subject_type", "Filter by audited subject type.", "string"),
			queryParam("subject_id", "Filter by audited subject id.", "string"),
			queryParam("since", "Only include entries at or after this RFC3339 timestamp.", "string"),
			queryParam("limit", "Deprecated maximum returned entries alias; defaults to 50 and caps at 500.", "integer"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Audit-chain entry list envelope.", "#/components/schemas/AuditChainEntryListEnvelope")
	case "generateBackupManifest":
		operation.Description = "Generates a tenant-scoped metadata commitment, not a restore receipt or proof that an operator backup completed. PostgreSQL emits backup-manifest.v2.0.0 with tenant-relational-state.v2 semantics, including append-only decision supersession history; historical commitments retain their recorded profiles and local-memory v1 hashes remain distinct. Credential material, replay bookkeeping and raw object payload bytes are excluded."
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusCreated] = jsonResponse("Backup manifest envelope.", "#/components/schemas/BackupManifestEnvelope")
	case "verifyBackupManifest":
		operation.Description = "Verifies a tenant-scoped backup manifest and returns deterministic manifest verification checks."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Backup manifest id."))
		operation.Responses[http.StatusOK] = jsonResponse("Backup manifest verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "releaseReadinessReport":
		operation.Description = "Returns a deterministic release-readiness report with gaps, assumptions, and limitations."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Release readiness report envelope.", "#/components/schemas/ReadinessReportEnvelope")
		addJSONResponseExamples(&operation, http.StatusOK, map[string]any{
			"failed-readiness-with-gap": specs.Example{
				Summary: "Readiness report with a vulnerability decision gap",
				Value:   releaseReadinessReportExample(),
			},
		})
	case "missingEvidenceReport":
		operation.Description = "Returns a deterministic missing-evidence report for a release with assumptions and limitations."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Missing evidence report envelope.", "#/components/schemas/MissingEvidenceReportEnvelope")
	case "evaluatePolicy":
		operation.Description = "Evaluates built-in deterministic release policy checks for a release."
		operation.RequestBody = jsonRequest("Policy evaluation request.", "#/components/schemas/EvaluatePolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Policy evaluation envelope.", "#/components/schemas/PolicyEvaluationEnvelope")
	case "createVulnerabilityDecision":
		operation.Description = "Creates an append-only vulnerability decision for a tenant-scoped scan finding. Tenant-internal notes are accepted for the ledger but excluded from the response and idempotency replays."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Vulnerability finding id."))
		operation.RequestBody = jsonRequest("Vulnerability decision creation request.", "#/components/schemas/CreateVulnerabilityDecisionRequest")
		addJSONRequestExamples(operation.RequestBody, map[string]any{
			"not-affected-decision": specs.Example{
				Summary: "Record a customer-visible not-affected decision",
				Value:   vulnerabilityDecisionExample(),
			},
		})
		operation.Responses[http.StatusCreated] = jsonResponse("Created vulnerability decision envelope.", "#/components/schemas/VulnerabilityDecisionEnvelope")
	case "listVulnerabilityDecisions":
		operation.Description = "Lists append-only vulnerability decisions over time with tenant-scoped product, release, vulnerability, component, status, and active filters. Tenant-internal notes are excluded from responses."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Filter by product id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
			queryParam("vulnerability", "Filter by vulnerability identifier.", "string"),
			queryParam("component", "Filter by affected component.", "string"),
			queryParam("status", "Filter by decision status.", "string"),
			queryParam("active", "When true returns active decisions; when false returns superseded decisions.", "boolean"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Vulnerability decision list envelope.", "#/components/schemas/VulnerabilityDecisionListEnvelope")
	case "recordVulnerabilityWorkflow":
		operation.Description = "Records an append-only vulnerability workflow event for a tenant-scoped finding."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Vulnerability finding id."))
		operation.RequestBody = jsonRequest("Vulnerability workflow event request.", "#/components/schemas/RecordVulnerabilityWorkflowRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created vulnerability workflow record envelope.", "#/components/schemas/VulnerabilityWorkflowRecordEnvelope")
	case "createException":
		operation.Description = "Creates a scoped, expiring release/finding/control exception that is inactive until approved."
		operation.RequestBody = jsonRequest("Exception creation request.", "#/components/schemas/CreateExceptionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created exception envelope.", "#/components/schemas/ExceptionEnvelope")
	case "listExceptions":
		operation.Description = "Lists tenant- and current verify-grant-scoped exceptions, optionally filtered by release. In the PostgreSQL profile, release ownership and bounded keyset pages are resolved in one database snapshot before results are returned. A missing filtered release returns 404; an existing release outside the actor's grants returns 403."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Exception list envelope.", "#/components/schemas/ExceptionListEnvelope")
	case "approveException":
		operation.Description = "Approves an unexpired exception as an audited append-only transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Exception id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Approved exception envelope.", "#/components/schemas/ExceptionEnvelope")
	case "createCustomPolicy":
		operation.Description = "Creates a deterministic custom policy definition for tenant-managed release checks."
		operation.RequestBody = jsonRequest("Custom policy creation request.", "#/components/schemas/CreateCustomPolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created custom policy envelope.", "#/components/schemas/CustomPolicyEnvelope")
	case "evaluateCustomPolicy":
		operation.Description = "Evaluates a tenant custom policy against a release and records the input hash."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Custom policy id."))
		operation.RequestBody = jsonRequest("Custom policy evaluation request.", "#/components/schemas/EvaluatePolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Custom policy evaluation envelope.", "#/components/schemas/CustomPolicyEvaluationEnvelope")
	case "createWaiver":
		operation.Description = "Creates a first-class scoped waiver for controls or policies. Approval is a separate audited transition."
		operation.RequestBody = jsonRequest("Waiver creation request.", "#/components/schemas/CreateWaiverRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created waiver envelope.", "#/components/schemas/WaiverEnvelope")
	case "approveWaiver":
		operation.Description = "Approves an unexpired waiver as an audited transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Waiver id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Approved waiver envelope.", "#/components/schemas/WaiverEnvelope")
	case "createApproval":
		operation.Description = "Creates an immutable approval record for a release, waiver, package, or review subject."
		operation.RequestBody = jsonRequest("Approval creation request.", "#/components/schemas/CreateApprovalRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created approval envelope.", "#/components/schemas/ApprovalRecordEnvelope")
	case "uploadOpenAPIContract":
		operation.Description = "Uploads an OpenAPI 3.1 contract, stores raw bytes as evidence, and records normalized operation metadata. Use application/vnd.oai.openapi+json with the explicit metadata headers for streaming uploads up to 20 MiB; the JSON envelope remains limited to small requests."
		operation.RequestBody = streamingDocumentRequest("OpenAPI contract upload request.", "#/components/schemas/UploadOpenAPIContractRequest", "application/vnd.oai.openapi+json", app.EvidenceDocumentLimit)
		operation.Parameters = append(operation.Parameters, optionalHeaderParam("X-Evydence-Product-ID", "Required for a native OpenAPI document upload."), optionalHeaderParam("X-Evydence-Release-ID", "Required for a native OpenAPI document upload."), optionalHeaderParam("X-Evydence-Version", "Required for a native OpenAPI document upload."))
		setRequestBodyLimit(&operation, app.EvidenceDocumentLimit)
		operation.Responses[http.StatusCreated] = jsonResponse("Created OpenAPI contract envelope.", "#/components/schemas/OpenAPIContractEnvelope")
	case "getOpenAPIContract":
		operation.Description = "Returns tenant-scoped OpenAPI contract metadata by id. PostgreSQL reads require current same-tenant source evidence, product, and optional release parentage; human sessions need an evidence:read grant covering the product or release."
		operation.Parameters = append(operation.Parameters, pathParam("id", "OpenAPI contract id."))
		operation.Responses[http.StatusOK] = jsonResponse("OpenAPI contract envelope.", "#/components/schemas/OpenAPIContractEnvelope")
	case "createOpenAPIDiff":
		operation.Description = "Creates a deterministic OpenAPI contract diff for release contract checks."
		operation.RequestBody = jsonRequest("OpenAPI contract diff request.", "#/components/schemas/CreateOpenAPIDiffRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created OpenAPI contract diff envelope.", "#/components/schemas/ContractDiffEnvelope")
	case "listSigningKeys":
		operation.Description = "Lists tenant signing public-key lifecycle metadata under verify:read; human sessions require a current tenant-level grant. PostgreSQL reads are keyset-paginated and never select encrypted private key material."
		operation.Responses[http.StatusOK] = jsonResponse("Signing key list envelope.", "#/components/schemas/SigningKeyListEnvelope")
	case "rotateSigningKey":
		operation.Description = "Rotates the active tenant signing key, retires the prior key with an explicit validity window, and returns public-key metadata only."
		operation.RequestBody = jsonRequest("Signing key rotation request.", "#/components/schemas/SigningKeyTransitionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Rotated signing key envelope.", "#/components/schemas/SigningKeyEnvelope")
	case "revokeSigningKey":
		operation.Description = "Revokes a tenant signing key as an audited lifecycle transition. Ordinary revocation preserves signatures valid at signing time; compromised-key policy is explicit and can invalidate historical results."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Signing key id."))
		operation.RequestBody = jsonRequest("Signing key revocation request.", "#/components/schemas/SigningKeyTransitionRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked signing key envelope.", "#/components/schemas/SigningKeyEnvelope")
	case "createSigningProvider":
		operation.Description = "Creates signing provider metadata for external signing operations. Production private key material must not be supplied."
		operation.RequestBody = jsonRequest("Signing provider creation request.", "#/components/schemas/CreateSigningProviderRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created signing provider envelope.", "#/components/schemas/SigningProviderEnvelope")
	case "createSigningOperation":
		operation.Description = "Requests a configured signing executor to sign a canonical request binding the provider, key reference, subject, payload digest, request id, and nonce. Caller-supplied signatures are rejected."
		operation.RequestBody = jsonRequest("Signing operation creation request.", "#/components/schemas/CreateSigningOperationRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created signing operation envelope.", "#/components/schemas/SigningOperationEnvelope")
	case "createArtifactSignature":
		operation.Description = "Records detached artifact signature evidence with recorded status; creation does not verify cryptographic trust. PostgreSQL authorizes the current tenant-owned artifact, stages optional JSON payload bytes, and commits signature metadata, payload lifecycle, finalization job and audit in the same transaction. Human sessions need a current artifact association covered by evidence:write grants. IDs are bounded at 1024 bytes; algorithm and signature text at 64 KiB. Payload staging is not finalization."
		operation.RequestBody = jsonRequest("Artifact signature creation request.", "#/components/schemas/CreateArtifactSignatureRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created artifact signature envelope.", "#/components/schemas/ArtifactSignatureEnvelope")
	case "getArtifactSignature":
		operation.Description = "Returns artifact signature metadata by id only when the current tenant owns the signature and its artifact digest still matches. A human session additionally needs an evidence:read grant covering a current evidence or build association; issued credentials use their evidence:read scope."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Artifact signature id."))
		operation.Responses[http.StatusOK] = jsonResponse("Artifact signature envelope.", "#/components/schemas/ArtifactSignatureEnvelope")
	case "verifyCosignSignature":
		operation.Description = "Cryptographically verifies a stored Sigstore/Cosign bundle against operator-configured trust material and caller-supplied keyless identity policy. The explicit offline profile requires an embedded Rekor inclusion proof and does not silently downgrade an online-required request."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Artifact signature id."))
		operation.RequestBody = jsonRequest("Cosign policy verification request.", "#/components/schemas/VerifyCosignSignatureRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Cosign verification envelope.", "#/components/schemas/CosignVerificationEnvelope")
	case "uploadBuildAttestation":
		operation.Description = "Uploads a DSSE/in-toto build attestation for a tenant-scoped build and stores raw bytes in object storage."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build run id."))
		operation.RequestBody = jsonRequest("DSSE envelope.", "#/components/schemas/DSSEEnvelope")
		operation.Responses[http.StatusCreated] = jsonResponse("Created build attestation envelope.", "#/components/schemas/BuildAttestationEnvelope")
	case "verifyBuildAttestationSignature":
		operation.Description = "Offline-verifies DSSE PAE, an in-toto Statement v1/SLSA provenance v1 predicate, registered release-artifact subject digests, and immutable configured tenant-root policy."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build attestation id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Build attestation verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "createDSSETrustRoot":
		operation.Description = "Creates a tenant-scoped immutable DSSE Ed25519 trust root with an explicit SLSA predicate, builder, and required-claims policy."
		operation.RequestBody = jsonRequest("DSSE trust-root creation request.", "#/components/schemas/CreateDSSETrustRootRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created DSSE trust root envelope.", "#/components/schemas/DSSETrustRootEnvelope")
	case "createReleaseCandidate":
		operation.Description = "Creates an immutable release-candidate snapshot of selected release evidence references."
		operation.RequestBody = jsonRequest("Release candidate creation request.", "#/components/schemas/CreateReleaseCandidateRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created release candidate envelope.", "#/components/schemas/ReleaseCandidateEnvelope")
	case "listReleaseCandidates":
		operation.Description = "Lists tenant-scoped release candidates, optionally filtered by release."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Release candidate list envelope.", "#/components/schemas/ReleaseCandidateListEnvelope")
	case "getReleaseCandidate":
		operation.Description = "Returns a tenant-scoped release candidate by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release candidate id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release candidate envelope.", "#/components/schemas/ReleaseCandidateEnvelope")
	case "promoteReleaseCandidate", "rejectReleaseCandidate":
		operation.Description = "Records a release-candidate lifecycle transition without mutating the original snapshot. Supply the current revision as a strong decimal ETag in If-Match."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release candidate id."), revisionIfMatchParam())
		operation.RequestBody = jsonRequest("Release candidate transition request.", "#/components/schemas/ReleaseCandidateTransitionRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Transitioned release candidate envelope.", "#/components/schemas/ReleaseCandidateEnvelope")
	case "supersedeEvidence":
		operation.Description = "Supersedes immutable evidence by linking it to replacement evidence and appending lifecycle metadata. Worker-owned parser and build-attestation evidence has fixed projection relationships and returns a conflict instead."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence supersession request.", "#/components/schemas/SupersedeEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Superseded evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "linkEvidence":
		operation.Description = "Creates an append-only relationship from evidence to another tenant-scoped subject. Worker-owned parser and build-attestation evidence has fixed projection relationships and returns a conflict instead."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence link request.", "#/components/schemas/LinkEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Linked evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "recordEvidenceLifecycleEvent":
		operation.Description = "Appends an evidence lifecycle event such as amendment, redaction marker, tombstone, or retention marker."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence lifecycle event request.", "#/components/schemas/RecordEvidenceLifecycleEventRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence lifecycle event envelope.", "#/components/schemas/EvidenceLifecycleEventEnvelope")
	case "listEvidenceLifecycleEvents":
		operation.Description = "Lists append-only lifecycle events for a tenant-scoped evidence item. PostgreSQL pages ordinary evidence events from a consistent snapshot without loading all lifecycle records; worker-owned evidence retains its validated projection path. Sensitive detail fields are removed from responses."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.Responses[http.StatusOK] = jsonResponse("Evidence lifecycle event list envelope.", "#/components/schemas/EvidenceLifecycleEventListEnvelope")
	case "createSourceRepository":
		operation.Description = "Creates source repository metadata with source:write authorization. PostgreSQL serializes tenant/provider/full-name reuse and returns the existing repository unchanged without another audit entry. Human sessions need a tenant-wide grant for detached creation, or a matching product/project grant for attached creation; the existing repository is separately authorized before metadata is read. IDs are bounded at 1024 bytes, tenant/provider/full-name keys at 2304 bytes and optional metadata at 64 KiB. Repository and audit records commit in the same transaction as HTTP replay state. This records supplied metadata and does not contact or verify the provider, clone URL or repository contents."
		operation.RequestBody = jsonRequest("Source repository creation request.", "#/components/schemas/CreateSourceRepositoryRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source repository envelope.", "#/components/schemas/SourceRepositoryEnvelope")
	case "listSourceRepositories":
		operation.Description = "Lists tenant-scoped source repositories, optionally filtered by project."
		operation.Parameters = append(operation.Parameters, queryParam("project_id", "Project id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Source repository list envelope.", "#/components/schemas/SourceRepositoryListEnvelope")
	case "recordSourceCommit":
		operation.Description = "Records immutable source commit metadata using current repository tenant/project authorization before metadata reads. PostgreSQL mode normalizes 40-character hexadecimal SHAs to lowercase and returns the original repository/SHA record without changing metadata or auditing twice. Commit and audit are persisted in the same transaction. Stores only sha256 of exact nonblank message bytes; whitespace-only messages have no hash. Author and message inputs are bounded to 64 KiB; timestamps use UTC microseconds and committed_at defaults to recording time when omitted. Recording does not verify provider identity or repository contents."
		operation.RequestBody = jsonRequest("Source commit creation request.", "#/components/schemas/RecordSourceCommitRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source commit envelope.", "#/components/schemas/SourceCommitEnvelope")
	case "upsertSourceBranch":
		operation.Description = "Records or replaces source branch metadata after current repository tenant/project authorization before metadata reads. PostgreSQL mode requires any supplied head commit to belong to the same repository and tenant. Existing branch identity and creation time are retained; head, protected flag and protection hash are replaced, including defaults when omitted. Repository/name upserts serialize; each executed create/update and its audit persist in the same transaction with replay state. Combined tenant/repository/name identity is limited to 2304 UTF-8 bytes and protection hash metadata to 64 KiB. A supplied protection hash is recorded metadata only; recording does not verify provider identity or branch protection."
		operation.RequestBody = jsonRequest("Source branch upsert request.", "#/components/schemas/UpsertSourceBranchRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Source branch envelope.", "#/components/schemas/SourceBranchEnvelope")
	case "recordPullRequest":
		operation.Description = "Records an append-only pull-request metadata snapshot after current repository tenant/project authorization before metadata reads. Any supplied head commit must belong to the same repository and tenant. Each non-replayed call creates a new snapshot, even for the same provider ID; recording does not update an earlier snapshot. An omitted provider defaults to the stored repository provider. Snapshot, audit and HTTP replay state persist in the same transaction. Tenant/repository/head IDs are bounded to 1024 UTF-8 bytes and submitted metadata to 64 KiB; states are open, closed or merged. Recording does not verify provider identity, repository contents, review approval or merge authority."
		operation.RequestBody = jsonRequest("Pull request record request.", "#/components/schemas/RecordPullRequestRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created pull request envelope.", "#/components/schemas/PullRequestEnvelope")
	case "createDeploymentEnvironment":
		operation.Description = "Creates tenant-owned deployment environment metadata after deployment:write authorization. PostgreSQL serializes tenant/product/name reuse and returns the original environment without changing its kind or appending another audit entry. Human sessions need a tenant or product grant. New environment and audit records commit in the same transaction; replay adds no effects. Tenant/product IDs are bounded at 1024 bytes and kind text at 64 KiB; the combined tenant ID, product ID and normalized name is bounded at 2304 bytes to fit the unique database key. This records an environment definition, not proof of an actual deployment."
		operation.RequestBody = jsonRequest("Deployment environment creation request.", "#/components/schemas/CreateDeploymentEnvironmentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created deployment environment envelope.", "#/components/schemas/DeploymentEnvironmentEnvelope")
	case "listDeploymentEnvironments":
		operation.Description = "Lists tenant-scoped deployment environments, optionally filtered by product."
		operation.Parameters = append(operation.Parameters, queryParam("product_id", "Product id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Deployment environment list envelope.", "#/components/schemas/DeploymentEnvironmentListEnvelope")
	case "recordDeployment":
		operation.Description = "Records append-only deployment metadata with immediately readable deployment/event evidence in the same transaction as both audit entries and HTTP replay state. Requires deployment:write; human sessions need a current tenant, product or release grant. Environment and release must have the same tenant and product; rollback targets must use the same environment, and artifacts must be tenant-owned. Reference IDs are bounded at 1024 bytes and artifact lists at 1024 entries. Omitted started_at defaults to command time; supplied timestamps are normalized to UTC without imposing ordering. PostgreSQL uses bounded identity reads without Ledger state. This records supplied metadata and does not prove runtime security or availability."
		operation.RequestBody = jsonRequest("Deployment event creation request.", "#/components/schemas/RecordDeploymentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created deployment event envelope.", "#/components/schemas/DeploymentEventEnvelope")
	case "listDeployments":
		operation.Description = "Lists tenant-scoped deployment events by optional release and environment filters."
		operation.Parameters = append(operation.Parameters,
			queryParam("release_id", "Release id.", "string"),
			queryParam("environment_id", "Deployment environment id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Deployment event list envelope.", "#/components/schemas/DeploymentEventListEnvelope")
	case "getDeployment":
		operation.Description = "Returns a tenant-scoped deployment event by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Deployment event id."))
		operation.Responses[http.StatusOK] = jsonResponse("Deployment event envelope.", "#/components/schemas/DeploymentEventEnvelope")
	case "recordCollectorRelease":
		operation.Description = "Records collector release evidence through bounded current collector, signature/artifact, SBOM/evidence and scan/evidence reads in PostgreSQL. Human sessions require a tenant-wide collector:admin grant, checked before replay. Pins, release rows, audit and replay state commit atomically. Reference presence is not proof of runtime safety or vulnerability absence."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Collector id."))
		operation.RequestBody = jsonRequest("Collector release record request.", "#/components/schemas/RecordCollectorReleaseRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created collector release envelope.", "#/components/schemas/CollectorReleaseEnvelope")
	case "collectorHealthReport":
		operation.Description = "Returns collector supply-chain health from recorded tenant evidence, assumptions, and limitations. Production resolves the collector and its latest and pinned releases in one tenant-scoped database snapshot; human sessions require a tenant-wide collector:read grant."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Collector id."))
		operation.Responses[http.StatusOK] = jsonResponse("Collector health report envelope.", "#/components/schemas/CollectorHealthReportEnvelope")
	case "createCommercialCollector":
		operation.Description = "Creates tenant-scoped commercial collector metadata through focused PostgreSQL commands under a current tenant-wide collector:admin grant for human sessions. Identity is tenant/provider/name/version; duplicate creation conflicts, while same-key replay returns original metadata after current authorization. Metadata, audit and replay state commit atomically. No external code is installed and no provider trust is granted."
		operation.RequestBody = jsonRequest("Commercial collector definition request.", "#/components/schemas/CreateCommercialCollectorRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created commercial collector definition envelope.", "#/components/schemas/CommercialCollectorDefinitionEnvelope")
	case "listCommercialCollectors":
		operation.Description = "Lists tenant-scoped commercial collector definitions under collector:read; human sessions require a current tenant-level grant. PostgreSQL results are keyset-paginated."
		operation.Responses[http.StatusOK] = jsonResponse("Commercial collector definition list envelope.", "#/components/schemas/CommercialCollectorDefinitionListEnvelope")
	case "createMarketplaceCollector":
		operation.Description = "Creates tenant-scoped marketplace collector package metadata and evidence references."
		operation.RequestBody = jsonRequest("Marketplace collector creation request.", "#/components/schemas/CreateMarketplaceCollectorRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created marketplace collector envelope.", "#/components/schemas/MarketplaceCollectorEnvelope")
	case "listMarketplaceCollectors":
		operation.Description = "Keyset-pages tenant-scoped marketplace collector metadata. Human sessions need a current tenant-level collector:read grant; PostgreSQL applies the tenant limit in SQL."
		operation.Responses[http.StatusOK] = jsonResponse("Marketplace collector list envelope.", "#/components/schemas/MarketplaceCollectorListEnvelope")
	case "marketplaceCollectorHealth":
		operation.Description = "Returns marketplace collector package health from current tenant-owned signature, SBOM, and scan references. Presence does not prove package safety, marketplace trust, or provider endorsement."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Marketplace collector id."))
		operation.Responses[http.StatusOK] = jsonResponse("Marketplace collector health report envelope.", "#/components/schemas/MarketplaceCollectorHealthReportEnvelope")
	case "listControlFrameworkTemplatePacks":
		operation.Description = "Lists built-in control framework template packs available for explicit tenant installation."
		operation.Responses[http.StatusOK] = jsonResponse("Control framework template pack list envelope.", "#/components/schemas/ControlFrameworkTemplatePackListEnvelope")
	case "installControlFrameworkTemplatePack":
		operation.Description = "Installs a named starter pack as ordinary framework/control records. PostgreSQL uses a focused transaction with current tenant-level controls:admin grants for human sessions, a tenant-scoped version existence check, all starter controls, and one audit attributed to the authenticated principal. Same-key replay returns the original framework; changed request bytes or a different-key duplicate tenant/slug/version return 409. No cached Ledger inventory is used. The trimmed slug is NUL-free UTF-8 and bounded at 1024 bytes before durable replay reservation; invalid slugs return 400 and unknown slugs 404. An optional body must be an empty JSON object; blank/absent bodies retain their existing acceptance. Malformed, non-object, null, or unknown-field bodies return 400. Local-memory mode retains its explicit compatibility installation command. Starter content organizes technical evidence, not framework compliance or control efficacy."
		operation.Parameters = append(operation.Parameters, pathParam("slug", "Control framework template pack slug; trimmed, NUL-free UTF-8, at most 1024 bytes."))
		operation.RequestBody = jsonRequest("Optional empty JSON object; an absent or blank body uses an empty object.", "#/components/schemas/EmptyObject")
		operation.RequestBody.Required = false
		operation.Responses[http.StatusCreated] = jsonResponse("Installed control framework envelope.", "#/components/schemas/ControlFrameworkEnvelope")
	case "registerContainerImage":
		operation.Description = "Registers OCI/container image metadata and digest evidence linked to an optional artifact."
		operation.RequestBody = jsonRequest("Container image registration request.", "#/components/schemas/RegisterContainerImageRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Registered container image envelope.", "#/components/schemas/ContainerImageEnvelope")
	case "uploadSecurityScan", "uploadAPISecurityScan":
		operation.Description = "Uploads SAST, DAST, secret, license, or API security scan metadata and raw JSON payload evidence without exposing raw payload bytes in responses."
		operation.Description += focusedSecurityDocumentDescription + " The generic findings/severity and SARIF version/runs/results/level parsers are reduced contracts, not complete SARIF support. Omitted format defaults to generic. Projections are bounded at 100,000 findings, 1 MiB per label, and 8 MiB combined summary labels; overflow fails validation. Secret-scan redacted/quarantined flags record policy metadata and do not prove that stored raw bytes are scrubbed or safe to distribute. Scanner findings are not authoritative."
		operation.RequestBody = jsonRequest("Security scan upload request.", "#/components/schemas/UploadSecurityScanRequest")
		if operation.OperationID == "uploadAPISecurityScan" {
			operation.RequestBody = jsonRequest("API security scan upload request; category is fixed to api_security and must not be supplied.", "#/components/schemas/UploadAPISecurityScanRequest")
		}
		operation.Responses[http.StatusCreated] = jsonResponse("Created security scan envelope.", "#/components/schemas/SecurityScanEnvelope")
	case "uploadManualSecurityDocument":
		operation.Description = "Uploads sensitive manual security evidence such as threat model, security review, or penetration-test report metadata and raw payload reference."
		operation.Description += focusedSecurityDocumentDescription + " Payload is an opaque non-null JSON value whose exact encoded bytes are retained, not executed. Omitted media_type defaults to application/octet-stream. Manual evidence has lower default trust and requires human review; acceptance does not establish legal sufficiency."
		operation.RequestBody = jsonRequest("Manual security document upload request.", "#/components/schemas/UploadManualSecurityDocumentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created manual security document envelope.", "#/components/schemas/ManualSecurityDocumentEnvelope")
	case "uploadSPDXSBOM":
		operation.Description = "Uploads an SPDX 2.2 or 2.3 JSON SBOM payload, stores immutable raw bytes as evidence, and records deterministic normalization metadata. Use application/spdx+json with explicit metadata headers for streaming uploads up to 20 MiB; the JSON envelope remains limited to small requests."
		operation.Description += focusedSBOMIngestionDescription
		operation.RequestBody = streamingDocumentRequest("SPDX SBOM upload request.", "#/components/schemas/UploadSPDXSBOMRequest", "application/spdx+json", app.EvidenceDocumentLimit)
		operation.Parameters = append(operation.Parameters, optionalHeaderParam("X-Evydence-Release-ID", "Required for a native SPDX document upload."), optionalHeaderParam("X-Evydence-Artifact-ID", "Optional artifact id for a native SPDX document upload."))
		setRequestBodyLimit(&operation, app.EvidenceDocumentLimit)
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "createSBOMDiff":
		operation.Description = "Creates a deterministic SBOM diff between two tenant-scoped SBOM records."
		operation.RequestBody = jsonRequest("SBOM diff creation request.", "#/components/schemas/CreateSBOMDiffRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM diff envelope.", "#/components/schemas/SBOMDiffEnvelope")
	case "vulnerabilityPostureReport":
		operation.Description = "Returns aggregate severity counts and open-critical counts from stored vulnerability-scan findings only; decisions, VEX, exceptions, and workflow records are not included. Without release_id, human sessions require a tenant-wide security:read grant; a release filter permits a matching tenant, product, or release grant. Raw findings are not returned, and scanner coverage is not independently verified."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Optional single release id; blank or duplicate values are rejected.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Vulnerability posture report envelope.", "#/components/schemas/VulnerabilityPostureReportEnvelope")
	case "vulnerabilityDecisionSummaryReport":
		operation.Description = "Returns customer-safe active vulnerability decision summaries for one tenant-owned release with assumptions and limitations. Raw payloads and internal notes are excluded."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Single release id; missing, blank, duplicate, or unknown query parameters are rejected.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Vulnerability decision summary report envelope.", "#/components/schemas/VulnerabilityDecisionSummaryReportEnvelope")
	case "generateAnomalyReport":
		operation.Description = "Creates a deterministic anomaly report over existing tenant evidence and metrics with assumptions and limitations."
		operation.RequestBody = jsonRequest("Anomaly report creation request.", "#/components/schemas/CreateAnomalyReportRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created anomaly report envelope.", "#/components/schemas/AnomalyReportEnvelope")
	case "createMerkleBatch":
		operation.Description = "Creates a Merkle batch over tenant audit-chain entries for checkpoint export or transparency anchoring."
		operation.RequestBody = jsonRequest("Merkle batch creation request.", "#/components/schemas/CreateMerkleBatchRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created Merkle batch envelope.", "#/components/schemas/MerkleBatchEnvelope")
	case "verifyMerkleBatch":
		operation.Description = "Verifies a tenant-scoped Merkle batch root and leaf set against stored audit-chain entries."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Merkle batch id."))
		operation.Responses[http.StatusOK] = jsonResponse("Merkle batch verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "createTransparencyCheckpoint":
		operation.Description = "Records an external transparency or timestamp checkpoint reference for a Merkle batch."
		operation.RequestBody = jsonRequest("Transparency checkpoint creation request.", "#/components/schemas/CreateTransparencyCheckpointRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created transparency checkpoint envelope.", "#/components/schemas/TransparencyCheckpointEnvelope")
	case "createPublicTransparencyLog":
		operation.Description = "Creates tenant metadata for an optional public transparency log trust root."
		operation.RequestBody = jsonRequest("Public transparency log creation request.", "#/components/schemas/CreatePublicTransparencyLogRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created public transparency log envelope.", "#/components/schemas/PublicTransparencyLogEnvelope")
	case "publishPublicTransparencyLogEntry":
		operation.Description = "Records publication metadata for a checkpoint submitted to a configured public transparency log."
		operation.RequestBody = jsonRequest("Public transparency log entry publication request.", "#/components/schemas/PublishPublicTransparencyLogEntryRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created public transparency log entry envelope.", "#/components/schemas/PublicTransparencyLogEntryEnvelope")
	case "verifyPublicTransparencyLogEntry":
		operation.Description = "Verifies operator-supplied RFC6962-style public transparency inclusion proof material for a published entry."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Public transparency log entry id."))
		operation.RequestBody = jsonRequest("Public transparency log inclusion proof verification request.", "#/components/schemas/VerifyPublicTransparencyLogEntryRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Verified public transparency log entry envelope.", "#/components/schemas/PublicTransparencyLogEntryEnvelope")
	case "fetchPublicTransparencyLogEntryProof":
		operation.Description = "Fetches public transparency inclusion proof material from the configured log endpoint or transparency proof gateway and verifies it locally. Endpoint trust and provider semantics remain deployment responsibilities."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Public transparency log entry id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Fetched and verified public transparency log entry envelope.", "#/components/schemas/PublicTransparencyLogEntryEnvelope")
	case "createObjectRetentionPolicy":
		operation.Description = "Creates a tenant-scoped retention-intent record and its maximum provider-observation age. Creation does not prove provider-enforced retention."
		operation.RequestBody = jsonRequest("Object retention policy creation request.", "#/components/schemas/CreateObjectRetentionPolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created object retention policy envelope.", "#/components/schemas/ObjectRetentionPolicyEnvelope")
	case "verifyObjectRetentionPolicy":
		operation.Description = "Records a provider-backed retention observation when available. Without complete provider, bucket, mode, duration, legal-hold, and observation-time evidence, the policy remains not_verified; expired successful observations are reported as stale."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Object retention policy id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Verified object retention policy envelope.", "#/components/schemas/ObjectRetentionPolicyEnvelope")
	case "signingCustodyReviewReport":
		operation.Description = "Returns tenant signing-provider and object-lock verification metadata for deployment custody review. It is evidence metadata only, not legal compliance proof, certification, HSM custody proof, or a secure-deployment guarantee."
		operation.Responses[http.StatusOK] = jsonResponse("Signing custody review report envelope.", "#/components/schemas/SigningCustodyReviewReportEnvelope")
	case "createLegalHold":
		operation.Description = "Creates an append-only legal-hold marker for a tenant-scoped retention subject."
		operation.RequestBody = jsonRequest("Legal hold creation request.", "#/components/schemas/CreateLegalHoldRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created legal hold envelope.", "#/components/schemas/LegalHoldEnvelope")
	case "createRetentionOverride":
		operation.Description = "Creates an append-only retention override for a tenant-scoped retention subject."
		operation.RequestBody = jsonRequest("Retention override creation request.", "#/components/schemas/CreateRetentionOverrideRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created retention override envelope.", "#/components/schemas/RetentionOverrideEnvelope")
	case "retentionReport":
		operation.Description = "Returns a retention report for tenant-scoped holds and overrides with storage verification limitations."
		operation.Parameters = append(operation.Parameters,
			queryParam("scope_type", "Optional retention scope type.", "string"),
			queryParam("scope_id", "Optional retention scope id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Retention report envelope.", "#/components/schemas/RetentionReportEnvelope")
	case "createSaaSEditionProfile":
		operation.Description = "Creates a SaaS edition profile record for future hosted deployment planning; it is not a production readiness claim."
		operation.RequestBody = jsonRequest("SaaS edition profile creation request.", "#/components/schemas/CreateSaaSEditionProfileRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SaaS edition profile envelope.", "#/components/schemas/SaaSEditionProfileEnvelope")
	case "craReadinessReport":
		operation.Description = "Returns a CRA-oriented readiness report without legal compliance or certification conclusions."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Product id.", "string"),
			queryParam("release_id", "Release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("CRA readiness report envelope.", "#/components/schemas/ReadinessReportEnvelope")
	case "craVulnerabilityHandlingReport":
		operation.Description = "Returns a CRA-oriented vulnerability handling evidence report without legal compliance, certification, scanner-authority, or release-security conclusions."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Product id.", "string"),
			queryParam("release_id", "Release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("CRA vulnerability handling report envelope.", "#/components/schemas/CRAVulnerabilityHandlingReportEnvelope")
	case "securityUpdateEvidenceReport":
		operation.Description = "Returns a security update evidence report for release-scoped fixed decisions, incidents, remediation tasks, and linked evidence without legal or security conclusions."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Product id.", "string"),
			queryParam("release_id", "Release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Security update evidence report envelope.", "#/components/schemas/SecurityUpdateEvidenceReportEnvelope")
	case "controlCoverageReport":
		operation.Description = "Returns deterministic control coverage with linked evidence, missing evidence, assumptions, and limitations."
		operation.Parameters = append(operation.Parameters,
			queryParam("framework_id", "Control framework id.", "string"),
			queryParam("product_id", "Product id.", "string"),
			queryParam("release_id", "Release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Control coverage report envelope.", "#/components/schemas/ReadinessReportEnvelope")
	case "createRedactionProfile":
		operation.Description = "Creates an explicit redaction profile for customer and report package generation."
		operation.RequestBody = jsonRequest("Redaction profile creation request.", "#/components/schemas/CreateRedactionProfileRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created redaction profile envelope.", "#/components/schemas/RedactionProfileEnvelope")
	case "createCustomerPackage":
		operation.Description = "Creates a scoped customer security package manifest using an explicit redaction profile."
		operation.RequestBody = jsonRequest("Customer package creation request.", "#/components/schemas/CreateCustomerPackageRequest")
		addJSONRequestExamples(operation.RequestBody, map[string]any{
			"release-evidence-package": specs.Example{
				Summary: "Create a scoped release evidence package",
				Value:   customerPackageRequestExample(),
			},
		})
		operation.Responses[http.StatusCreated] = jsonResponse("Created customer security package envelope.", "#/components/schemas/CustomerSecurityPackageEnvelope")
	case "getCustomerPackage":
		operation.Description = "Returns a tenant-scoped customer security package manifest by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Customer package id."))
		operation.Responses[http.StatusOK] = jsonResponse("Customer security package envelope.", "#/components/schemas/CustomerSecurityPackageEnvelope")
	case "createCustomerPortalAccess":
		operation.Description = "Creates a named, expiring external reviewer access record for a customer package and returns the portal token once."
		operation.RequestBody = jsonRequest("Customer portal access creation request.", "#/components/schemas/CreateCustomerPortalAccessRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created portal access and one-time token envelope.", "#/components/schemas/CustomerPortalAccessCreateEnvelope")
	case "listCustomerPortalAccess":
		operation.Description = "Lists tenant-scoped external reviewer access records visible under the caller's current package, product, release, or tenant-level package:read grant. Token hashes and secrets are never returned."
		operation.Parameters = append(operation.Parameters, queryParam("package_id", "Optional customer package id filter.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Customer portal access list envelope.", "#/components/schemas/CustomerPortalAccessListEnvelope")
	case "revokeCustomerPortalAccess":
		operation.Description = "Revokes a tenant-scoped external reviewer access record; revocation is append-only and the original token cannot be used afterwards."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Customer portal access id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked customer portal access envelope.", "#/components/schemas/CustomerPortalAccessEnvelope")
	case "downloadCustomerPackage":
		operation.Description = "Downloads a scoped customer security package ZIP. The archive contains redacted manifest metadata and verification guidance, not raw tenant evidence payload bytes."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Customer package id."))
		operation.Responses[http.StatusOK] = binaryResponse("Customer security package ZIP archive.")
	case "accessCustomerPortalPackage":
		operation.Description = "Public token exchange endpoint for a scoped customer package. It intentionally uses no bearer authentication and accepts only the issued portal token in the JSON body."
		operation.RequestBody = jsonRequest("Customer portal token request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Scoped customer package envelope.", "#/components/schemas/CustomerSecurityPackageEnvelope")
	case "downloadCustomerPortalPackage":
		operation.Description = "Public token exchange endpoint for downloading a scoped customer package ZIP. It intentionally uses no bearer authentication and accepts only the issued portal token in the JSON body."
		operation.RequestBody = jsonRequest("Customer portal token request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = binaryResponse("Customer security package ZIP archive.")
	case "customerPortalPackageViewForm":
		operation.Description = "Public HTML form for reviewing or downloading a scoped customer package with a portal token. It does not accept tokens in URLs and does not use bearer authentication."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = htmlResponse("Customer portal package review form.")
	case "customerPortalPackageView":
		operation.Description = "Public HTML package review endpoint backed by the customer portal token exchange. Tokens are accepted only as form body fields."
		operation.RequestBody = formRequest("Customer portal token form request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = htmlResponse("Scoped customer package review HTML.")
	case "downloadCustomerPortalPackageView":
		operation.Description = "Public HTML-form package ZIP download endpoint backed by the customer portal token exchange. Tokens are accepted only as form body fields."
		operation.RequestBody = formRequest("Customer portal token form request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = binaryResponse("Customer security package ZIP archive.")
	case "securityReviewPackageReport":
		operation.Description = "Returns a redaction-aware security-review package report with assumptions and limitations."
		operation.Parameters = append(operation.Parameters, queryParam("package_id", "Customer package id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Security review package report envelope.", "#/components/schemas/SecurityReviewPackageReportEnvelope")
	case "craReadinessHTMLPackage":
		operation.Description = "Creates a deterministic CRA-readiness HTML package without legal compliance or certification conclusions."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Product id.", "string"),
			queryParam("release_id", "Release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("CRA readiness HTML package envelope.", "#/components/schemas/HTMLReportPackageEnvelope")
	case "createReportTemplate":
		operation.Description = "Creates a tenant-defined deterministic report template with an explicit allowed-field list."
		operation.RequestBody = jsonRequest("Report template creation request.", "#/components/schemas/CreateReportTemplateRequest")
		setRequestBodyLimit(&operation, app.ReportTemplateRequestLimit)
		operation.Responses[http.StatusCreated] = jsonResponse("Created report template envelope.", "#/components/schemas/CustomReportTemplateEnvelope")
	case "renderReportTemplate":
		operation.Description = "Renders a tenant report template for a scoped subject using allowed fields only."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Report template id."))
		operation.RequestBody = jsonRequest("Report template render request.", "#/components/schemas/RenderReportTemplateRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Rendered report envelope.", "#/components/schemas/RenderedCustomReportEnvelope")
	case "exportEvidenceBundle":
		operation.Description = "Exports a portable evidence bundle manifest with hashes, signatures, and verification text."
		operation.RequestBody = jsonRequest("Evidence bundle export request.", "#/components/schemas/ExportEvidenceBundleRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence bundle envelope.", "#/components/schemas/EvidenceBundleEnvelope")
	case "importEvidenceBundle":
		operation.Description = "Imports a portable evidence bundle manifest and records deterministic import metadata."
		operation.RequestBody = jsonRequest("Evidence bundle import request.", "#/components/schemas/EvidenceBundle")
		operation.Responses[http.StatusCreated] = jsonResponse("Evidence bundle import result envelope.", "#/components/schemas/EvidenceBundleImportEnvelope")
	case "createEvidenceSummary":
		operation.Description = "Creates an evidence-backed summary with citations, assumptions, and limitations."
		operation.RequestBody = jsonRequest("Evidence summary creation request.", "#/components/schemas/CreateEvidenceSummaryRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence summary envelope.", "#/components/schemas/EvidenceSummaryEnvelope")
	case "createQuestionnaireTemplate":
		operation.Description = "Creates a tenant questionnaire template with explicit evidence/control mapping fields."
		operation.RequestBody = jsonRequest("Questionnaire template creation request.", "#/components/schemas/CreateQuestionnaireTemplateRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created questionnaire template envelope.", "#/components/schemas/QuestionnaireTemplateEnvelope")
	case "createQuestionnairePackage":
		operation.Description = "Creates a questionnaire response package from a template and scoped evidence package."
		operation.RequestBody = jsonRequest("Questionnaire package creation request.", "#/components/schemas/CreateQuestionnairePackageRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created questionnaire package envelope.", "#/components/schemas/QuestionnairePackageEnvelope")
	case "createQuestionnaireDraft":
		operation.Description = "Creates an evidence-backed questionnaire draft with limitations."
		operation.RequestBody = jsonRequest("Questionnaire draft creation request.", "#/components/schemas/CreateQuestionnaireDraftRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created questionnaire draft envelope.", "#/components/schemas/QuestionnaireDraftEnvelope")
	case "createQuestionnaireAnswerLibraryEntry":
		operation.Description = "Creates a reusable questionnaire answer draft linked to optional evidence, product, release, or control scope. A human session needs a matching product or release grant; a draft without product or release scope requires a tenant grant."
		operation.RequestBody = jsonRequest("Questionnaire answer library entry creation request.", "#/components/schemas/CreateQuestionnaireAnswerLibraryEntryRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created questionnaire answer library entry envelope.", "#/components/schemas/QuestionnaireAnswerLibraryEntryEnvelope")
	case "listQuestionnaireAnswerLibrary":
		operation.Description = "Lists questionnaire answer drafts with optional question, product, and release filters. Product and release filters must reference current tenant-owned parents and agree when combined. Human sessions see only entries covered by their current resource grants; tenant-wide drafts require a tenant grant."
		operation.Parameters = append(operation.Parameters,
			queryParam("question_id", "Filter by questionnaire question id.", "string"),
			queryParam("product_id", "Filter by product id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Questionnaire answer library entry list envelope.", "#/components/schemas/QuestionnaireAnswerLibraryEntryListEnvelope")
	case "createPDFReportPackage":
		operation.Description = "Creates a deterministic PDF report package record and payload metadata."
		operation.RequestBody = jsonRequest("PDF report package creation request.", "#/components/schemas/CreatePDFReportPackageRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created PDF report package envelope.", "#/components/schemas/PDFReportPackageEnvelope")
	}
	if isPaginatedOperation(operation.OperationID) {
		operation.Description += " Results use bounded keyset pagination. Cursor tokens are opaque and bound to the tenant, filters, sort, and direction."
		operation.Parameters = appendPaginationParameters(operation.OperationID, operation.Parameters)
	}
	if isConditionalReadOperation(operation.OperationID) {
		operation.Parameters = appendParameterIfMissing(operation.Parameters, optionalHeaderParam("If-None-Match", "Optional ETag from a prior private resource read. A match returns 304 without a response body."))
		if operation.Extensions == nil {
			operation.Extensions = map[string]any{}
		}
		operation.Extensions["x-evydence-conditional-read"] = map[string]any{
			"cache_control": "private, max-age=0, must-revalidate",
			"vary":          "Authorization",
			"not_modified":  http.StatusNotModified,
		}
	}
	return operation
}

func isPaginatedOperation(operationID string) bool {
	switch operationID {
	case "listAPIKeys", "listCollectors", "listControlFrameworks", "listControlEvidence", "listProducts", "listEvidence", "searchEvidence", "listSBOMComponents", "listAuditLog", "listVulnerabilityDecisions", "listExceptions", "listSigningKeys", "listReleaseCandidates", "listEvidenceLifecycleEvents", "listSourceRepositories", "listDeploymentEnvironments", "listDeployments", "listCommercialCollectors", "listMarketplaceCollectors", "listControlFrameworkTemplatePacks", "listCustomerPortalAccess", "listQuestionnaireAnswerLibrary", "listRoleBindings":
		return true
	default:
		return false
	}
}

func isConditionalReadOperation(operationID string) bool {
	switch operationID {
	case "getSecurityControl", "getProduct", "getProject", "getRelease", "getReleaseCandidate", "getArtifact", "getArtifactSignature", "getBuildRun", "getDeployment", "getCustomerPackage", "getEvidence", "getSBOM", "getVEX", "getVEXImportReport", "getVulnerabilityScan", "getOpenAPIContract", "getReleaseBundle", "getReleaseBundleManifest":
		return true
	default:
		return false
	}
}

func appendPaginationParameters(operationID string, parameters []specs.Parameter) []specs.Parameter {
	sortValues := []string{string(appquery.SortCreatedAt), string(appquery.SortID)}
	defaultSort := string(appquery.SortCreatedAt)
	defaultDirection := string(appquery.Ascending)
	if operationID == "listControlFrameworkTemplatePacks" || operationID == "listSBOMComponents" {
		sortValues = []string{string(appquery.SortID)}
		defaultSort = string(appquery.SortID)
	}
	if operationID == "searchEvidence" || operationID == "listAuditLog" {
		defaultDirection = string(appquery.Descending)
	}
	parameters = appendParameterIfMissing(parameters, specs.Parameter{
		Name:        "page_size",
		In:          "query",
		Description: "Maximum records in this page. Defaults to 50 and is capped at 500.",
		Schema:      map[string]any{"type": "integer", "minimum": 1, "maximum": appquery.MaxPageSize, "default": appquery.DefaultPageSize},
	})
	parameters = appendParameterIfMissing(parameters, specs.Parameter{
		Name:        "cursor",
		In:          "query",
		Description: "Opaque continuation token returned as meta.next_cursor. It must be reused with the same tenant, filters, sort, and direction.",
		Schema:      map[string]any{"type": "string", "minLength": 1, "maxLength": 4096},
	})
	parameters = appendParameterIfMissing(parameters, specs.Parameter{
		Name:        "sort",
		In:          "query",
		Description: "Stable sort key for cursor pagination.",
		Schema:      map[string]any{"type": "string", "enum": sortValues, "default": defaultSort},
	})
	parameters = appendParameterIfMissing(parameters, specs.Parameter{
		Name:        "direction",
		In:          "query",
		Description: "Sort direction for cursor pagination.",
		Schema:      map[string]any{"type": "string", "enum": []string{string(appquery.Ascending), string(appquery.Descending)}, "default": defaultDirection},
	})
	return parameters
}

func appendParameterIfMissing(parameters []specs.Parameter, parameter specs.Parameter) []specs.Parameter {
	for _, existing := range parameters {
		if existing.In == parameter.In && existing.Name == parameter.Name {
			return parameters
		}
	}
	return append(parameters, parameter)
}

func addProblemResponses(operation *specs.Operation) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		operation.Responses[status] = problemResponse(http.StatusText(status))
	}
}

func jsonRequest(description, schemaRef string) *specs.RequestBody {
	return &specs.RequestBody{
		Description:  description,
		Required:     true,
		ContentTypes: []string{"application/json"},
		Content: map[string]specs.MediaType{
			"application/json": {SchemaRef: schemaRef},
		},
	}
}

func streamingDocumentRequest(description, envelopeSchemaRef, mediaType string, limit int64) *specs.RequestBody {
	body := jsonRequest(description, envelopeSchemaRef)
	body.ContentTypes = append(body.ContentTypes, mediaType)
	body.Content[mediaType] = specs.MediaType{Schema: map[string]any{"type": "string", "format": "binary", "maxLength": limit}}
	return body
}

func setRequestBodyLimit(operation *specs.Operation, limit int64) {
	if operation.Extensions == nil {
		operation.Extensions = map[string]any{}
	}
	operation.Extensions["x-evydence-request-body-limit-bytes"] = limit
}

func optionalHeaderParam(name, description string) specs.Parameter {
	return specs.Parameter{Name: name, In: "header", Description: description, Required: false, Schema: map[string]any{"type": "string", "minLength": 1}}
}

func formRequest(description, schemaRef string) *specs.RequestBody {
	return &specs.RequestBody{
		Description:  description,
		Required:     true,
		ContentTypes: []string{"application/x-www-form-urlencoded"},
		Content: map[string]specs.MediaType{
			"application/x-www-form-urlencoded": {SchemaRef: schemaRef},
		},
	}
}

func addJSONRequestExamples(body *specs.RequestBody, examples map[string]any) {
	if body == nil || len(examples) == 0 {
		return
	}
	media := body.Content["application/json"]
	media.Examples = examples
	body.Content["application/json"] = media
}

func addJSONResponseExamples(operation *specs.Operation, status int, examples map[string]any) {
	if operation == nil || len(examples) == 0 {
		return
	}
	response := operation.Responses[status]
	media := response.Content["application/json"]
	media.Examples = examples
	response.Content["application/json"] = media
	operation.Responses[status] = response
}

const focusedSBOMIngestionDescription = " In PostgreSQL mode, a focused command validates current tenant-owned release parents and human release/artifact grants before parsing or staging. IDs are NUL-free UTF-8 bounded at 1024 bytes. Wrapped JSON remains capped at 64 KiB and rejects null, duplicate, and unknown fields; native uploads require one nonblank release header and allow one optional artifact header. Declared source size and SHA-256 are verified. Evidence, SBOM, audit, payload metadata, outbox jobs, and idempotency completion commit together. Replay checks current grants without parsing; retained body-only native receipts require matching tenant, release, optional artifact, and format and never execute a new upload. With worker-owned parsing and object storage, the response contains parsed components while the stored projection stays accepted until its parser job runs. Acceptance does not prove SBOM completeness or release security."

func cyclonedxSBOMUploadExample() map[string]any {
	return map[string]any{
		"release_id":  "rel_20260527120000",
		"artifact_id": "art_20260527120000",
		"payload": map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.6",
			"components": []map[string]any{
				{"name": "payments-api", "version": "1.0.0-rc.1", "purl": "pkg:oci/payments-api@sha256-ca978112"},
				{"name": "openssl", "version": "3.1.0-r0", "purl": "pkg:apk/openssl@3.1.0-r0"},
			},
		},
	}
}

func openVEXUploadExample() map[string]any {
	return map[string]any{
		"release_id":  "rel_20260527120000",
		"artifact_id": "art_20260527120000",
		"payload": map[string]any{
			"@context":  "https://openvex.dev/ns/v0.2.0",
			"@id":       "https://example.test/vex/payments-api/1.0.0",
			"author":    "security@example.test",
			"timestamp": "2026-05-27T12:00:00Z",
			"version":   1,
			"statements": []map[string]any{
				{
					"vulnerability":    map[string]any{"name": "CVE-2026-0002"},
					"products":         []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}},
					"status":           "fixed",
					"justification":    "fixed_in_release_candidate",
					"impact_statement": "Patched before this release candidate.",
					"action_statement": "Ship the fixed artifact after operator review.",
				},
			},
		},
	}
}

func vulnerabilityScanUploadExample() map[string]any {
	return map[string]any{
		"scanner":    "generic-json",
		"target_ref": "pkg:oci/payments-api@sha256-ca978112",
		"release_id": "rel_20260527120000",
		"findings": []map[string]any{
			{
				"vulnerability": "CVE-2026-0099",
				"component":     "pkg:apk/openssl@3.1.0-r0",
				"severity":      "critical",
				"state":         "open",
			},
		},
	}
}

func vulnerabilityDecisionExample() map[string]any {
	return map[string]any{
		"status":           "not_affected",
		"justification":    "The vulnerable code path is not reachable in this release.",
		"impact_statement": "The shipped artifact does not include the affected runtime path.",
		"customer_visible": true,
		"evidence_ids":     []string{"ev_20260527120000"},
		"supporting_refs":  []map[string]string{{"type": "exception", "id": "exc_20260527120000"}},
	}
}

func releaseReadinessReportExample() map[string]any {
	return map[string]any{
		"data": map[string]any{
			"report_type":      "release_readiness",
			"template_version": "release-readiness.v1.0.0",
			"product_id":       "prod_20260527120000",
			"release_id":       "rel_20260527120000",
			"result":           "failed",
			"policy_set":       "policy-set.v1.0.0",
			"summary": map[string]any{
				"headline":      "Release evidence has one blocking vulnerability decision gap.",
				"result":        "failed",
				"human_summary": "Required artifact, SBOM, scan, build, and bundle evidence is present, but one critical finding still needs a valid decision or approved exception.",
				"policy_set":    "policy-set.v1.0.0",
			},
			"blocking_findings": []map[string]any{
				{
					"finding_id":     "scan_20260527120000:finding:1",
					"scan_id":        "scan_20260527120000",
					"release_id":     "rel_20260527120000",
					"vulnerability":  "CVE-2026-0099",
					"component":      "pkg:apk/openssl@3.1.0-r0",
					"severity":       "critical",
					"state":          "open",
					"decision_state": "missing",
				},
			},
			"missing_evidence":    []string{"vulnerability_decision"},
			"accepted_exceptions": []map[string]any{},
			"assumptions": []string{
				"Readiness is based on tenant evidence recorded in Evydence.",
			},
			"limitations": []string{
				"Readiness supports technical review and does not prove legal compliance, certification, complete vulnerability coverage, or release security.",
			},
			"schema_version": "release-readiness.v1.0.0",
			"generated_at":   "2026-05-27T12:00:00Z",
		},
		"meta": map[string]any{"api_version": "v1"},
	}
}

func customerPackageRequestExample() map[string]any {
	return map[string]any{
		"product_id":           "prod_20260527120000",
		"release_id":           "rel_20260527120000",
		"redaction_profile_id": "rp_20260527120000",
		"title":                "Payments API 1.0.0 release evidence package",
		"expires_at":           "2026-06-30T00:00:00Z",
	}
}

func jsonResponse(description, schemaRef string) specs.Response {
	return specs.Response{
		Description:  description,
		ContentTypes: []string{"application/json"},
		Content: map[string]specs.MediaType{
			"application/json": {SchemaRef: schemaRef},
		},
	}
}

func problemResponse(description string) specs.Response {
	return specs.Response{
		Description:  description,
		ContentTypes: []string{"application/problem+json"},
		Content: map[string]specs.MediaType{
			"application/problem+json": {SchemaRef: "#/components/schemas/Problem"},
		},
	}
}

func binaryResponse(description string) specs.Response {
	return specs.Response{
		Description:  description,
		ContentTypes: []string{"application/zip"},
		Content: map[string]specs.MediaType{
			"application/zip": {Schema: map[string]any{"type": "string", "format": "binary"}},
		},
	}
}

func htmlResponse(description string) specs.Response {
	return specs.Response{
		Description:  description,
		ContentTypes: []string{"text/html"},
		Content: map[string]specs.MediaType{
			"text/html": {Schema: map[string]any{"type": "string"}},
		},
	}
}

func queryParam(name, description, typ string) specs.Parameter {
	schema := map[string]any{"type": typ}
	if name == "limit" {
		schema["minimum"] = 1
		schema["maximum"] = 100
	}
	return specs.Parameter{Name: name, In: "query", Description: description, Schema: schema}
}

func pathParam(name, description string) specs.Parameter {
	return specs.Parameter{Name: name, In: "path", Description: description, Required: true, Schema: map[string]any{"type": "string"}}
}

func headerParam(name, description string) specs.Parameter {
	return specs.Parameter{Name: name, In: "header", Description: description, Required: true, Schema: map[string]any{"type": "string"}}
}

func revisionIfMatchParam() specs.Parameter {
	return specs.Parameter{
		Name:        "If-Match",
		In:          "header",
		Required:    true,
		Description: `Current resource revision as a strong decimal ETag, for example "1". Stale revisions return VERSION_CONFLICT with current_revision.`,
		Schema:      map[string]any{"type": "string", "pattern": `^"[1-9][0-9]*"$`},
	}
}

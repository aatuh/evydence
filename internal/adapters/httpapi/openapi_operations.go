package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/specs"
)

func withCriticalOperationDetails(operation specs.Operation) specs.Operation {
	addProblemResponses(&operation)
	switch operation.OperationID {
	case "health":
		operation.Description = "Returns low-detail liveness status without touching tenant evidence or secret material."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Liveness status envelope.", "#/components/schemas/HealthStatusEnvelope")
	case "ready":
		operation.Description = "Returns low-detail process readiness without tenant evidence or secret material."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Readiness status envelope.", "#/components/schemas/ReadinessStatusEnvelope")
	case "version":
		operation.Description = "Returns the API process version string."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Version information envelope.", "#/components/schemas/VersionInfoEnvelope")
	case "metrics":
		operation.Description = "Returns safe tenant-scoped resource metrics for admin actors. A Prometheus text response is also available when requested with Accept: text/plain."
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
		operation.Description = "Returns instance-level diagnostic counts. Requires the explicit instance:admin scope; tenant admin and ordinary wildcard tenant keys are insufficient."
		operation.Responses[http.StatusOK] = jsonResponse("Instance admin snapshot envelope.", "#/components/schemas/InstanceAdminSnapshotEnvelope")
	case "createOrganization":
		operation.Description = "Creates a tenant-scoped organization record for human identity grouping."
		operation.RequestBody = jsonRequest("Organization creation request.", "#/components/schemas/CreateOrganizationRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created organization envelope.", "#/components/schemas/OrganizationEnvelope")
	case "createUser":
		operation.Description = "Creates a tenant-scoped human user metadata record. Authentication is still controlled by API keys or configured SSO/session flows."
		operation.RequestBody = jsonRequest("Human user creation request.", "#/components/schemas/CreateUserRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created human user envelope.", "#/components/schemas/HumanUserEnvelope")
	case "deactivateUser":
		operation.Description = "Deactivates a tenant-scoped human user as an audited lifecycle transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Human user id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Deactivated human user envelope.", "#/components/schemas/HumanUserEnvelope")
	case "createRoleBinding":
		operation.Description = "Creates a tenant-scoped role binding for a user or collector subject."
		operation.RequestBody = jsonRequest("Role binding creation request.", "#/components/schemas/CreateRoleBindingRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created role binding envelope.", "#/components/schemas/RoleBindingEnvelope")
	case "listRoleBindings":
		operation.Description = "Lists tenant-scoped role bindings visible to the identity administrator."
		operation.Responses[http.StatusOK] = jsonResponse("Role binding list envelope.", "#/components/schemas/RoleBindingListEnvelope")
	case "createSSOSession":
		operation.Description = "Creates an admin-managed human SSO session record and returns a one-time bearer secret."
		operation.RequestBody = jsonRequest("SSO session creation request.", "#/components/schemas/CreateSSOSessionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO session and one-time secret envelope.", "#/components/schemas/SSOSessionCreateEnvelope")
	case "revokeSSOSession":
		operation.Description = "Revokes a tenant-scoped SSO session as an audited lifecycle transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SSO session id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked SSO session envelope.", "#/components/schemas/SSOSessionEnvelope")
	case "createSSOProvider":
		operation.Description = "Records tenant SSO provider metadata. Optional static JWKS public keys and SAML signing certificates can be supplied for local token/assertion verification without live provider calls."
		operation.RequestBody = jsonRequest("SSO provider creation request.", "#/components/schemas/CreateSSOProviderRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO provider envelope.", "#/components/schemas/SSOProviderEnvelope")
	case "verifyProviderIdentity":
		operation.Description = "Verifies stored provider identity metadata and, when supplied, locally verifies OIDC ID-token or SAML assertion issuer, audience, subject, time bounds, and signature against configured tenant trust material."
		operation.RequestBody = jsonRequest("Provider identity verification request.", "#/components/schemas/VerifyProviderIdentityRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Provider verification envelope.", "#/components/schemas/ProviderVerificationEnvelope")
	case "linkSSOIdentity":
		operation.Description = "Links a verified provider subject to a tenant-scoped human user."
		operation.RequestBody = jsonRequest("SSO identity link request.", "#/components/schemas/LinkSSOIdentityRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO identity link envelope.", "#/components/schemas/UserIdentityLinkEnvelope")
	case "createAPIKey":
		operation.Description = "Creates a tenant-scoped API key and returns the secret exactly once. Stored records expose only non-secret key metadata."
		operation.RequestBody = jsonRequest("API key creation request.", "#/components/schemas/CreateAPIKeyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created API key and one-time secret envelope.", "#/components/schemas/APIKeyCreateEnvelope")
	case "listAPIKeys":
		operation.Description = "Lists tenant-scoped API key metadata without key hashes or one-time secrets."
		operation.Responses[http.StatusOK] = jsonResponse("API key list envelope.", "#/components/schemas/APIKeyListEnvelope")
	case "createCollector":
		operation.Description = "Creates a tenant-scoped collector identity, binds a scoped API key, and returns the collector key secret exactly once."
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
		operation.Description = "Lists tenant-scoped control evidence links with optional control, product, and release filters."
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
	case "createProject":
		operation.Description = "Creates a tenant-scoped project under a product."
		operation.RequestBody = jsonRequest("Project creation request.", "#/components/schemas/CreateProjectRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created project envelope.", "#/components/schemas/ProjectEnvelope")
	case "createRelease":
		operation.Description = "Creates an append-only release record under a product and optional project."
		operation.RequestBody = jsonRequest("Release creation request.", "#/components/schemas/CreateReleaseRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "getRelease":
		operation.Description = "Returns a tenant-scoped release by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "freezeRelease":
		operation.Description = "Freezes a release as an append-only transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Frozen release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "approveRelease":
		operation.Description = "Approves a release as an append-only transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Approved release envelope.", "#/components/schemas/ReleaseEnvelope")
	case "registerArtifact":
		operation.Description = "Registers an artifact digest for release evidence and later build/attestation matching."
		operation.RequestBody = jsonRequest("Artifact registration request.", "#/components/schemas/RegisterArtifactRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Registered artifact envelope.", "#/components/schemas/ArtifactEnvelope")
	case "createBuild":
		operation.Description = "Records an immutable CI build run. Collector identity is derived from the authenticated key when present."
		operation.RequestBody = jsonRequest("Build run creation request.", "#/components/schemas/CreateBuildRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created build run envelope.", "#/components/schemas/BuildRunEnvelope")
	case "getBuild":
		operation.Description = "Returns a tenant-scoped build run by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build run id."))
		operation.Responses[http.StatusOK] = jsonResponse("Build run envelope.", "#/components/schemas/BuildRunEnvelope")
	case "uploadGitHubSourceSnapshot":
		operation.Description = "Uploads a strict GitHub source snapshot, hashes commit messages, and stores repository, commit, branch, and pull-request evidence records."
		operation.RequestBody = jsonRequest("GitHub source snapshot upload request.", "#/components/schemas/SourceSnapshotRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source snapshot resources envelope.", "#/components/schemas/SourceSnapshotEnvelope")
	case "uploadGitLabSourceSnapshot":
		operation.Description = "Uploads a strict GitLab source snapshot, hashes commit messages, and stores repository, commit, branch, and pull-request evidence records."
		operation.RequestBody = jsonRequest("GitLab source snapshot upload request.", "#/components/schemas/SourceSnapshotRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source snapshot resources envelope.", "#/components/schemas/SourceSnapshotEnvelope")
	case "uploadSBOM":
		operation.Description = "Uploads a CycloneDX SBOM payload, stores raw bytes in object storage, and records normalized SBOM metadata."
		operation.RequestBody = jsonRequest("CycloneDX SBOM upload request.", "#/components/schemas/EvidenceUploadRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "getSBOM":
		operation.Description = "Returns a tenant-scoped SBOM metadata record by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "SBOM id."))
		operation.Responses[http.StatusOK] = jsonResponse("SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "uploadVEX", "uploadCycloneDXVEX":
		operation.Description = "Uploads VEX payload bytes, stores raw evidence in object storage, and records normalized VEX metadata and decisions where applicable."
		operation.RequestBody = jsonRequest("VEX upload request.", "#/components/schemas/EvidenceUploadRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created VEX document envelope.", "#/components/schemas/VEXDocumentEnvelope")
	case "getVEX":
		operation.Description = "Returns a tenant-scoped VEX document metadata record by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "VEX document id."))
		operation.Responses[http.StatusOK] = jsonResponse("VEX document envelope.", "#/components/schemas/VEXDocumentEnvelope")
	case "uploadVulnerabilityScan":
		operation.Description = "Uploads a generic vulnerability scan JSON payload and records normalized findings."
		operation.RequestBody = jsonRequest("Vulnerability scan upload payload.", "#/components/schemas/UploadVulnerabilityScanRequest")
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
		operation.Description = "Searches tenant-scoped evidence with deterministic filters and cursor-style pagination."
		operation.Parameters = append(operation.Parameters,
			queryParam("product_id", "Filter by product id.", "string"),
			queryParam("project_id", "Filter by project id.", "string"),
			queryParam("release_id", "Filter by release id.", "string"),
			queryParam("type", "Filter by evidence type.", "string"),
			queryParam("source", "Filter by evidence source.", "string"),
			queryParam("tag", "Filter by a single evidence tag.", "string"),
			queryParam("cursor", "Opaque pagination cursor.", "string"),
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
		operation.Description = "Lists tenant-scoped SBOM components by SBOM, release, artifact, name/version/PURL query, or exact PURL."
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
		operation.Description = "Creates an append-only incident record linked to tenant-scoped product and optional release evidence."
		operation.RequestBody = jsonRequest("Incident creation request.", "#/components/schemas/CreateIncidentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident envelope.", "#/components/schemas/IncidentEnvelope")
	case "recordIncidentTimeline":
		operation.Description = "Appends an incident timeline event and optional evidence reference."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Incident id."))
		operation.RequestBody = jsonRequest("Incident timeline event request.", "#/components/schemas/RecordIncidentTimelineRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident timeline event envelope.", "#/components/schemas/IncidentTimelineEventEnvelope")
	case "createIncidentWebhookReceiver":
		operation.Description = "Creates an incident-scoped webhook receiver with an Ed25519 public key. The matching private key stays with the external incident tool."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Incident id."))
		operation.RequestBody = jsonRequest("Incident webhook receiver creation request.", "#/components/schemas/CreateIncidentWebhookReceiverRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident webhook receiver envelope.", "#/components/schemas/IncidentWebhookReceiverEnvelope")
	case "receiveIncidentWebhook":
		operation.Description = "Public signed webhook endpoint for incident timeline events. It verifies Ed25519 signature, event id replay, and timestamp before parsing payload fields."
		operation.Parameters = append(operation.Parameters,
			pathParam("receiver_id", "Incident webhook receiver id."),
			headerParam("X-Evydence-Webhook-Event-ID", "Provider event id used for replay detection."),
			headerParam("X-Evydence-Webhook-Timestamp", "RFC3339 timestamp included in the signed payload."),
			headerParam("X-Evydence-Webhook-Signature", "ed25519=<base64 signature> over timestamp, event id, and raw body."),
		)
		operation.RequestBody = jsonRequest("Signed incident timeline event payload.", "#/components/schemas/SignedIncidentWebhookPayload")
		operation.Security = nil
		operation.Scopes = nil
		operation.Extensions = nil
		operation.Responses[http.StatusCreated] = jsonResponse("Accepted webhook event and timeline event envelope.", "#/components/schemas/IncidentWebhookDeliveryEnvelope")
	case "createRemediationTask":
		operation.Description = "Creates an incident or release remediation task linked to optional evidence."
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
		operation.Description = "Returns a tenant-scoped immutable release bundle by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle envelope.", "#/components/schemas/ReleaseBundleEnvelope")
	case "getReleaseBundleManifest":
		operation.Description = "Returns the deterministic release bundle manifest by bundle id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle manifest envelope.", "#/components/schemas/ReleaseBundleManifestEnvelope")
	case "verifyReleaseBundle":
		operation.Description = "Verifies a tenant-scoped release bundle and returns a deterministic verification result."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "verifyAuditChain":
		operation.Description = "Verifies the tenant audit chain continuity and returns deterministic verification checks."
		operation.Responses[http.StatusOK] = jsonResponse("Audit chain verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "verify":
		operation.Description = "Verifies a supported tenant-scoped subject such as evidence, audit chain, release bundle, artifact signature, or related verification target."
		operation.RequestBody = jsonRequest("Subject verification request.", "#/components/schemas/VerifySubjectRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Subject verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "listAuditLog":
		operation.Description = "Lists tenant-scoped append-only audit-chain entries in reverse chronological order."
		operation.Parameters = append(operation.Parameters,
			queryParam("subject_type", "Filter by audited subject type.", "string"),
			queryParam("subject_id", "Filter by audited subject id.", "string"),
			queryParam("since", "Only include entries at or after this RFC3339 timestamp.", "string"),
			queryParam("limit", "Maximum returned entries; defaults to 100 and caps at 500.", "integer"),
		)
		operation.Responses[http.StatusOK] = jsonResponse("Audit-chain entry list envelope.", "#/components/schemas/AuditChainEntryListEnvelope")
	case "generateBackupManifest":
		operation.Description = "Generates a tenant-scoped backup manifest after an operator backup completes. The manifest excludes raw payload bytes and private key material."
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
	case "missingEvidenceReport":
		operation.Description = "Returns a deterministic missing-evidence report for a release with assumptions and limitations."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Missing evidence report envelope.", "#/components/schemas/MissingEvidenceReportEnvelope")
	case "evaluatePolicy":
		operation.Description = "Evaluates built-in deterministic release policy checks for a release."
		operation.RequestBody = jsonRequest("Policy evaluation request.", "#/components/schemas/EvaluatePolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Policy evaluation envelope.", "#/components/schemas/PolicyEvaluationEnvelope")
	case "createVulnerabilityDecision":
		operation.Description = "Creates an append-only vulnerability decision for a tenant-scoped scan finding."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Vulnerability finding id."))
		operation.RequestBody = jsonRequest("Vulnerability decision creation request.", "#/components/schemas/CreateVulnerabilityDecisionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created vulnerability decision envelope.", "#/components/schemas/VulnerabilityDecisionEnvelope")
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
		operation.Description = "Lists tenant-scoped exceptions, optionally filtered by release."
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
		operation.Description = "Uploads an OpenAPI 3.1 contract, stores raw bytes as evidence, and records normalized operation metadata."
		operation.RequestBody = jsonRequest("OpenAPI contract upload request.", "#/components/schemas/UploadOpenAPIContractRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created OpenAPI contract envelope.", "#/components/schemas/OpenAPIContractEnvelope")
	case "getOpenAPIContract":
		operation.Description = "Returns a tenant-scoped OpenAPI contract metadata record by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "OpenAPI contract id."))
		operation.Responses[http.StatusOK] = jsonResponse("OpenAPI contract envelope.", "#/components/schemas/OpenAPIContractEnvelope")
	case "createOpenAPIDiff":
		operation.Description = "Creates a deterministic OpenAPI contract diff for release contract checks."
		operation.RequestBody = jsonRequest("OpenAPI contract diff request.", "#/components/schemas/CreateOpenAPIDiffRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created OpenAPI contract diff envelope.", "#/components/schemas/ContractDiffEnvelope")
	case "listSigningKeys":
		operation.Description = "Lists tenant signing public-key metadata without private key material."
		operation.Responses[http.StatusOK] = jsonResponse("Signing key list envelope.", "#/components/schemas/SigningKeyListEnvelope")
	case "rotateSigningKey":
		operation.Description = "Rotates the active tenant signing key and returns public-key metadata only."
		operation.RequestBody = jsonRequest("Signing key rotation request.", "#/components/schemas/SigningKeyTransitionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Rotated signing key envelope.", "#/components/schemas/SigningKeyEnvelope")
	case "revokeSigningKey":
		operation.Description = "Revokes a tenant signing key as an audited lifecycle transition."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Signing key id."))
		operation.RequestBody = jsonRequest("Signing key revocation request.", "#/components/schemas/SigningKeyTransitionRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Revoked signing key envelope.", "#/components/schemas/SigningKeyEnvelope")
	case "createSigningProvider":
		operation.Description = "Creates signing provider metadata for external signing operations. Production private key material must not be supplied."
		operation.RequestBody = jsonRequest("Signing provider creation request.", "#/components/schemas/CreateSigningProviderRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created signing provider envelope.", "#/components/schemas/SigningProviderEnvelope")
	case "createSigningOperation":
		operation.Description = "Records an external signing operation receipt and checks payload/signature metadata without logging secrets. When the API is configured with a signing executor, external_signature may be omitted and the executor signs the payload hash."
		operation.RequestBody = jsonRequest("Signing operation creation request.", "#/components/schemas/CreateSigningOperationRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created signing operation envelope.", "#/components/schemas/SigningOperationEnvelope")
	case "createArtifactSignature":
		operation.Description = "Records detached artifact signature evidence and optional raw signature payload metadata."
		operation.RequestBody = jsonRequest("Artifact signature creation request.", "#/components/schemas/CreateArtifactSignatureRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created artifact signature envelope.", "#/components/schemas/ArtifactSignatureEnvelope")
	case "getArtifactSignature":
		operation.Description = "Returns tenant-scoped artifact signature metadata by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Artifact signature id."))
		operation.Responses[http.StatusOK] = jsonResponse("Artifact signature envelope.", "#/components/schemas/ArtifactSignatureEnvelope")
	case "verifyCosignSignature":
		operation.Description = "Records deterministic cosign-style verification metadata for an artifact signature without implying online transparency trust."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Artifact signature id."))
		operation.RequestBody = jsonRequest("Cosign verification metadata request.", "#/components/schemas/VerifyCosignSignatureRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Cosign verification envelope.", "#/components/schemas/CosignVerificationEnvelope")
	case "uploadBuildAttestation":
		operation.Description = "Uploads a DSSE/in-toto build attestation for a tenant-scoped build and stores raw bytes in object storage."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build run id."))
		operation.RequestBody = jsonRequest("DSSE envelope.", "#/components/schemas/DSSEEnvelope")
		operation.Responses[http.StatusCreated] = jsonResponse("Created build attestation envelope.", "#/components/schemas/BuildAttestationEnvelope")
	case "verifyBuildAttestationSignature":
		operation.Description = "Verifies a build attestation signature against configured tenant DSSE trust roots."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Build attestation id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Build attestation verification envelope.", "#/components/schemas/VerificationResultEnvelope")
	case "createDSSETrustRoot":
		operation.Description = "Creates a tenant-scoped DSSE trust root using public verification key material only."
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
		operation.Description = "Records a release-candidate lifecycle transition without mutating the original snapshot."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release candidate id."))
		operation.RequestBody = jsonRequest("Release candidate transition request.", "#/components/schemas/ReleaseCandidateTransitionRequest")
		operation.Responses[http.StatusOK] = jsonResponse("Transitioned release candidate envelope.", "#/components/schemas/ReleaseCandidateEnvelope")
	case "supersedeEvidence":
		operation.Description = "Supersedes immutable evidence by linking it to replacement evidence and appending lifecycle metadata."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence supersession request.", "#/components/schemas/SupersedeEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Superseded evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "linkEvidence":
		operation.Description = "Creates an append-only relationship from evidence to another tenant-scoped subject."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence link request.", "#/components/schemas/LinkEvidenceRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Linked evidence item envelope.", "#/components/schemas/EvidenceItemEnvelope")
	case "recordEvidenceLifecycleEvent":
		operation.Description = "Appends an evidence lifecycle event such as amendment, redaction marker, tombstone, or retention marker."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.RequestBody = jsonRequest("Evidence lifecycle event request.", "#/components/schemas/RecordEvidenceLifecycleEventRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence lifecycle event envelope.", "#/components/schemas/EvidenceLifecycleEventEnvelope")
	case "listEvidenceLifecycleEvents":
		operation.Description = "Lists append-only lifecycle events for a tenant-scoped evidence item."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Evidence item id."))
		operation.Responses[http.StatusOK] = jsonResponse("Evidence lifecycle event list envelope.", "#/components/schemas/EvidenceLifecycleEventListEnvelope")
	case "createSourceRepository":
		operation.Description = "Creates a tenant-scoped source repository record."
		operation.RequestBody = jsonRequest("Source repository creation request.", "#/components/schemas/CreateSourceRepositoryRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source repository envelope.", "#/components/schemas/SourceRepositoryEnvelope")
	case "listSourceRepositories":
		operation.Description = "Lists tenant-scoped source repositories, optionally filtered by project."
		operation.Parameters = append(operation.Parameters, queryParam("project_id", "Project id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Source repository list envelope.", "#/components/schemas/SourceRepositoryListEnvelope")
	case "recordSourceCommit":
		operation.Description = "Records immutable source commit metadata and stores only a hash of the commit message."
		operation.RequestBody = jsonRequest("Source commit creation request.", "#/components/schemas/RecordSourceCommitRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created source commit envelope.", "#/components/schemas/SourceCommitEnvelope")
	case "upsertSourceBranch":
		operation.Description = "Records or updates source branch metadata and protected-branch snapshot hash."
		operation.RequestBody = jsonRequest("Source branch upsert request.", "#/components/schemas/UpsertSourceBranchRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Source branch envelope.", "#/components/schemas/SourceBranchEnvelope")
	case "recordPullRequest":
		operation.Description = "Records pull-request review metadata linked to source repository evidence."
		operation.RequestBody = jsonRequest("Pull request record request.", "#/components/schemas/RecordPullRequestRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created pull request envelope.", "#/components/schemas/PullRequestEnvelope")
	case "createDeploymentEnvironment":
		operation.Description = "Creates a tenant-scoped deployment environment for release deployment evidence."
		operation.RequestBody = jsonRequest("Deployment environment creation request.", "#/components/schemas/CreateDeploymentEnvironmentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created deployment environment envelope.", "#/components/schemas/DeploymentEnvironmentEnvelope")
	case "listDeploymentEnvironments":
		operation.Description = "Lists tenant-scoped deployment environments, optionally filtered by product."
		operation.Parameters = append(operation.Parameters, queryParam("product_id", "Product id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Deployment environment list envelope.", "#/components/schemas/DeploymentEnvironmentListEnvelope")
	case "recordDeployment":
		operation.Description = "Records append-only deployment evidence for a release/environment/artifact set."
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
		operation.Description = "Records collector release supply-chain evidence for a tenant-scoped collector."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Collector id."))
		operation.RequestBody = jsonRequest("Collector release record request.", "#/components/schemas/RecordCollectorReleaseRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created collector release envelope.", "#/components/schemas/CollectorReleaseEnvelope")
	case "collectorHealthReport":
		operation.Description = "Returns collector supply-chain health from recorded tenant evidence, assumptions, and limitations."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Collector id."))
		operation.Responses[http.StatusOK] = jsonResponse("Collector health report envelope.", "#/components/schemas/CollectorHealthReportEnvelope")
	case "createCommercialCollector":
		operation.Description = "Creates tenant-scoped commercial collector metadata without installing external code."
		operation.RequestBody = jsonRequest("Commercial collector definition request.", "#/components/schemas/CreateCommercialCollectorRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created commercial collector definition envelope.", "#/components/schemas/CommercialCollectorDefinitionEnvelope")
	case "listCommercialCollectors":
		operation.Description = "Lists tenant-scoped commercial collector definitions."
		operation.Responses[http.StatusOK] = jsonResponse("Commercial collector definition list envelope.", "#/components/schemas/CommercialCollectorDefinitionListEnvelope")
	case "createMarketplaceCollector":
		operation.Description = "Creates tenant-scoped marketplace collector package metadata and evidence references."
		operation.RequestBody = jsonRequest("Marketplace collector creation request.", "#/components/schemas/CreateMarketplaceCollectorRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created marketplace collector envelope.", "#/components/schemas/MarketplaceCollectorEnvelope")
	case "listMarketplaceCollectors":
		operation.Description = "Lists tenant-scoped marketplace collector package metadata."
		operation.Responses[http.StatusOK] = jsonResponse("Marketplace collector list envelope.", "#/components/schemas/MarketplaceCollectorListEnvelope")
	case "marketplaceCollectorHealth":
		operation.Description = "Returns marketplace collector package health from recorded signature, SBOM, and scan evidence."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Marketplace collector id."))
		operation.Responses[http.StatusOK] = jsonResponse("Marketplace collector health report envelope.", "#/components/schemas/MarketplaceCollectorHealthReportEnvelope")
	case "listControlFrameworkTemplatePacks":
		operation.Description = "Lists built-in control framework template packs available for explicit tenant installation."
		operation.Responses[http.StatusOK] = jsonResponse("Control framework template pack list envelope.", "#/components/schemas/ControlFrameworkTemplatePackListEnvelope")
	case "installControlFrameworkTemplatePack":
		operation.Description = "Installs a named control framework template pack into the tenant as ordinary framework/control records."
		operation.Parameters = append(operation.Parameters, pathParam("slug", "Control framework template pack slug."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusCreated] = jsonResponse("Installed control framework envelope.", "#/components/schemas/ControlFrameworkEnvelope")
	case "registerContainerImage":
		operation.Description = "Registers OCI/container image metadata and digest evidence linked to an optional artifact."
		operation.RequestBody = jsonRequest("Container image registration request.", "#/components/schemas/RegisterContainerImageRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Registered container image envelope.", "#/components/schemas/ContainerImageEnvelope")
	case "uploadSecurityScan", "uploadAPISecurityScan":
		operation.Description = "Uploads SAST, DAST, secret, license, or API security scan metadata and raw JSON payload evidence without exposing raw payload bytes in responses."
		operation.RequestBody = jsonRequest("Security scan upload request.", "#/components/schemas/UploadSecurityScanRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created security scan envelope.", "#/components/schemas/SecurityScanEnvelope")
	case "uploadManualSecurityDocument":
		operation.Description = "Uploads sensitive manual security evidence such as threat model, security review, or penetration-test report metadata and raw payload reference."
		operation.RequestBody = jsonRequest("Manual security document upload request.", "#/components/schemas/UploadManualSecurityDocumentRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created manual security document envelope.", "#/components/schemas/ManualSecurityDocumentEnvelope")
	case "uploadSPDXSBOM":
		operation.Description = "Uploads an SPDX JSON SBOM payload, stores raw bytes as evidence, and records normalized SBOM metadata."
		operation.RequestBody = jsonRequest("SPDX SBOM upload request.", "#/components/schemas/UploadSPDXSBOMRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM envelope.", "#/components/schemas/SBOMEnvelope")
	case "createSBOMDiff":
		operation.Description = "Creates a deterministic SBOM diff between two tenant-scoped SBOM records."
		operation.RequestBody = jsonRequest("SBOM diff creation request.", "#/components/schemas/CreateSBOMDiffRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SBOM diff envelope.", "#/components/schemas/SBOMDiffEnvelope")
	case "vulnerabilityPostureReport":
		operation.Description = "Returns a vulnerability posture report derived from stored scan, decision, VEX, exception, and workflow records."
		operation.Parameters = append(operation.Parameters, queryParam("release_id", "Release id.", "string"))
		operation.Responses[http.StatusOK] = jsonResponse("Vulnerability posture report envelope.", "#/components/schemas/VulnerabilityPostureReportEnvelope")
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
	case "createObjectRetentionPolicy":
		operation.Description = "Creates an object retention policy record for storage immutability verification."
		operation.RequestBody = jsonRequest("Object retention policy creation request.", "#/components/schemas/CreateObjectRetentionPolicyRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created object retention policy envelope.", "#/components/schemas/ObjectRetentionPolicyEnvelope")
	case "verifyObjectRetentionPolicy":
		operation.Description = "Records verification metadata for a tenant object retention policy."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Object retention policy id."))
		operation.RequestBody = jsonRequest("Empty JSON object.", "#/components/schemas/EmptyObject")
		operation.Responses[http.StatusOK] = jsonResponse("Verified object retention policy envelope.", "#/components/schemas/ObjectRetentionPolicyEnvelope")
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
		operation.Responses[http.StatusCreated] = jsonResponse("Created customer security package envelope.", "#/components/schemas/CustomerSecurityPackageEnvelope")
	case "getCustomerPackage":
		operation.Description = "Returns a tenant-scoped customer security package manifest by id."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Customer package id."))
		operation.Responses[http.StatusOK] = jsonResponse("Customer security package envelope.", "#/components/schemas/CustomerSecurityPackageEnvelope")
	case "createCustomerPortalAccess":
		operation.Description = "Creates token-based customer portal access for a customer package and returns the token once."
		operation.RequestBody = jsonRequest("Customer portal access creation request.", "#/components/schemas/CreateCustomerPortalAccessRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created portal access and one-time token envelope.", "#/components/schemas/CustomerPortalAccessCreateEnvelope")
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
	case "createPDFReportPackage":
		operation.Description = "Creates a deterministic PDF report package record and payload metadata."
		operation.RequestBody = jsonRequest("PDF report package creation request.", "#/components/schemas/CreatePDFReportPackageRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created PDF report package envelope.", "#/components/schemas/PDFReportPackageEnvelope")
	}
	return operation
}

func addProblemResponses(operation *specs.Operation) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity} {
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

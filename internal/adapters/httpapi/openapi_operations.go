package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/specs"
)

func withCriticalOperationDetails(operation specs.Operation) specs.Operation {
	addProblemResponses(&operation)
	switch operation.OperationID {
	case "ready":
		operation.Description = "Returns low-detail process readiness without tenant evidence or secret material."
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Readiness status envelope.", "#/components/schemas/ReadinessStatusEnvelope")
	case "instanceAdminSnapshot":
		operation.Description = "Returns instance-level diagnostic counts. Requires the explicit instance:admin scope; tenant admin and ordinary wildcard tenant keys are insufficient."
		operation.Responses[http.StatusOK] = jsonResponse("Instance admin snapshot envelope.", "#/components/schemas/DataEnvelope")
	case "createSSOSession":
		operation.Description = "Creates an admin-managed human SSO session record and returns a one-time bearer secret."
		operation.RequestBody = jsonRequest("SSO session creation request.", "#/components/schemas/CreateSSOSessionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO session and one-time secret envelope.", "#/components/schemas/SSOSessionCreateEnvelope")
	case "createSSOProvider":
		operation.Description = "Records tenant SSO provider metadata. Optional static JWKS public keys and SAML signing certificates can be supplied for local token/assertion verification without live provider calls."
		operation.RequestBody = jsonRequest("SSO provider creation request.", "#/components/schemas/CreateSSOProviderRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO provider envelope.", "#/components/schemas/SSOProviderEnvelope")
	case "verifyProviderIdentity":
		operation.Description = "Verifies stored provider identity metadata and, when supplied, locally verifies OIDC ID-token or SAML assertion issuer, audience, subject, time bounds, and signature against configured tenant trust material."
		operation.RequestBody = jsonRequest("Provider identity verification request.", "#/components/schemas/VerifyProviderIdentityRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Provider verification envelope.", "#/components/schemas/ProviderVerificationEnvelope")
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
		operation.Responses[http.StatusCreated] = jsonResponse("Created evidence item envelope.", "#/components/schemas/DataEnvelope")
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
		operation.Responses[http.StatusOK] = jsonResponse("SBOM component result envelope.", "#/components/schemas/DataEnvelope")
	case "createIncidentWebhookReceiver":
		operation.Description = "Creates an incident-scoped webhook receiver with an Ed25519 public key. The matching private key stays with the external incident tool."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Incident id."))
		operation.RequestBody = jsonRequest("Incident webhook receiver creation request.", "#/components/schemas/DataEnvelope")
		operation.Responses[http.StatusCreated] = jsonResponse("Created incident webhook receiver envelope.", "#/components/schemas/DataEnvelope")
	case "receiveIncidentWebhook":
		operation.Description = "Public signed webhook endpoint for incident timeline events. It verifies Ed25519 signature, event id replay, and timestamp before parsing payload fields."
		operation.Parameters = append(operation.Parameters,
			pathParam("receiver_id", "Incident webhook receiver id."),
			headerParam("X-Evydence-Webhook-Event-ID", "Provider event id used for replay detection."),
			headerParam("X-Evydence-Webhook-Timestamp", "RFC3339 timestamp included in the signed payload."),
			headerParam("X-Evydence-Webhook-Signature", "ed25519=<base64 signature> over timestamp, event id, and raw body."),
		)
		operation.RequestBody = jsonRequest("Signed incident timeline event payload.", "#/components/schemas/DataEnvelope")
		operation.Security = nil
		operation.Scopes = nil
		operation.Extensions = nil
		operation.Responses[http.StatusCreated] = jsonResponse("Accepted webhook event and timeline event envelope.", "#/components/schemas/DataEnvelope")
	case "createReleaseBundle":
		operation.Description = "Creates an immutable signed release bundle for a release."
		operation.RequestBody = jsonRequest("Release bundle creation request.", "#/components/schemas/CreateReleaseBundleRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created release bundle envelope.", "#/components/schemas/DataEnvelope")
	case "verifyReleaseBundle":
		operation.Description = "Verifies a tenant-scoped release bundle and returns a deterministic verification result."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle verification envelope.", "#/components/schemas/ReleaseBundleVerificationEnvelope")
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
		operation.Responses[http.StatusOK] = jsonResponse("Scoped customer package envelope.", "#/components/schemas/DataEnvelope")
	case "downloadCustomerPortalPackage":
		operation.Description = "Public token exchange endpoint for downloading a scoped customer package ZIP. It intentionally uses no bearer authentication and accepts only the issued portal token in the JSON body."
		operation.RequestBody = jsonRequest("Customer portal token request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = binaryResponse("Customer security package ZIP archive.")
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

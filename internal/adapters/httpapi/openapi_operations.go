package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/specs"
)

func withCriticalOperationDetails(operation specs.Operation) specs.Operation {
	addProblemResponses(&operation)
	switch operation.OperationID {
	case "instanceAdminSnapshot":
		operation.Description = "Returns instance-level diagnostic counts. Requires the explicit instance:admin scope; tenant admin and ordinary wildcard tenant keys are insufficient."
		operation.Responses[http.StatusOK] = jsonResponse("Instance admin snapshot envelope.", "#/components/schemas/DataEnvelope")
	case "createSSOSession":
		operation.Description = "Creates an admin-managed human SSO session record and returns a one-time bearer secret."
		operation.RequestBody = jsonRequest("SSO session creation request.", "#/components/schemas/CreateSSOSessionRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created SSO session and one-time secret envelope.", "#/components/schemas/SSOSessionCreateEnvelope")
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
	case "createReleaseBundle":
		operation.Description = "Creates an immutable signed release bundle for a release."
		operation.RequestBody = jsonRequest("Release bundle creation request.", "#/components/schemas/CreateReleaseBundleRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created release bundle envelope.", "#/components/schemas/DataEnvelope")
	case "verifyReleaseBundle":
		operation.Description = "Verifies a tenant-scoped release bundle and returns a deterministic verification result."
		operation.Parameters = append(operation.Parameters, pathParam("id", "Release bundle id."))
		operation.Responses[http.StatusOK] = jsonResponse("Release bundle verification envelope.", "#/components/schemas/ReleaseBundleVerificationEnvelope")
	case "createCustomerPortalAccess":
		operation.Description = "Creates token-based customer portal access for a customer package and returns the token once."
		operation.RequestBody = jsonRequest("Customer portal access creation request.", "#/components/schemas/CreateCustomerPortalAccessRequest")
		operation.Responses[http.StatusCreated] = jsonResponse("Created portal access and one-time token envelope.", "#/components/schemas/CustomerPortalAccessCreateEnvelope")
	case "accessCustomerPortalPackage":
		operation.Description = "Public token exchange endpoint for a scoped customer package. It intentionally uses no bearer authentication and accepts only the issued portal token in the JSON body."
		operation.RequestBody = jsonRequest("Customer portal token request.", "#/components/schemas/CustomerPortalPackageRequest")
		operation.Security = nil
		operation.Scopes = nil
		operation.Responses[http.StatusOK] = jsonResponse("Scoped customer package envelope.", "#/components/schemas/DataEnvelope")
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

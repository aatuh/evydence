package application

import (
	"encoding/json"
	"testing"

	"github.com/aatuh/evydence/internal/authz"
)

func TestAuthorizationReferencesPreservePolicyOwnedCoordinates(t *testing.T) {
	// Assignment, not a field-by-field conversion, must preserve all ownership
	// coordinates when a context hands its resolved references to policy.
	request := authz.Request{Resources: ResourceReferences{
		TenantID: "tenant", OrganizationID: "organization", ProductID: "product",
		ProjectID: "project", ReleaseID: "release", ArtifactID: "artifact", BuildID: "build",
		DeploymentID: "deployment", EnvironmentID: "environment", CustomerPackageID: "package",
	}}
	roundtrip := AuthorizationRequest{Resources: request.Resources}
	if roundtrip.Resources != request.Resources {
		t.Fatal("authorization coordinates changed at the application/policy boundary")
	}
}

func TestAuthorizationReferencesPreserveLegacyJSONBytesWhenNewOwnersAreAbsent(t *testing.T) {
	for _, tc := range []struct {
		name string
		refs ResourceReferences
		want string
	}{
		{"empty", ResourceReferences{}, `{"ProductID":"","ProjectID":"","ReleaseID":"","ArtifactID":"","BuildID":"","DeploymentID":"","EnvironmentID":"","CustomerPackageID":""}`},
		{"resolved", ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", ArtifactID: "artifact", BuildID: "build", DeploymentID: "deployment", EnvironmentID: "environment", CustomerPackageID: "package"}, `{"ProductID":"product","ProjectID":"project","ReleaseID":"release","ArtifactID":"artifact","BuildID":"build","DeploymentID":"deployment","EnvironmentID":"environment","CustomerPackageID":"package"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.refs)
			if err != nil || string(body) != tc.want {
				t.Fatalf("internal reference JSON compatibility changed: got=%s want=%s error=%v", body, tc.want, err)
			}
		})
	}
}

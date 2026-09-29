package wiring

import (
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
)

func TestBuildAPIReadServicesRejectsIncompleteRuntimeWithoutLeakingSecrets(t *testing.T) {
	for _, test := range []struct {
		name    string
		runtime *Runtime
	}{
		{"nil runtime", nil},
		{"postgres without store", &Runtime{Process: API, Profile: PostgreSQL}},
		{"memory with store", &Runtime{Process: API, Profile: LocalMemory, Postgres: &postgres.Store{}}},
		{"unknown profile", &Runtime{Process: API, Profile: Profile("other")}},
		{"worker runtime", &Runtime{Process: Worker, Profile: PostgreSQL, Postgres: &postgres.Store{}}},
		{"production memory", &Runtime{Process: API, Profile: LocalMemory, Production: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildAPIReadServices(test.runtime, "private-pepper")
			if err == nil || strings.Contains(err.Error(), "private-pepper") {
				t.Fatalf("unsafe runtime error=%v", err)
			}
		})
	}
}

func TestBuildAPIReadServicesComposesDurableQueriesOnlyForPostgres(t *testing.T) {
	memory, err := BuildAPIReadServices(&Runtime{Process: API, Profile: LocalMemory}, "")
	if err != nil || memory.Authenticator != nil || memory.InstanceAdminQuery != nil || memory.ProductQuery != nil || memory.ArtifactPointQuery != nil || memory.OpenAPIContractPointQuery != nil || memory.ReleaseBundleQuery != nil || memory.ControlEvidenceQuery != nil || memory.MarketplaceCollectorQuery != nil || memory.CollectorHealthQuery != nil || memory.VulnerabilityPostureQuery != nil {
		t.Fatalf("local memory dependencies=%#v error=%v", memory, err)
	}
	store := &postgres.Store{}
	options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "non-default-pepper")
	if err != nil {
		t.Fatal(err)
	}
	if options.Authenticator == nil || options.InstanceAdminQuery == nil || options.ProductQuery == nil || options.CatalogPointQuery == nil ||
		options.BuildPointQuery == nil || options.ArtifactPointQuery == nil || options.ReleaseCandidateQuery == nil || options.DeploymentPointQuery == nil ||
		options.DeploymentListQuery == nil || options.EvidencePointQuery == nil || options.OpenAPIContractPointQuery == nil || options.SourceRepositoryQuery == nil ||
		options.CollectorQuery == nil || options.CollectorHealthQuery == nil || options.CommercialCollectorQuery == nil || options.MarketplaceCollectorQuery == nil || options.VulnerabilityPostureQuery == nil || options.ControlsQuery == nil || options.ControlEvidenceQuery == nil || options.ArtifactSignatureQuery == nil ||
		options.ReleaseBundleQuery == nil || options.AnswerLibraryQuery == nil || options.AuditLogQuery == nil ||
		options.SigningKeyQuery == nil ||
		options.PortalAccessQuery == nil || options.APIKeyQuery == nil || options.RoleBindingQuery == nil {
		t.Fatalf("incomplete durable dependencies=%#v", options)
	}
	if _, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, ""); err == nil {
		t.Fatal("production accepted a missing credential pepper")
	}
}

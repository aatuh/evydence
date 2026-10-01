package wiring

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
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
			_, err := BuildAPIReadServices(test.runtime, "private-pepper", nil)
			if err == nil || strings.Contains(err.Error(), "private-pepper") {
				t.Fatalf("unsafe runtime error=%v", err)
			}
		})
	}
}

func TestBuildAPIReadServicesComposesDurableQueriesOnlyForPostgres(t *testing.T) {
	memory, err := BuildAPIReadServices(&Runtime{Process: API, Profile: LocalMemory}, "", nil)
	if err != nil || memory.ReadinessQuery != nil || memory.MetricsQuery != nil || memory.RetentionQuery != nil || memory.IncidentReportQuery != nil || memory.SecurityUpdateEvidenceQuery != nil || memory.CRAVulnerabilityQuery != nil || memory.MissingEvidenceQuery != nil || memory.ControlCoverageQuery != nil || memory.Authenticator != nil || memory.InstanceAdminQuery != nil || memory.OutboxDiagnosticsQuery != nil || memory.OutboxReplayCommand != nil || memory.ProductQuery != nil || memory.ArtifactPointQuery != nil || memory.EvidenceFlowQuery != nil || memory.OpenAPIContractPointQuery != nil || memory.SBOMPointQuery != nil || memory.VulnerabilityScanPointQuery != nil || memory.VEXPointQuery != nil || memory.SBOMComponentsQuery != nil || memory.ReleaseBundleQuery != nil || memory.ControlEvidenceQuery != nil || memory.ControlTemplateQuery != nil || memory.ExceptionsQuery != nil || memory.VulnerabilityDecisionQuery != nil || memory.VulnerabilityDecisionSummaryQuery != nil || memory.MarketplaceCollectorQuery != nil || memory.CollectorHealthQuery != nil || memory.VulnerabilityPostureQuery != nil {
		t.Fatalf("local memory dependencies=%#v error=%v", memory, err)
	}
	store := &postgres.Store{}
	checks := []app.ReadinessCheck{
		{Name: "postgres", Check: func(context.Context) error { return nil }},
		{Name: "migrations", Check: func(context.Context) error { return nil }},
		{Name: "writer_lease", Check: func(context.Context) error { return nil }},
		{Name: "signing_config", Check: func(context.Context) error { return nil }},
	}
	options, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "non-default-pepper", checks)
	if err != nil {
		t.Fatal(err)
	}
	if options.ReadinessQuery == nil || options.MetricsQuery == nil || options.RetentionQuery == nil || options.IncidentReportQuery == nil || options.SecurityUpdateEvidenceQuery == nil || options.CRAVulnerabilityQuery == nil || options.MissingEvidenceQuery == nil || options.ControlCoverageQuery == nil || options.Authenticator == nil || options.InstanceAdminQuery == nil || options.OutboxDiagnosticsQuery == nil || options.OutboxReplayCommand == nil || options.ProductQuery == nil || options.CatalogPointQuery == nil || options.EvidenceFlowQuery == nil ||
		options.BuildPointQuery == nil || options.ArtifactPointQuery == nil || options.ReleaseCandidateQuery == nil || options.DeploymentPointQuery == nil ||
		options.DeploymentListQuery == nil || options.EvidencePointQuery == nil || options.OpenAPIContractPointQuery == nil || options.SBOMPointQuery == nil || options.VulnerabilityScanPointQuery == nil || options.VEXPointQuery == nil || options.SBOMComponentsQuery == nil || options.SourceRepositoryQuery == nil ||
		options.CollectorQuery == nil || options.CollectorHealthQuery == nil || options.CommercialCollectorQuery == nil || options.MarketplaceCollectorQuery == nil || options.VulnerabilityPostureQuery == nil || options.ControlsQuery == nil || options.ControlTemplateQuery == nil || options.ExceptionsQuery == nil || options.VulnerabilityDecisionQuery == nil || options.VulnerabilityDecisionSummaryQuery == nil || options.ControlEvidenceQuery == nil || options.ArtifactSignatureQuery == nil ||
		options.ReleaseBundleQuery == nil || options.AnswerLibraryQuery == nil || options.AuditLogQuery == nil ||
		options.SigningKeyQuery == nil ||
		options.PortalAccessQuery == nil || options.APIKeyQuery == nil || options.RoleBindingQuery == nil {
		t.Fatalf("incomplete durable dependencies=%#v", options)
	}
	if _, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "", checks); err == nil {
		t.Fatal("production accepted a missing credential pepper")
	}
	if _, err := BuildAPIReadServices(&Runtime{Process: API, Profile: PostgreSQL, Postgres: store, Production: true}, "non-default-pepper", nil); err == nil {
		t.Fatal("production accepted missing dependency probes")
	}
	status, err := options.ReadinessQuery.Public(t.Context())
	if err != nil || status["status"] != "ok" {
		t.Fatalf("composed readiness=%#v err=%v", status, err)
	}
}

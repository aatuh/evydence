package wiring

import (
	"errors"
	"fmt"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
)

// BuildAPIReadServices composes the API's durable authentication and focused
// query ports from one validated runtime. Local memory deliberately keeps the
// explicit Ledger fallback and receives no PostgreSQL-backed read services.
func BuildAPIReadServices(runtime *Runtime, pepper string) (httpapi.ServerOptions, error) {
	if runtime == nil {
		return httpapi.ServerOptions{}, errors.New("API runtime is required")
	}
	if runtime.Process != API {
		return httpapi.ServerOptions{}, errors.New("API read services require an API runtime")
	}
	switch runtime.Profile {
	case LocalMemory:
		if runtime.Production || runtime.Postgres != nil {
			return httpapi.ServerOptions{}, errors.New("local-memory API runtime is inconsistent")
		}
		return httpapi.ServerOptions{}, nil
	case PostgreSQL:
		if runtime.Postgres == nil {
			return httpapi.ServerOptions{}, errors.New("PostgreSQL API runtime is incomplete")
		}
	default:
		return httpapi.ServerOptions{}, errors.New("unsupported API runtime profile")
	}
	store := runtime.Postgres
	var options httpapi.ServerOptions
	var err error
	options.Authenticator, err = BuildAuthenticator(store, store, pepper, runtime.Production)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create authenticator: %w", err)
	}
	options.ProductQuery, err = BuildProductQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create product query: %w", err)
	}
	options.CatalogPointQuery, err = BuildCatalogPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create catalog point query: %w", err)
	}
	options.BuildPointQuery, err = BuildBuildPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create build point query: %w", err)
	}
	options.ReleaseCandidateQuery, err = BuildReleaseCandidateQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release candidate query: %w", err)
	}
	options.DeploymentPointQuery, err = BuildDeploymentPointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create deployment point query: %w", err)
	}
	options.DeploymentListQuery, err = BuildDeploymentListQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create deployment list query: %w", err)
	}
	options.EvidencePointQuery, err = BuildEvidencePointQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create evidence point query: %w", err)
	}
	options.SourceRepositoryQuery, err = BuildSourceRepositoryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create source repository query: %w", err)
	}
	options.CollectorQuery, err = BuildCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create collector query: %w", err)
	}
	options.CollectorHealthQuery, err = BuildCollectorHealthQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create collector health query: %w", err)
	}
	options.CommercialCollectorQuery, err = BuildCommercialCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create commercial collector query: %w", err)
	}
	options.MarketplaceCollectorQuery, err = BuildMarketplaceCollectorQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create marketplace collector query: %w", err)
	}
	options.ControlsQuery, err = BuildControlsQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create controls query: %w", err)
	}
	options.ControlEvidenceQuery, err = BuildControlEvidenceQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create control evidence query: %w", err)
	}
	options.ArtifactSignatureQuery, err = BuildArtifactSignatureQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create artifact signature query: %w", err)
	}
	options.ReleaseBundleQuery, err = BuildReleaseBundleQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create release bundle query: %w", err)
	}
	options.AnswerLibraryQuery, err = BuildAnswerLibraryQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create answer library query: %w", err)
	}
	options.PortalAccessQuery, err = BuildPortalAccessQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create portal access query: %w", err)
	}
	options.SigningKeyQuery, err = BuildSigningKeyQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create signing key query: %w", err)
	}
	options.AuditLogQuery, err = BuildAuditLogQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create audit log query: %w", err)
	}
	options.APIKeyQuery, err = BuildAPIKeyQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create API-key query: %w", err)
	}
	options.RoleBindingQuery, err = BuildRoleBindingQuery(store)
	if err != nil {
		return httpapi.ServerOptions{}, fmt.Errorf("create role-binding query: %w", err)
	}
	return options, nil
}

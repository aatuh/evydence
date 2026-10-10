package httpapi

import (
	"context"
	"errors"
)

// Historical helper names and response assertions are retained, but composition
// receives only a transaction-factory fixture, never an application aggregate.
// This test-only wiring is not a supported runtime backend. EVY-906 still
// requires deletion of the remaining application aggregate/state machinery.
func newLegacyServerFixture(ledger *repositoryFixture) (*Server, error) {
	return newLegacyServerFixtureWithOptionsContext(context.Background(), ledger, ServerOptions{})
}

func newLegacyServerFixtureWithOptions(ledger *repositoryFixture, opts ServerOptions) (*Server, error) {
	return newLegacyServerFixtureWithOptionsContext(context.Background(), ledger, opts)
}

// Derived transport fixtures inherit the explicitly configured authentication
// port, not a credential cache inferred from their shared transaction locator.
func derivedServerFixture(base *Server, opts ServerOptions) (*Server, error) {
	return derivedServerFixtureWithContext(context.Background(), base, opts)
}
func derivedServerFixtureWithContext(ctx context.Context, base *Server, opts ServerOptions) (*Server, error) {
	if opts.Authenticator == nil {
		opts.Authenticator = base.authn
	}
	return newLegacyServerFixtureWithOptionsContext(ctx, legacyFixtureLedger(base), opts)
}

func newLegacyServerFixtureWithOptionsContext(ctx context.Context, ledger *repositoryFixture, opts ServerOptions) (*Server, error) {
	if ctx == nil {
		return nil, errors.New("server context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ledger == nil {
		return nil, errors.New("local server requires an explicit Ledger")
	}
	server, err := newServerWithOptionsContext(ctx, opts)
	if err != nil {
		return nil, err
	}
	server.bindLegacyLedgerFixture(ledger)
	if opts.Authenticator != nil {
		server.authn = opts.Authenticator
	}
	return server, nil
}

// The transaction-only setup handle is obtained from existing test-only query ports,
// never a production Server field or a global registry. Tests overriding both
// query ports should retain their explicit transaction locator instead.
func legacyFixtureLedger(server *Server) *repositoryFixture {
	if query, ok := server.roleBindingQuery.(roleBindingFixtureQuery); ok {
		return query.ledger
	}
	if query, ok := server.apiKeyQuery.(apiKeyFixtureQuery); ok {
		return query.ledger
	}
	panic("server has no legacy identity-query fixture")
}

// Focused replay fixture ports keep isolated command effects and their replay
// record in the same transaction; there is no legacy Server replay field.
func (s *Server) bindLegacyLedgerFixture(ledger *repositoryFixture) {
	if authn, ok := s.authn.(identityNativeFixtureAuthenticator); ok {
		authn.ledger = ledger
		s.authn = authn
	} else if authn, ok := s.authn.(ssoFixtureAuthenticator); ok {
		authn.ledger = ledger
		s.authn = authn
	} else if s.authn == nil {
		s.authn = fixtureSessionAuthenticator(ledger, "test", nil)
	}
	s.bindCatalogFixturePorts(ledger)
	s.bindRegistrationFixturePorts(ledger)
	s.bindLifecycleFixturePorts(ledger)
	s.bindCatalogQueryFixturePorts(ledger)
	s.bindIdentityQueryFixturePorts(ledger)
	s.bindAPIKeyFixturePort(ledger)
	s.bindDeploymentFixturePorts(ledger)
	s.bindEvidenceFixturePorts(ledger)
	s.bindPackageFixturePorts(ledger)
	s.bindVerificationReadFixturePorts(ledger)
	s.bindSigningAdministrationFixturePorts(ledger)
	s.bindVerificationCommandFixturePorts(ledger)
	s.bindRiskQueryFixturePorts(ledger)
	s.bindGovernanceFixturePorts(ledger)
	s.bindRiskCommandFixturePorts(ledger)
	s.bindEvidenceReadFixturePorts(ledger)
	s.bindIngestionFixturePorts(ledger)
	s.bindDiffFixturePorts(ledger)
	s.bindIntegrationFixtureCommands(ledger)
	s.bindIntegrationFixtureQueries(ledger)
	s.bindOperationsFixtureCommands(ledger)
	s.bindOperationsFixtureQueries(ledger)
	s.bindControlFixtureCommands(ledger)
	s.bindControlFixtureQueries(ledger)
	s.bindRiskWorkflowFixtureCommands(ledger)
	s.bindRiskReportFixtureQueries(ledger)
	s.bindArtifactSignatureFixturePorts(ledger)
	s.bindPackageReportFixtureQueries(ledger)
	s.bindOperatorFixturePorts(ledger)
	s.bindMembershipFixturePorts(ledger)
	s.bindSSOProviderFixturePorts(ledger)
	s.bindSSOSessionFixturePorts(ledger)
	s.bindPeripheralFixturePorts(ledger)
	s.bindTransparencyFixturePorts(ledger)
	s.bindReportSigningFixturePorts(ledger)
	s.bindProviderVerificationFixturePort(ledger)
	s.bindPortalFixturePorts(ledger)
	s.bindQuestionnaireFixturePorts(ledger)
	s.bindSummaryDraftFixturePorts(ledger)
}

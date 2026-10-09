package httpapi

import (
	"context"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Native focused commands share the fixture's actual transaction, never its
// provider/link caches. Optional discovery and time are explicit test ports.
type ssoProviderFixtureCommands struct {
	catalogFixtureCommands
	discovery app.OIDCDiscoveryClient
	clock     application.Clock
}

func identityTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: app.NewMemoryUnitOfWorkFactory()})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	return server, secret
}

type ssoProviderFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type ssoProviderFixtureGuard struct {
	identityapp.SSOProviderWriteReader
	identityapp.SSOIdentityLinkWriteReader
	repos    app.Repositories
	readOnly bool
}

func (f ssoProviderFixtureTransactions) execute(ctx context.Context, run func(context.Context, ssoProviderFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		providers, ok := repos.Identity.(identityapp.SSOProviderWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		links, ok := repos.Identity.(identityapp.SSOIdentityLinkWriteReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, ssoProviderFixtureGuard{providers, links, repos, f.readOnly})
	})
}
func (f ssoProviderFixtureTransactions) ExecuteSSOProvider(ctx context.Context, run func(context.Context, identityapp.SSOProviderTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx ssoProviderFixtureGuard) error { return run(ctx, tx) })
}
func (f ssoProviderFixtureTransactions) ExecuteSSOIdentityLink(ctx context.Context, run func(context.Context, identityapp.SSOIdentityLinkTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx ssoProviderFixtureGuard) error { return run(ctx, tx) })
}
func (ssoProviderFixtureGuard) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, r)
}
func (g ssoProviderFixtureGuard) InsertSSOProvider(ctx context.Context, v identitydomain.SSOProvider) error {
	if g.readOnly {
		panic("SSO preflight inserted provider")
	}
	return g.repos.Identity.InsertSSOProvider(ctx, domain.SSOProvider(v))
}
func (g ssoProviderFixtureGuard) CompareAndSwapSSOProviderTrustMaterial(ctx context.Context, expected, v identitydomain.SSOProvider) error {
	if g.readOnly {
		panic("SSO preflight changed trust")
	}
	return g.repos.Identity.CompareAndSwapSSOProviderTrustMaterial(ctx, domain.SSOProvider(expected), domain.SSOProvider(v))
}
func (g ssoProviderFixtureGuard) InsertUserIdentityLink(ctx context.Context, v identitydomain.UserIdentityLink) error {
	if g.readOnly {
		panic("SSO preflight linked identity")
	}
	return g.repos.Identity.InsertUserIdentityLink(ctx, domain.UserIdentityLink(v))
}
func (g ssoProviderFixtureGuard) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if g.readOnly {
		panic("SSO preflight appended audit")
	}
	return (portalFixtureTransaction{repos: g.repos}).AppendAudit(ctx, v)
}
func (ssoProviderFixtureGuard) Hash(any) (string, error) { panic("SSO preflight hashed trust") }
func (ssoProviderFixtureGuard) FetchOIDCTrustMaterial(context.Context, identityapp.OIDCDiscoveryRequest) (identityapp.OIDCDiscoveryResult, error) {
	panic("SSO preflight performed discovery")
}

type ssoProviderFixtureDiscovery struct{ client app.OIDCDiscoveryClient }

func (d ssoProviderFixtureDiscovery) FetchOIDCTrustMaterial(ctx context.Context, in identityapp.OIDCDiscoveryRequest) (identityapp.OIDCDiscoveryResult, error) {
	v, err := d.client.FetchOIDCTrustMaterial(ctx, app.OIDCDiscoveryRequest{TenantID: in.TenantID, ProviderID: in.ProviderID, Issuer: in.Issuer})
	if err != nil {
		return identityapp.OIDCDiscoveryResult{}, err
	}
	return identityapp.OIDCDiscoveryResult{Issuer: v.Issuer, JWKS: v.JWKS}, nil
}
func (f ssoProviderFixtureCommands) clockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return clock, ids
}
func (f ssoProviderFixtureCommands) providerCommands(readOnly bool) (*identityapp.SSOProviderCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	var discovery identityapp.OIDCDiscovery
	if f.discovery != nil {
		discovery = ssoProviderFixtureDiscovery{f.discovery}
		if readOnly {
			discovery = ssoProviderFixtureGuard{}
		}
	}
	return identityapp.NewSSOProviderCommands(identityapp.SSOProviderCommandConfig{Transactions: ssoProviderFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), TrustMaterial: identityapp.PublicTrustMaterialValidator{}, Hasher: peripheralNativeHasher{readOnly: readOnly}, OIDCDiscovery: discovery, Clock: clock, IDs: ids})
}
func (f ssoProviderFixtureCommands) linkCommands(readOnly bool) (*identityapp.SSOIdentityLinkCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	return identityapp.NewSSOIdentityLinkCommands(identityapp.SSOIdentityLinkCommandConfig{Transactions: ssoProviderFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f ssoProviderFixtureCommands) AuthorizeCreateSSOProvider(ctx context.Context, a domain.Actor, in identityapp.CreateSSOProviderInput) error {
	g, err := f.providerCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateSSOProvider(ctx, a, in)
}
func (f ssoProviderFixtureCommands) AuthorizeUpdateSSOProviderTrustMaterial(ctx context.Context, a domain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) error {
	g, err := f.providerCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeUpdateSSOProviderTrustMaterial(ctx, a, id, in)
}
func (f ssoProviderFixtureCommands) AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.providerCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx, a, id)
}
func (f ssoProviderFixtureCommands) AuthorizeLinkSSOIdentity(ctx context.Context, a domain.Actor, in identityapp.LinkSSOIdentityInput) error {
	g, err := f.linkCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeLinkSSOIdentity(ctx, a, in)
}
func (f ssoProviderFixtureCommands) CreateSSOProvider(ctx context.Context, a domain.Actor, in identityapp.CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	c, err := f.providerCommands(false)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	v, err := c.CreateSSOProvider(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (f ssoProviderFixtureCommands) UpdateSSOProviderTrustMaterial(ctx context.Context, a domain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	c, err := f.providerCommands(false)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	v, err := c.UpdateSSOProviderTrustMaterial(ctx, a, id, in)
	return v, providerVerificationFixtureError(err)
}
func (f ssoProviderFixtureCommands) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOProvider, error) {
	c, err := f.providerCommands(false)
	if err != nil {
		return identitydomain.SSOProvider{}, err
	}
	v, err := c.RefreshSSOProviderOIDCTrustMaterial(ctx, a, id)
	return v, providerVerificationFixtureError(err)
}
func (f ssoProviderFixtureCommands) LinkSSOIdentity(ctx context.Context, a domain.Actor, in identityapp.LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	c, err := f.linkCommands(false)
	if err != nil {
		return identitydomain.UserIdentityLink{}, err
	}
	v, err := c.LinkSSOIdentity(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (s *Server) bindSSOProviderFixturePorts(ledger *app.Ledger) {
	if old, fixture := s.ssoProviderCommands.(ssoProviderFixtureCommands); fixture {
		old.ledger = ledger
		s.ssoProviderCommands = old
	} else if s.ssoProviderCommands == nil {
		s.ssoProviderCommands = ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	}
	if old, fixture := s.ssoIdentityLinkCommands.(ssoProviderFixtureCommands); fixture {
		old.ledger = ledger
		s.ssoIdentityLinkCommands = old
	} else if s.ssoIdentityLinkCommands == nil {
		s.ssoIdentityLinkCommands = ssoProviderFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	}
}

func (s *Server) bindSSOProviderFixtureResources(discovery app.OIDCDiscoveryClient, clock application.Clock) {
	if f, ok := s.ssoProviderCommands.(ssoProviderFixtureCommands); ok {
		f.discovery, f.clock = discovery, clock
		s.ssoProviderCommands = f
	}
	if f, ok := s.ssoIdentityLinkCommands.(ssoProviderFixtureCommands); ok {
		f.clock = clock
		s.ssoIdentityLinkCommands = f
	}
}

var (
	_ SSOProviderCommands     = ssoProviderFixtureCommands{}
	_ SSOIdentityLinkCommands = ssoProviderFixtureCommands{}
)

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

type ssoProviderFixtureCommands struct{ catalogFixtureCommands }

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

type ssoProviderFixtureTransactions struct{ catalogFixtureCommands }
type ssoProviderFixtureGuard struct {
	identityapp.SSOProviderWriteReader
	identityapp.SSOIdentityLinkWriteReader
}

func (f ssoProviderFixtureTransactions) execute(ctx context.Context, run func(context.Context, ssoProviderFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		providers, ok := repos.Identity.(identityapp.SSOProviderWriteReader)
		if !ok {
			return app.ErrValidation
		}
		links, ok := repos.Identity.(identityapp.SSOIdentityLinkWriteReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, ssoProviderFixtureGuard{providers, links})
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
func (ssoProviderFixtureGuard) InsertSSOProvider(context.Context, identitydomain.SSOProvider) error {
	panic("SSO preflight inserted provider")
}
func (ssoProviderFixtureGuard) CompareAndSwapSSOProviderTrustMaterial(context.Context, identitydomain.SSOProvider, identitydomain.SSOProvider) error {
	panic("SSO preflight changed trust")
}
func (ssoProviderFixtureGuard) InsertUserIdentityLink(context.Context, identitydomain.UserIdentityLink) error {
	panic("SSO preflight linked identity")
}
func (ssoProviderFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("SSO preflight appended audit")
}
func (ssoProviderFixtureGuard) Hash(any) (string, error) { panic("SSO preflight hashed trust") }
func (ssoProviderFixtureGuard) FetchOIDCTrustMaterial(context.Context, identityapp.OIDCDiscoveryRequest) (identityapp.OIDCDiscoveryResult, error) {
	panic("SSO preflight performed discovery")
}

// The sentinel proves preflight does not perform network I/O. Actual optional
// discovery configuration and execution remain owned by the historical command;
// this test bridge is not configuration, SQL-locking or durability evidence.
func (f ssoProviderFixtureCommands) providerGuard() (*identityapp.SSOProviderCommands, error) {
	return identityapp.NewSSOProviderCommands(identityapp.SSOProviderCommandConfig{Transactions: ssoProviderFixtureTransactions(f), Authorizer: identityapp.NewMembershipWriteAuthorizer(), TrustMaterial: identityapp.PublicTrustMaterialValidator{}, Hasher: ssoProviderFixtureGuard{}, OIDCDiscovery: ssoProviderFixtureGuard{}, Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f ssoProviderFixtureCommands) linkGuard() (*identityapp.SSOIdentityLinkCommands, error) {
	return identityapp.NewSSOIdentityLinkCommands(identityapp.SSOIdentityLinkCommandConfig{Transactions: ssoProviderFixtureTransactions(f), Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f ssoProviderFixtureCommands) AuthorizeCreateSSOProvider(ctx context.Context, a domain.Actor, in identityapp.CreateSSOProviderInput) error {
	g, err := f.providerGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateSSOProvider(ctx, a, in)
}
func (f ssoProviderFixtureCommands) AuthorizeUpdateSSOProviderTrustMaterial(ctx context.Context, a domain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) error {
	g, err := f.providerGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeUpdateSSOProviderTrustMaterial(ctx, a, id, in)
}
func (f ssoProviderFixtureCommands) AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.providerGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx, a, id)
}
func (f ssoProviderFixtureCommands) AuthorizeLinkSSOIdentity(ctx context.Context, a domain.Actor, in identityapp.LinkSSOIdentityInput) error {
	g, err := f.linkGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeLinkSSOIdentity(ctx, a, in)
}
func (f ssoProviderFixtureCommands) CreateSSOProvider(ctx context.Context, a domain.Actor, in identityapp.CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	v, err := f.commandLedger(ctx).CreateSSOProvider(ctx, a, app.CreateSSOProviderInput(in))
	return identitydomain.SSOProvider(v), err
}
func (f ssoProviderFixtureCommands) UpdateSSOProviderTrustMaterial(ctx context.Context, a domain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	v, err := f.commandLedger(ctx).UpdateSSOProviderTrustMaterial(ctx, a, id, app.UpdateSSOProviderTrustMaterialInput(in))
	return identitydomain.SSOProvider(v), err
}
func (f ssoProviderFixtureCommands) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOProvider, error) {
	v, err := f.commandLedger(ctx).RefreshSSOProviderOIDCTrustMaterial(ctx, a, id)
	return identitydomain.SSOProvider(v), err
}
func (f ssoProviderFixtureCommands) LinkSSOIdentity(ctx context.Context, a domain.Actor, in identityapp.LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	v, err := f.commandLedger(ctx).LinkSSOIdentity(ctx, a, app.LinkSSOIdentityInput(in))
	return identitydomain.UserIdentityLink(v), err
}
func (s *Server) bindSSOProviderFixturePorts(ledger *app.Ledger) {
	f := ssoProviderFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.ssoProviderCommands.(ssoProviderFixtureCommands); s.ssoProviderCommands == nil || fixture {
		s.ssoProviderCommands = f
	}
	if _, fixture := s.ssoIdentityLinkCommands.(ssoProviderFixtureCommands); s.ssoIdentityLinkCommands == nil || fixture {
		s.ssoIdentityLinkCommands = f
	}
}

var (
	_ SSOProviderCommands     = ssoProviderFixtureCommands{}
	_ SSOIdentityLinkCommands = ssoProviderFixtureCommands{}
)

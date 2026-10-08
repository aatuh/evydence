package httpapi

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Native issuance/revocation share the real isolated command transaction.
// Public exchange owns its native transaction and is not HTTP idempotency.
type ssoSessionFixtureCommands struct {
	catalogFixtureCommands
	credentials identityapp.SessionCredentialManager
	clock       application.Clock
}
type ssoSessionFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type ssoSessionFixtureGuard struct {
	identityapp.SSOSessionWriteReader
	identityapp.SSOSessionRevocationReader
	repos    app.Repositories
	readOnly bool
}

func (f ssoSessionFixtureTransactions) execute(ctx context.Context, run func(context.Context, ssoSessionFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		issue, ok := repos.Identity.(identityapp.SSOSessionWriteReader)
		if !ok {
			return app.ErrValidation
		}
		revoke, ok := repos.Identity.(identityapp.SSOSessionRevocationReader)
		if !ok {
			return app.ErrValidation
		}
		if repos.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, ssoSessionFixtureGuard{issue, revoke, repos, f.readOnly})
	})
}
func (f ssoSessionFixtureTransactions) ExecuteSSOSession(ctx context.Context, run func(context.Context, identityapp.SSOSessionTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx ssoSessionFixtureGuard) error { return run(ctx, tx) })
}
func (f ssoSessionFixtureTransactions) ExecuteSSOSessionRevocation(ctx context.Context, run func(context.Context, identityapp.SSOSessionRevocationTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx ssoSessionFixtureGuard) error { return run(ctx, tx) })
}
func (g ssoSessionFixtureGuard) LockSSOSessionWrites(ctx context.Context, tenant string) error {
	return g.SSOSessionWriteReader.LockSSOSessionWrites(ctx, tenant)
}
func (ssoSessionFixtureGuard) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return identityapp.NewSSOSessionRevocationAuthorizer().Authorize(ctx, a, r)
}
func (g ssoSessionFixtureGuard) InsertSSOSession(ctx context.Context, v identitydomain.SSOSession) error {
	if g.readOnly {
		panic("session preflight inserted session")
	}
	return g.repos.Identity.InsertSSOSession(ctx, domain.SSOSession(v))
}
func (g ssoSessionFixtureGuard) RevokeSSOSessionMetadata(ctx context.Context, v identitydomain.SSOSession, now time.Time) error {
	if g.readOnly {
		panic("session preflight revoked session")
	}
	w, ok := g.repos.Identity.(interface {
		RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error
	})
	if !ok {
		return app.ErrValidation
	}
	return w.RevokeSSOSessionMetadata(ctx, v, now)
}
func (g ssoSessionFixtureGuard) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if g.readOnly {
		panic("session preflight appended audit")
	}
	return (portalFixtureTransaction{repos: g.repos}).AppendAudit(ctx, v)
}
func (ssoSessionFixtureGuard) GenerateSession() (identityapp.Credential, error) {
	panic("session preflight minted credential")
}
func (f ssoSessionFixtureCommands) clockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return clock, ids
}
func (f ssoSessionFixtureCommands) issueCommands(readOnly bool) (*identityapp.SSOSessionCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	c := f.credentials
	if readOnly {
		c = ssoSessionFixtureGuard{}
	} else if c == nil {
		c = fixtureSessionCredentials("test")
	}
	return identityapp.NewSSOSessionCommands(identityapp.SSOSessionCommandConfig{Transactions: ssoSessionFixtureTransactions{f.catalogFixtureCommands, readOnly}, Credentials: c, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f ssoSessionFixtureCommands) revokeCommands(readOnly bool) (*identityapp.SSOSessionRevocationCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	return identityapp.NewSSOSessionRevocationCommands(identityapp.SSOSessionRevocationConfig{Transactions: ssoSessionFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: identityapp.NewSSOSessionRevocationAuthorizer(), Clock: clock, IDs: ids})
}
func (f ssoSessionFixtureCommands) AuthorizeCreateSSOSession(ctx context.Context, a domain.Actor, in identityapp.CreateSSOSessionInput) error {
	g, err := f.issueCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateSSOSession(ctx, a, in)
}
func (f ssoSessionFixtureCommands) AuthorizeRevokeSSOSession(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.revokeCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeRevokeSSOSession(ctx, a, id)
}
func (f ssoSessionFixtureCommands) AuthorizeRevokeCurrentSSOSession(ctx context.Context, a domain.Actor) error {
	g, err := f.revokeCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeRevokeCurrentSSOSession(ctx, a)
}
func (f ssoSessionFixtureCommands) CreateSSOSession(ctx context.Context, a domain.Actor, in identityapp.CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	c, err := f.issueCommands(false)
	if err != nil {
		return identitydomain.SSOSession{}, "", err
	}
	v, secret, err := c.CreateSSOSession(ctx, a, in)
	return v, secret, providerVerificationFixtureError(err)
}
func (f ssoSessionFixtureCommands) RevokeSSOSession(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOSession, error) {
	c, err := f.revokeCommands(false)
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	v, err := c.RevokeSSOSession(ctx, a, id)
	return v, providerVerificationFixtureError(err)
}
func (f ssoSessionFixtureCommands) RevokeCurrentSSOSession(ctx context.Context, a domain.Actor) (identitydomain.SSOSession, error) {
	c, err := f.revokeCommands(false)
	if err != nil {
		return identitydomain.SSOSession{}, err
	}
	v, err := c.RevokeCurrentSSOSession(ctx, a)
	return v, providerVerificationFixtureError(err)
}
func (f ssoSessionFixtureCommands) ExchangeSSOCredential(ctx context.Context, in identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	c, err := f.exchangeCommands()
	if err != nil {
		return identitydomain.ProviderVerification{}, identitydomain.SSOSession{}, "", err
	}
	v, session, secret, err := c.ExchangeSSOCredential(ctx, in)
	return v, session, secret, providerVerificationFixtureError(err)
}
func ssoFixtureVerificationModel(v domain.ProviderVerification) identitydomain.ProviderVerification {
	checks := make([]identitydomain.VerificationCheck, len(v.Checks))
	for i, c := range v.Checks {
		checks[i] = identitydomain.VerificationCheck(c)
	}
	p := identitydomain.VerificationProfileSnapshot(v.Profile)
	p.RequiredChecks = slices.Clone(p.RequiredChecks)
	p.TrustMaterial = slices.Clone(p.TrustMaterial)
	p.Limitations = slices.Clone(p.Limitations)
	return identitydomain.ProviderVerification{ID: v.ID, TenantID: v.TenantID, ProviderType: v.ProviderType, ProviderID: v.ProviderID, Subject: v.Subject, Result: v.Result, Checks: checks, Profile: p, Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func (s *Server) bindSSOSessionFixturePorts(ledger *app.Ledger) {
	f := ssoSessionFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.ssoSessionCommands.(ssoSessionFixtureCommands); fixture {
		old.ledger = ledger
		s.ssoSessionCommands = old
	} else if s.ssoSessionCommands == nil {
		s.ssoSessionCommands = f
	}
	if old, fixture := s.ssoSessionRevocationCommands.(ssoSessionFixtureCommands); fixture {
		old.ledger = ledger
		s.ssoSessionRevocationCommands = old
	} else if s.ssoSessionRevocationCommands == nil {
		s.ssoSessionRevocationCommands = f
	}
	if old, fixture := s.ssoExchangeCommands.(ssoSessionFixtureCommands); fixture {
		old.ledger = ledger
		s.ssoExchangeCommands = old
	} else if s.ssoExchangeCommands == nil {
		s.ssoExchangeCommands = f
	}
	if old, fixture := s.authn.(ssoFixtureAuthenticator); fixture {
		old.ledger = ledger
		s.authn = old
	} else if _, historical := s.authn.(*app.Ledger); historical {
		s.authn = fixtureSessionAuthenticator(ledger, "test", nil)
	}
}

func (s *Server) bindSSOSessionFixtureResources(pepper string, clock application.Clock) {
	credentials := fixtureSessionCredentials(pepper)
	if f, ok := s.ssoSessionCommands.(ssoSessionFixtureCommands); ok {
		f.credentials, f.clock = credentials, clock
		s.ssoSessionCommands = f
	}
	if f, ok := s.ssoSessionRevocationCommands.(ssoSessionFixtureCommands); ok {
		f.clock = clock
		s.ssoSessionRevocationCommands = f
	}
	if f, ok := s.ssoExchangeCommands.(ssoSessionFixtureCommands); ok {
		f.credentials, f.clock = credentials, clock
		s.ssoExchangeCommands = f
	}
	if f, ok := s.authn.(ssoFixtureAuthenticator); ok {
		f.credentials = credentials
		if clock != nil {
			f.clock = clock
		}
		s.authn = f
	}
}

var (
	_ SSOSessionCommands           = ssoSessionFixtureCommands{}
	_ SSOSessionRevocationCommands = ssoSessionFixtureCommands{}
	_ SSOExchangeCommands          = ssoSessionFixtureCommands{}
)

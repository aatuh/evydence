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

// Tests retain real historical issuance/revocation in the isolated command
// clone. Public exchange owns its real transaction and is not HTTP idempotency.
type ssoSessionFixtureCommands struct{ catalogFixtureCommands }
type ssoSessionFixtureTransactions struct{ catalogFixtureCommands }
type ssoSessionFixtureGuard struct {
	identityapp.SSOSessionWriteReader
	identityapp.SSOSessionRevocationReader
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
		return run(ctx, ssoSessionFixtureGuard{issue, revoke})
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
func (ssoSessionFixtureGuard) InsertSSOSession(context.Context, identitydomain.SSOSession) error {
	panic("session preflight inserted session")
}
func (ssoSessionFixtureGuard) RevokeSSOSessionMetadata(context.Context, identitydomain.SSOSession, time.Time) error {
	panic("session preflight revoked session")
}
func (ssoSessionFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("session preflight appended audit")
}
func (ssoSessionFixtureGuard) GenerateSession() (identityapp.Credential, error) {
	panic("session preflight minted credential")
}
func (f ssoSessionFixtureCommands) issueGuard() (*identityapp.SSOSessionCommands, error) {
	return identityapp.NewSSOSessionCommands(identityapp.SSOSessionCommandConfig{Transactions: ssoSessionFixtureTransactions(f), Credentials: ssoSessionFixtureGuard{}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f ssoSessionFixtureCommands) revokeGuard() (*identityapp.SSOSessionRevocationCommands, error) {
	return identityapp.NewSSOSessionRevocationCommands(identityapp.SSOSessionRevocationConfig{Transactions: ssoSessionFixtureTransactions(f), Authorizer: identityapp.NewSSOSessionRevocationAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f ssoSessionFixtureCommands) AuthorizeCreateSSOSession(ctx context.Context, a domain.Actor, in identityapp.CreateSSOSessionInput) error {
	g, err := f.issueGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateSSOSession(ctx, a, in)
}
func (f ssoSessionFixtureCommands) AuthorizeRevokeSSOSession(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.revokeGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeRevokeSSOSession(ctx, a, id)
}
func (f ssoSessionFixtureCommands) AuthorizeRevokeCurrentSSOSession(ctx context.Context, a domain.Actor) error {
	g, err := f.revokeGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeRevokeCurrentSSOSession(ctx, a)
}
func (f ssoSessionFixtureCommands) CreateSSOSession(ctx context.Context, a domain.Actor, in identityapp.CreateSSOSessionInput) (identitydomain.SSOSession, string, error) {
	v, secret, err := f.commandLedger(ctx).CreateSSOSession(ctx, a, app.CreateSSOSessionInput(in))
	return identitydomain.SSOSession(v), secret, err
}
func (f ssoSessionFixtureCommands) RevokeSSOSession(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOSession, error) {
	v, err := f.commandLedger(ctx).RevokeSSOSession(ctx, a, id)
	return identitydomain.SSOSession(v), err
}
func (f ssoSessionFixtureCommands) RevokeCurrentSSOSession(ctx context.Context, a domain.Actor) (identitydomain.SSOSession, error) {
	v, err := f.commandLedger(ctx).RevokeCurrentSSOSession(ctx, a)
	return identitydomain.SSOSession(v), err
}
func (f ssoSessionFixtureCommands) ExchangeSSOCredential(ctx context.Context, in identityapp.ExchangeSSOCredentialInput) (identitydomain.ProviderVerification, identitydomain.SSOSession, string, error) {
	v, session, secret, err := f.commandLedger(ctx).ExchangeSSOCredential(ctx, app.ExchangeSSOCredentialInput(in))
	return ssoFixtureVerificationModel(v), identitydomain.SSOSession(session), secret, err
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
	f := ssoSessionFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.ssoSessionCommands.(ssoSessionFixtureCommands); s.ssoSessionCommands == nil || fixture {
		s.ssoSessionCommands = f
	}
	if _, fixture := s.ssoSessionRevocationCommands.(ssoSessionFixtureCommands); s.ssoSessionRevocationCommands == nil || fixture {
		s.ssoSessionRevocationCommands = f
	}
	if _, fixture := s.ssoExchangeCommands.(ssoSessionFixtureCommands); s.ssoExchangeCommands == nil || fixture {
		s.ssoExchangeCommands = f
	}
}

var (
	_ SSOSessionCommands           = ssoSessionFixtureCommands{}
	_ SSOSessionRevocationCommands = ssoSessionFixtureCommands{}
	_ SSOExchangeCommands          = ssoSessionFixtureCommands{}
)

package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// Test-only composition of the real focused services and memory repositories.
// Token consumption owns its transaction, including committed semantic denials.
// No test credential configuration or memory check is production/SQL evidence.
type portalFixturePorts struct {
	catalogFixtureCommands
	clock application.Clock
}
type portalFixtureRepository interface {
	packageapp.PortalAccessWriteReader
	packageapp.PortalAccessLookup
	packagequery.PortalAccessReader
	ReadPortalAccessForToken(context.Context, string, string) (packagedomain.CustomerPortalAccess, error)
	InsertFocusedPortalAccess(context.Context, packagedomain.CustomerPortalAccess) error
	RevokeFocusedPortalAccess(context.Context, string, string, time.Time) error
	UpdateFocusedPortalTokenAccess(context.Context, packagedomain.CustomerPortalAccess, packagedomain.CustomerPortalAccess) error
}
type portalFixtureTransactions struct {
	portalFixturePorts
	readOnly bool
}
type portalFixtureTransaction struct {
	portalFixtureRepository
	repos    app.Repositories
	readOnly bool
}
type portalFixtureCredentials struct {
	c *identityapp.HMACAuthenticationCredentials
}

func portalFixtureError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return packageapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return packageapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return packageapp.ErrConflict
	case errors.Is(err, app.ErrUnauthorized):
		return application.ErrUnauthorized
	case errors.Is(err, app.ErrForbidden):
		return application.ErrForbidden
	default:
		return err
	}
}
func (f portalFixturePorts) fixtureClock() application.Clock {
	if f.clock != nil {
		return f.clock
	}
	return application.ClockFunc(time.Now)
}
func (c portalFixtureCredentials) GeneratePortalCredential() (packageapp.PortalCredential, error) {
	v, err := c.c.GeneratePortalAccess()
	return packageapp.PortalCredential{Secret: v.Secret, Prefix: v.Prefix, Hash: v.Hash}, err
}
func (c portalFixtureCredentials) HashPortalToken(v string) string    { return c.c.Hash(v) }
func (c portalFixtureCredentials) EqualPortalHashes(a, b string) bool { return c.c.Equal(a, b) }

type portalFixtureGuardCredentials struct{}

func (portalFixtureGuardCredentials) GeneratePortalCredential() (packageapp.PortalCredential, error) {
	panic("portal preflight issued a credential")
}
func (f portalFixturePorts) accessCommands(readOnly bool) (*packageapp.PortalAccessCommands, error) {
	c, err := identityapp.NewHMACAuthenticationCredentials("portal-fixture-pepper")
	if err != nil {
		return nil, err
	}
	var credentials packageapp.PortalCredentialIssuer = portalFixtureCredentials{c}
	clock, ids := f.fixtureClock(), application.IDGenerator(application.IDGeneratorFunc(application.NewID))
	if readOnly {
		credentials = portalFixtureGuardCredentials{}
		clock, ids = application.ClockFunc(membershipFixtureClock), application.IDGeneratorFunc(membershipFixtureID)
	}
	return packageapp.NewPortalAccessCommands(packageapp.PortalAccessCommandConfig{Transactions: portalFixtureTransactions{f, readOnly}, Credentials: credentials, Authorizer: packagequery.NewPortalAccessWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f portalFixturePorts) AuthorizeCreatePortalAccess(ctx context.Context, a domain.Actor, in packageapp.CreatePortalAccessInput) error {
	c, err := f.accessCommands(true)
	if err != nil {
		return err
	}
	return c.AuthorizeCreatePortalAccess(ctx, a, in)
}
func (f portalFixturePorts) AuthorizeRevokePortalAccess(ctx context.Context, a domain.Actor, id string) error {
	c, err := f.accessCommands(true)
	if err != nil {
		return err
	}
	return c.AuthorizeRevokePortalAccess(ctx, a, id)
}
func (f portalFixturePorts) CreatePortalAccess(ctx context.Context, a domain.Actor, in packageapp.CreatePortalAccessInput) (packagedomain.CustomerPortalAccess, string, error) {
	c, err := f.accessCommands(false)
	if err != nil {
		return packagedomain.CustomerPortalAccess{}, "", err
	}
	return c.CreatePortalAccess(ctx, a, in)
}
func (f portalFixturePorts) RevokePortalAccess(ctx context.Context, a domain.Actor, id string) (packagedomain.CustomerPortalAccess, error) {
	c, err := f.accessCommands(false)
	if err != nil {
		return packagedomain.CustomerPortalAccess{}, err
	}
	return c.RevokePortalAccess(ctx, a, id)
}
func (f portalFixturePorts) LookupPortalAccess(ctx context.Context, prefix string) (packageapp.PortalAccessCandidate, error) {
	var out packageapp.PortalAccessCandidate
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(portalFixtureRepository)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.LookupPortalAccess(ctx, prefix)
		return err
	})
	return out, portalFixtureError(err)
}
func (f portalFixturePorts) AccessPortalPackage(ctx context.Context, token string, in packageapp.PortalAcceptanceInput, download bool) (packagedomain.CustomerSecurityPackage, error) {
	c, err := identityapp.NewHMACAuthenticationCredentials("portal-fixture-pepper")
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	commands, err := packageapp.NewPortalTokenCommands(packageapp.PortalTokenCommandConfig{Lookup: f, Transactions: portalFixtureTransactions{f, false}, Credentials: portalFixtureCredentials{c}, Clock: f.fixtureClock(), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	return commands.AccessPortalPackage(ctx, token, in, download)
}
func (f portalFixtureTransactions) execute(ctx context.Context, fn func(context.Context, portalFixtureTransaction) error) error {
	return portalFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(portalFixtureRepository)
		if !ok || repos.Packages == nil || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, portalFixtureTransaction{r, repos, f.readOnly})
	}))
}
func (f portalFixtureTransactions) ExecutePortalAccess(ctx context.Context, _ string, fn func(context.Context, packageapp.PortalAccessTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx portalFixtureTransaction) error { return fn(ctx, tx) })
}
func (f portalFixtureTransactions) ExecutePortalToken(ctx context.Context, _ string, fn func(context.Context, packageapp.PortalTokenTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx portalFixtureTransaction) error { return fn(ctx, tx) })
}
func (t portalFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return packagequery.NewPortalAccessWriteAuthorizer().Authorize(ctx, a, r)
}
func (t portalFixtureTransaction) ReadPortalPackageScope(ctx context.Context, tenant, id string) (packageapp.PortalPackageScope, error) {
	v, err := t.portalFixtureRepository.ReadPortalPackageScope(ctx, tenant, id)
	return v, portalFixtureError(err)
}
func (t portalFixtureTransaction) ReadPortalAccessForRevocation(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	v, err := t.portalFixtureRepository.ReadPortalAccessForRevocation(ctx, tenant, id)
	return v, portalFixtureError(err)
}
func (t portalFixtureTransaction) ReadPortalAccessForToken(ctx context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	v, err := t.portalFixtureRepository.ReadPortalAccessForToken(ctx, tenant, id)
	return v, portalFixtureError(err)
}
func (t portalFixtureTransaction) InsertPortalAccess(ctx context.Context, v packagedomain.CustomerPortalAccess) error {
	if t.readOnly {
		panic("portal preflight inserted a credential")
	}
	return portalFixtureError(t.InsertFocusedPortalAccess(ctx, v))
}
func (t portalFixtureTransaction) RevokePortalAccess(ctx context.Context, tenant, id string, at time.Time) error {
	if t.readOnly {
		panic("portal preflight revoked a credential")
	}
	return portalFixtureError(t.RevokeFocusedPortalAccess(ctx, tenant, id, at))
}
func (t portalFixtureTransaction) GetPortalPackageForUpdate(ctx context.Context, tenant, id string) (packagedomain.CustomerSecurityPackage, error) {
	if t.readOnly {
		panic("portal preflight read private package content")
	}
	v, err := t.repos.Packages.GetCustomerSecurityPackageForUpdate(ctx, tenant, id)
	return packagedomain.CustomerSecurityPackage(v), portalFixtureError(err)
}
func (t portalFixtureTransaction) UpdatePortalTokenAccess(ctx context.Context, old, v packagedomain.CustomerPortalAccess) error {
	if t.readOnly {
		panic("portal preflight changed counters or NDA acceptance")
	}
	return portalFixtureError(t.UpdateFocusedPortalTokenAccess(ctx, old, v))
}
func (t portalFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.readOnly {
		panic("portal preflight wrote an audit")
	}
	v, err := t.repos.Audit.Append(ctx, domain.AuditChainEntry{ID: e.ID, TenantID: e.TenantID, EntryType: e.EntryType, SubjectType: e.SubjectType, SubjectID: e.SubjectID, ActorType: e.ActorType, ActorID: e.ActorID, OccurredAt: e.OccurredAt, PayloadHash: e.PayloadHash, SignatureRef: e.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	return application.AuditReceipt{ID: v.ID}, portalFixtureError(err)
}
func (f portalFixturePorts) PagePortalAccess(ctx context.Context, request packagequery.PortalAccessPageRequest) (appquery.Result[packagequery.PortalAccessPoint], error) {
	var out appquery.Result[packagequery.PortalAccessPoint]
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		r, ok := repos.Identity.(portalFixtureRepository)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = r.PagePortalAccess(ctx, request)
		return err
	})
	return out, portalFixtureError(err)
}
func (f portalFixturePorts) ListPage(ctx context.Context, a domain.Actor, id string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[packagedomain.CustomerPortalAccess], error) {
	q, err := packagequery.NewPortalAccess(f)
	if err != nil {
		return appquery.Result[packagedomain.CustomerPortalAccess]{}, err
	}
	return q.ListPage(ctx, a, id, page, after)
}
func (s *Server) bindPortalFixturePorts(ledger *app.Ledger) {
	f := portalFixturePorts{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.portalAccessCommands.(portalFixturePorts); s.portalAccessCommands == nil || fixture {
		s.portalAccessCommands = f
	}
	if _, fixture := s.portalTokenCommands.(portalFixturePorts); s.portalTokenCommands == nil || fixture {
		s.portalTokenCommands = f
	}
	if _, fixture := s.portalAccessQuery.(portalFixturePorts); s.portalAccessQuery == nil || fixture {
		s.portalAccessQuery = f
	}
}

var (
	_ PortalAccessCommands = portalFixturePorts{}
	_ PortalTokenCommands  = portalFixturePorts{}
	_ PortalAccessQuery    = portalFixturePorts{}
)

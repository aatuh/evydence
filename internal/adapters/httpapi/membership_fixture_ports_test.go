package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Actual focused commands use the fixture's active repositories, never its
// organization/user/role caches. Read-only guards cannot perform effects.
type membershipFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type membershipFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type membershipFixtureGuard struct {
	identityapp.MembershipWriteReader
	identityapp.RoleBindingWriteReader
	repos    app.Repositories
	readOnly bool
}

func (f membershipFixtureTransactions) execute(ctx context.Context, run func(context.Context, membershipFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		members, ok := repos.Identity.(identityapp.MembershipWriteReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		roles, ok := repos.Identity.(identityapp.RoleBindingWriteReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, membershipFixtureGuard{members, roles, repos, f.readOnly})
	})
}
func (f membershipFixtureTransactions) ExecuteMembership(ctx context.Context, run func(context.Context, identityapp.MembershipTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx membershipFixtureGuard) error { return run(ctx, tx) })
}
func (f membershipFixtureTransactions) ExecuteRoleBinding(ctx context.Context, run func(context.Context, identityapp.RoleBindingTransaction) error) error {
	return f.execute(ctx, func(ctx context.Context, tx membershipFixtureGuard) error { return run(ctx, tx) })
}
func (membershipFixtureGuard) Authorize(ctx context.Context, a domain.Actor, request application.AuthorizationRequest) error {
	return identityapp.NewMembershipWriteAuthorizer().Authorize(ctx, a, request)
}
func (g membershipFixtureGuard) InsertOrganization(ctx context.Context, v identitydomain.Organization) error {
	if g.readOnly {
		panic("membership guard inserted organization")
	}
	return g.repos.Identity.InsertOrganization(ctx, domain.Organization(v))
}
func (g membershipFixtureGuard) InsertHumanUser(ctx context.Context, v identitydomain.HumanUser) error {
	if g.readOnly {
		panic("membership guard inserted user")
	}
	return g.repos.Identity.InsertHumanUser(ctx, domain.HumanUser(v))
}
func (g membershipFixtureGuard) DeactivateHumanUser(ctx context.Context, v identitydomain.HumanUser) error {
	if g.readOnly {
		panic("membership guard deactivated user")
	}
	return g.repos.Identity.DeactivateHumanUser(ctx, domain.HumanUser(v))
}
func (g membershipFixtureGuard) InsertRoleBinding(ctx context.Context, v identitydomain.RoleBinding) error {
	if g.readOnly {
		panic("membership guard inserted role")
	}
	return g.repos.Identity.InsertRoleBinding(ctx, domain.RoleBinding(v))
}
func (g membershipFixtureGuard) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if g.readOnly {
		panic("membership guard appended audit")
	}
	return (portalFixtureTransaction{repos: g.repos}).AppendAudit(ctx, v)
}
func membershipFixtureClock() time.Time { panic("membership guard read clock") }
func membershipFixtureID(string) string { panic("membership guard allocated ID") }
func (f membershipFixtureCommands) clockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly && f.clock != nil {
		clock = f.clock
	}
	return clock, ids
}
func (f membershipFixtureCommands) membershipCommands(readOnly bool) (*identityapp.MembershipCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	return identityapp.NewMembershipCommands(identityapp.MembershipCommandConfig{Transactions: membershipFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f membershipFixtureCommands) roleCommands(readOnly bool) (*identityapp.RoleBindingCommands, error) {
	clock, ids := f.clockIDs(readOnly)
	return identityapp.NewRoleBindingCommands(identityapp.RoleBindingCommandConfig{Transactions: membershipFixtureTransactions{f.catalogFixtureCommands, readOnly}, Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: clock, IDs: ids})
}
func (f membershipFixtureCommands) AuthorizeCreateOrganization(ctx context.Context, a domain.Actor, in identityapp.CreateOrganizationInput) error {
	g, err := f.membershipCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateOrganization(ctx, a, in)
}
func (f membershipFixtureCommands) AuthorizeCreateUser(ctx context.Context, a domain.Actor, in identityapp.CreateUserInput) error {
	g, err := f.membershipCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateUser(ctx, a, in)
}
func (f membershipFixtureCommands) AuthorizeDeactivateUser(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.membershipCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeDeactivateUser(ctx, a, id)
}
func (f membershipFixtureCommands) AuthorizeCreateRoleBinding(ctx context.Context, a domain.Actor, in identityapp.CreateRoleBindingInput) error {
	g, err := f.roleCommands(true)
	if err != nil {
		return err
	}
	return g.AuthorizeCreateRoleBinding(ctx, a, in)
}
func (f membershipFixtureCommands) CreateOrganization(ctx context.Context, a domain.Actor, in identityapp.CreateOrganizationInput) (identitydomain.Organization, error) {
	c, err := f.membershipCommands(false)
	if err != nil {
		return identitydomain.Organization{}, err
	}
	v, err := c.CreateOrganization(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (f membershipFixtureCommands) CreateUser(ctx context.Context, a domain.Actor, in identityapp.CreateUserInput) (identitydomain.HumanUser, error) {
	c, err := f.membershipCommands(false)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	v, err := c.CreateUser(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (f membershipFixtureCommands) DeactivateUser(ctx context.Context, a domain.Actor, id string) (identitydomain.HumanUser, error) {
	c, err := f.membershipCommands(false)
	if err != nil {
		return identitydomain.HumanUser{}, err
	}
	v, err := c.DeactivateUser(ctx, a, id)
	return v, providerVerificationFixtureError(err)
}
func (f membershipFixtureCommands) CreateRoleBinding(ctx context.Context, a domain.Actor, in identityapp.CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	c, err := f.roleCommands(false)
	if err != nil {
		return identitydomain.RoleBinding{}, err
	}
	v, err := c.CreateRoleBinding(ctx, a, in)
	return v, providerVerificationFixtureError(err)
}
func (s *Server) bindMembershipFixturePorts(ledger *app.Ledger) {
	f := membershipFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.membershipCommands.(membershipFixtureCommands); fixture {
		old.ledger = ledger
		s.membershipCommands = old
	} else if s.membershipCommands == nil {
		s.membershipCommands = f
	}
	if old, fixture := s.roleBindingCommands.(membershipFixtureCommands); fixture {
		old.ledger = ledger
		s.roleBindingCommands = old
	} else if s.roleBindingCommands == nil {
		s.roleBindingCommands = f
	}
}

var (
	_ MembershipCommands  = membershipFixtureCommands{}
	_ RoleBindingCommands = membershipFixtureCommands{}
)

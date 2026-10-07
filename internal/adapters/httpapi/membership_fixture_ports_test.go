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

// Tests retain real isolated historical writes; preflight uses actual focused
// Identity command algorithms on transaction-owned references. No runtime
// Ledger compatibility path or no-op authorization is added.
type membershipFixtureCommands struct{ catalogFixtureCommands }
type membershipFixtureTransactions struct{ catalogFixtureCommands }
type membershipFixtureGuard struct {
	identityapp.MembershipWriteReader
	identityapp.RoleBindingWriteReader
}

func (f membershipFixtureTransactions) execute(ctx context.Context, run func(context.Context, membershipFixtureGuard) error) error {
	return f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		members, ok := repos.Identity.(identityapp.MembershipWriteReader)
		if !ok {
			return app.ErrValidation
		}
		roles, ok := repos.Identity.(identityapp.RoleBindingWriteReader)
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, membershipFixtureGuard{members, roles})
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
func (membershipFixtureGuard) InsertOrganization(context.Context, identitydomain.Organization) error {
	panic("membership guard inserted organization")
}
func (membershipFixtureGuard) InsertHumanUser(context.Context, identitydomain.HumanUser) error {
	panic("membership guard inserted user")
}
func (membershipFixtureGuard) DeactivateHumanUser(context.Context, identitydomain.HumanUser) error {
	panic("membership guard deactivated user")
}
func (membershipFixtureGuard) InsertRoleBinding(context.Context, identitydomain.RoleBinding) error {
	panic("membership guard inserted role")
}
func (membershipFixtureGuard) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("membership guard appended audit")
}
func membershipFixtureClock() time.Time { panic("membership guard read clock") }
func membershipFixtureID(string) string { panic("membership guard allocated ID") }
func (f membershipFixtureCommands) membershipGuard() (*identityapp.MembershipCommands, error) {
	return identityapp.NewMembershipCommands(identityapp.MembershipCommandConfig{Transactions: membershipFixtureTransactions(f), Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f membershipFixtureCommands) roleGuard() (*identityapp.RoleBindingCommands, error) {
	return identityapp.NewRoleBindingCommands(identityapp.RoleBindingCommandConfig{Transactions: membershipFixtureTransactions(f), Authorizer: identityapp.NewMembershipWriteAuthorizer(), Clock: application.ClockFunc(membershipFixtureClock), IDs: application.IDGeneratorFunc(membershipFixtureID)})
}
func (f membershipFixtureCommands) AuthorizeCreateOrganization(ctx context.Context, a domain.Actor, in identityapp.CreateOrganizationInput) error {
	g, err := f.membershipGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateOrganization(ctx, a, in)
}
func (f membershipFixtureCommands) AuthorizeCreateUser(ctx context.Context, a domain.Actor, in identityapp.CreateUserInput) error {
	g, err := f.membershipGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateUser(ctx, a, in)
}
func (f membershipFixtureCommands) AuthorizeDeactivateUser(ctx context.Context, a domain.Actor, id string) error {
	g, err := f.membershipGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeDeactivateUser(ctx, a, id)
}
func (f membershipFixtureCommands) AuthorizeCreateRoleBinding(ctx context.Context, a domain.Actor, in identityapp.CreateRoleBindingInput) error {
	g, err := f.roleGuard()
	if err != nil {
		return err
	}
	return g.AuthorizeCreateRoleBinding(ctx, a, in)
}
func (f membershipFixtureCommands) CreateOrganization(ctx context.Context, a domain.Actor, in identityapp.CreateOrganizationInput) (identitydomain.Organization, error) {
	v, err := f.commandLedger(ctx).CreateOrganization(ctx, a, app.CreateOrganizationInput(in))
	return identitydomain.Organization(v), err
}
func (f membershipFixtureCommands) CreateUser(ctx context.Context, a domain.Actor, in identityapp.CreateUserInput) (identitydomain.HumanUser, error) {
	v, err := f.commandLedger(ctx).CreateUser(ctx, a, app.CreateUserInput(in))
	return identitydomain.HumanUser(v), err
}
func (f membershipFixtureCommands) DeactivateUser(ctx context.Context, a domain.Actor, id string) (identitydomain.HumanUser, error) {
	v, err := f.commandLedger(ctx).DeactivateUser(ctx, a, id)
	return identitydomain.HumanUser(v), err
}
func (f membershipFixtureCommands) CreateRoleBinding(ctx context.Context, a domain.Actor, in identityapp.CreateRoleBindingInput) (identitydomain.RoleBinding, error) {
	v, err := f.commandLedger(ctx).CreateRoleBinding(ctx, a, app.CreateRoleBindingInput(in))
	return identitydomain.RoleBinding(v), err
}
func (s *Server) bindMembershipFixturePorts(ledger *app.Ledger) {
	f := membershipFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.membershipCommands.(membershipFixtureCommands); s.membershipCommands == nil || fixture {
		s.membershipCommands = f
	}
	if _, fixture := s.roleBindingCommands.(membershipFixtureCommands); s.roleBindingCommands == nil || fixture {
		s.roleBindingCommands = f
	}
}

var (
	_ MembershipCommands  = membershipFixtureCommands{}
	_ RoleBindingCommands = membershipFixtureCommands{}
)

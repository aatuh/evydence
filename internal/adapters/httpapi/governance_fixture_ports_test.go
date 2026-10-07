package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Only HTTP tests use this bridge. Preflight executes the actual native guard
// algorithm on focused repositories; writes retain the isolated fixture clone.
type governanceFixtureCommands struct{ catalogFixtureCommands }

// Only tests exercising real governance writes opt into these repositories;
// unrelated legacy fixtures retain their previous backend/serialization.
func governanceTestServer(t *testing.T) (*Server, string) {
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

type governanceFixtureTransactions struct {
	catalogFixtureCommands
	authorizer application.Authorizer
}

type governanceFixtureTransaction struct {
	riskapp.WaiverCommandReader
	riskapp.ExceptionCommandReader
	riskapp.ApprovalReader
	application.Authorizer
	governance app.GovernanceRepository
	decisions  app.DecisionRepository
	audit      app.AuditRepository
}

func (r governanceFixtureTransactions) execute(ctx context.Context, run func(context.Context, governanceFixtureTransaction) error) error {
	return r.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, repos app.Repositories) error {
		waivers, ok := repos.Governance.(riskapp.WaiverCommandReader)
		if !ok {
			return app.ErrValidation
		}
		exceptions, ok := repos.Decisions.(riskapp.ExceptionCommandReader)
		if !ok {
			return app.ErrValidation
		}
		approvals, ok := repos.Governance.(riskapp.ApprovalReader)
		if !ok || repos.Audit == nil || r.authorizer == nil || run == nil {
			return app.ErrValidation
		}
		return run(ctx, governanceFixtureTransaction{WaiverCommandReader: waivers, ExceptionCommandReader: exceptions, ApprovalReader: approvals, Authorizer: r.authorizer, governance: repos.Governance, decisions: repos.Decisions, audit: repos.Audit})
	})
}

func (r governanceFixtureTransactions) ExecuteWaiver(ctx context.Context, run func(context.Context, riskapp.WaiverTransaction) error) error {
	return r.execute(ctx, func(ctx context.Context, tx governanceFixtureTransaction) error { return run(ctx, tx) })
}
func (r governanceFixtureTransactions) ExecuteException(ctx context.Context, run func(context.Context, riskapp.ExceptionTransaction) error) error {
	return r.execute(ctx, func(ctx context.Context, tx governanceFixtureTransaction) error { return run(ctx, tx) })
}
func (r governanceFixtureTransactions) ExecuteApproval(ctx context.Context, run func(context.Context, riskapp.ApprovalTransaction) error) error {
	return r.execute(ctx, func(ctx context.Context, tx governanceFixtureTransaction) error { return run(ctx, tx) })
}

// Even the transaction bridge has real writes/audits, not placeholder effects.
// Native authorization never invokes them, clocks, IDs or full-record reads.
func (t governanceFixtureTransaction) InsertWaiver(ctx context.Context, value riskdomain.Waiver) error {
	return t.governance.InsertWaiver(ctx, domain.Waiver(value))
}
func (t governanceFixtureTransaction) ApproveWaiver(ctx context.Context, value riskdomain.Waiver) error {
	return t.governance.ApproveWaiver(ctx, domain.Waiver(value))
}
func (t governanceFixtureTransaction) InsertException(ctx context.Context, value riskdomain.Exception) error {
	return t.decisions.InsertException(ctx, domain.Exception(value))
}
func (t governanceFixtureTransaction) ApproveException(ctx context.Context, value riskdomain.Exception) error {
	return t.decisions.ApproveException(ctx, domain.Exception(value))
}
func (t governanceFixtureTransaction) InsertApprovalRecord(ctx context.Context, value riskdomain.ApprovalRecord) error {
	return t.governance.InsertApprovalRecord(ctx, domain.ApprovalRecord(value))
}
func (t governanceFixtureTransaction) AppendAudit(ctx context.Context, value application.AuditEvent) (application.AuditReceipt, error) {
	entry, err := t.audit.Append(ctx, domain.AuditChainEntry{ID: value.ID, TenantID: value.TenantID, EntryType: value.EntryType, SubjectType: value.SubjectType, SubjectID: value.SubjectID, ActorType: value.ActorType, ActorID: value.ActorID, OccurredAt: value.OccurredAt, PayloadHash: value.PayloadHash, SignatureRef: value.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	return application.AuditReceipt{ID: entry.ID}, err
}

func governanceFixtureGuardClock() time.Time { panic("governance replay guard read a clock") }
func governanceFixtureGuardID(string) string { panic("governance replay guard allocated an ID") }

func (f governanceFixtureCommands) waiverGuard() (*riskapp.WaiverCommands, error) {
	authorizer := riskapp.NewWaiverWriteAuthorizer()
	return riskapp.NewWaiverCommands(riskapp.WaiverCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: application.ClockFunc(governanceFixtureGuardClock), IDs: application.IDGeneratorFunc(governanceFixtureGuardID)})
}
func (f governanceFixtureCommands) exceptionGuard() (*riskapp.ExceptionCommands, error) {
	authorizer := riskapp.NewExceptionWriteAuthorizer()
	return riskapp.NewExceptionCommands(riskapp.ExceptionCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: application.ClockFunc(governanceFixtureGuardClock), IDs: application.IDGeneratorFunc(governanceFixtureGuardID)})
}
func (f governanceFixtureCommands) approvalGuard() (*riskapp.ApprovalCommands, error) {
	authorizer := riskapp.NewApprovalWriteAuthorizer()
	return riskapp.NewApprovalCommands(riskapp.ApprovalCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: application.ClockFunc(governanceFixtureGuardClock), IDs: application.IDGeneratorFunc(governanceFixtureGuardID)})
}

func (f governanceFixtureCommands) AuthorizeCreateWaiver(ctx context.Context, actor domain.Actor, input riskapp.CreateWaiverInput) error {
	guard, err := f.waiverGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateWaiver(ctx, actor, input)
}
func (f governanceFixtureCommands) AuthorizeApproveWaiver(ctx context.Context, actor domain.Actor, id string) error {
	guard, err := f.waiverGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeApproveWaiver(ctx, actor, id)
}
func (f governanceFixtureCommands) AuthorizeCreateException(ctx context.Context, actor domain.Actor, input riskapp.CreateExceptionInput) error {
	guard, err := f.exceptionGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateException(ctx, actor, input)
}
func (f governanceFixtureCommands) AuthorizeApproveException(ctx context.Context, actor domain.Actor, id string) error {
	guard, err := f.exceptionGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeApproveException(ctx, actor, id)
}
func (f governanceFixtureCommands) AuthorizeApproval(ctx context.Context, actor domain.Actor, input riskapp.CreateApprovalInput) error {
	guard, err := f.approvalGuard()
	if err != nil {
		return err
	}
	return guard.AuthorizeApproval(ctx, actor, input)
}

func (f governanceFixtureCommands) CreateWaiver(ctx context.Context, actor domain.Actor, input riskapp.CreateWaiverInput) (riskdomain.Waiver, error) {
	value, err := f.commandLedger(ctx).CreateWaiver(ctx, actor, app.CreateWaiverInput(input))
	return riskdomain.Waiver(value), err
}
func (f governanceFixtureCommands) ApproveWaiver(ctx context.Context, actor domain.Actor, id string) (riskdomain.Waiver, error) {
	value, err := f.commandLedger(ctx).ApproveWaiver(ctx, actor, id)
	return riskdomain.Waiver(value), err
}
func (f governanceFixtureCommands) CreateException(ctx context.Context, actor domain.Actor, input riskapp.CreateExceptionInput) (riskdomain.Exception, error) {
	value, err := f.commandLedger(ctx).CreateException(ctx, actor, app.CreateExceptionInput(input))
	return riskdomain.Exception(value), err
}
func (f governanceFixtureCommands) ApproveException(ctx context.Context, actor domain.Actor, id string) (riskdomain.Exception, error) {
	value, err := f.commandLedger(ctx).ApproveException(ctx, actor, id)
	return riskdomain.Exception(value), err
}
func (f governanceFixtureCommands) CreateApprovalRecord(ctx context.Context, actor domain.Actor, input riskapp.CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	value, err := f.commandLedger(ctx).CreateApprovalRecord(ctx, actor, app.CreateApprovalInput(input))
	return riskdomain.ApprovalRecord(value), err
}

func (s *Server) bindGovernanceFixturePorts(ledger *app.Ledger) {
	commands := governanceFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.waiverCommands.(governanceFixtureCommands); s.waiverCommands == nil || fixture {
		s.waiverCommands = commands
	}
	if _, fixture := s.exceptionCommands.(governanceFixtureCommands); s.exceptionCommands == nil || fixture {
		s.exceptionCommands = commands
	}
	if _, fixture := s.approvalCommands.(governanceFixtureCommands); s.approvalCommands == nil || fixture {
		s.approvalCommands = commands
	}
}

var (
	_ WaiverCommands    = governanceFixtureCommands{}
	_ ExceptionCommands = governanceFixtureCommands{}
	_ ApprovalCommands  = governanceFixtureCommands{}
)

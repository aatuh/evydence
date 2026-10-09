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

// Only tests use this composition. Both preflight and fresh writes execute the
// actual Risk algorithms on transaction-owned repositories, never Ledger methods.
type governanceFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
	ids   application.IDGenerator
}

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
	server.bindRepositoryIngestionFixtureScope()
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
	if ctx == nil || run == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (f governanceFixtureCommands) clockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	if readOnly {
		return application.ClockFunc(governanceFixtureGuardClock), application.IDGeneratorFunc(governanceFixtureGuardID)
	}
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	if f.ids != nil {
		ids = f.ids
	}
	return clock, ids
}

func (f governanceFixtureCommands) nativeWaiver(readOnly bool) (*riskapp.WaiverCommands, error) {
	authorizer := riskapp.NewWaiverWriteAuthorizer()
	clock, ids := f.clockIDs(readOnly)
	return riskapp.NewWaiverCommands(riskapp.WaiverCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: clock, IDs: ids})
}
func (f governanceFixtureCommands) nativeException(readOnly bool) (*riskapp.ExceptionCommands, error) {
	authorizer := riskapp.NewExceptionWriteAuthorizer()
	clock, ids := f.clockIDs(readOnly)
	return riskapp.NewExceptionCommands(riskapp.ExceptionCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: clock, IDs: ids})
}
func (f governanceFixtureCommands) nativeApproval(readOnly bool) (*riskapp.ApprovalCommands, error) {
	authorizer := riskapp.NewApprovalWriteAuthorizer()
	clock, ids := f.clockIDs(readOnly)
	return riskapp.NewApprovalCommands(riskapp.ApprovalCommandConfig{Authorizer: authorizer, Transactions: governanceFixtureTransactions{f.catalogFixtureCommands, authorizer}, Clock: clock, IDs: ids})
}

func (f governanceFixtureCommands) AuthorizeCreateWaiver(ctx context.Context, actor domain.Actor, input riskapp.CreateWaiverInput) error {
	guard, err := f.nativeWaiver(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateWaiver(ctx, actor, input)
}
func (f governanceFixtureCommands) AuthorizeApproveWaiver(ctx context.Context, actor domain.Actor, id string) error {
	guard, err := f.nativeWaiver(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeApproveWaiver(ctx, actor, id)
}
func (f governanceFixtureCommands) AuthorizeCreateException(ctx context.Context, actor domain.Actor, input riskapp.CreateExceptionInput) error {
	guard, err := f.nativeException(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateException(ctx, actor, input)
}
func (f governanceFixtureCommands) AuthorizeApproveException(ctx context.Context, actor domain.Actor, id string) error {
	guard, err := f.nativeException(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeApproveException(ctx, actor, id)
}
func (f governanceFixtureCommands) AuthorizeApproval(ctx context.Context, actor domain.Actor, input riskapp.CreateApprovalInput) error {
	guard, err := f.nativeApproval(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeApproval(ctx, actor, input)
}

func (f governanceFixtureCommands) CreateWaiver(ctx context.Context, actor domain.Actor, input riskapp.CreateWaiverInput) (riskdomain.Waiver, error) {
	commands, err := f.nativeWaiver(false)
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return commands.CreateWaiver(ctx, actor, input)
}
func (f governanceFixtureCommands) ApproveWaiver(ctx context.Context, actor domain.Actor, id string) (riskdomain.Waiver, error) {
	commands, err := f.nativeWaiver(false)
	if err != nil {
		return riskdomain.Waiver{}, err
	}
	return commands.ApproveWaiver(ctx, actor, id)
}
func (f governanceFixtureCommands) CreateException(ctx context.Context, actor domain.Actor, input riskapp.CreateExceptionInput) (riskdomain.Exception, error) {
	commands, err := f.nativeException(false)
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return commands.CreateException(ctx, actor, input)
}
func (f governanceFixtureCommands) ApproveException(ctx context.Context, actor domain.Actor, id string) (riskdomain.Exception, error) {
	commands, err := f.nativeException(false)
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return commands.ApproveException(ctx, actor, id)
}
func (f governanceFixtureCommands) CreateApprovalRecord(ctx context.Context, actor domain.Actor, input riskapp.CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	commands, err := f.nativeApproval(false)
	if err != nil {
		return riskdomain.ApprovalRecord{}, err
	}
	return commands.CreateApprovalRecord(ctx, actor, input)
}

func (s *Server) bindGovernanceFixturePorts(ledger *app.Ledger) {
	if commands, fixture := s.waiverCommands.(governanceFixtureCommands); s.waiverCommands == nil || fixture {
		commands.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.waiverCommands = commands
	}
	if commands, fixture := s.exceptionCommands.(governanceFixtureCommands); s.exceptionCommands == nil || fixture {
		commands.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.exceptionCommands = commands
	}
	if commands, fixture := s.approvalCommands.(governanceFixtureCommands); s.approvalCommands == nil || fixture {
		commands.catalogFixtureCommands = catalogFixtureCommands{ledger: ledger}
		s.approvalCommands = commands
	}
}

func (s *Server) bindGovernanceFixtureResources(clock application.Clock, ids application.IDGenerator) {
	if f, ok := s.waiverCommands.(governanceFixtureCommands); ok {
		f.clock, f.ids = clock, ids
		s.waiverCommands = f
	}
	if f, ok := s.exceptionCommands.(governanceFixtureCommands); ok {
		f.clock, f.ids = clock, ids
		s.exceptionCommands = f
	}
	if f, ok := s.approvalCommands.(governanceFixtureCommands); ok {
		f.clock, f.ids = clock, ids
		s.approvalCommands = f
	}
}

var (
	_ WaiverCommands    = governanceFixtureCommands{}
	_ ExceptionCommands = governanceFixtureCommands{}
	_ ApprovalCommands  = governanceFixtureCommands{}
)

package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// This preserves the pre-retirement local fixture's transaction and response
// assertions while handlers migrate. It is not a supported runtime backend and
// cannot be used by a production caller. EVY-906 still requires deletion of the
// remaining aggregate and legacy handlers, not merely this fixture separation.
func newLegacyServerFixture(ledger *app.Ledger) (*Server, error) {
	return newLegacyServerFixtureWithOptionsContext(context.Background(), ledger, ServerOptions{})
}

func newLegacyServerFixtureWithOptions(ledger *app.Ledger, opts ServerOptions) (*Server, error) {
	return newLegacyServerFixtureWithOptionsContext(context.Background(), ledger, opts)
}

func newLegacyServerFixtureWithOptionsContext(ctx context.Context, ledger *app.Ledger, opts ServerOptions) (*Server, error) {
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

// Replay uses the isolated command ledger so its effects and replay record
// still commit together; fixture migration must not turn this into a no-op.
func (s *Server) bindLegacyLedgerFixture(ledger *app.Ledger) {
	s.ledger = ledger
	s.authn = ledger
	s.idempotency = legacyFixtureIdempotencyExecutor{ledger: ledger}
	s.identityAccess = ledger
	s.localDeployments = ledger
	s.localEvidenceCreation = ledger
	s.localEvidenceRelationships = ledger
	s.localReportTemplates = ledger
	s.localBundleImport = ledger
	s.localEvidenceBundles = ledger
	s.evidenceIngestion = ledger
	s.riskDecisions = ledger
	s.packages = ledger
	s.verification = ledger
	s.bindCatalogFixturePorts(ledger)
	s.bindRegistrationFixturePorts(ledger)
	s.bindLifecycleFixturePorts(ledger)
	s.bindCatalogQueryFixturePorts(ledger)
}

type legacyFixtureCommandScope struct {
	ledger *app.Ledger
}

func (scope legacyFixtureCommandScope) bind(server *Server) {
	server.bindLegacyLedgerFixture(scope.ledger)
}

type legacyFixtureIdempotencyExecutor struct {
	ledger *app.Ledger
}

func (executor legacyFixtureIdempotencyExecutor) WithBody(ctx context.Context, actor domain.Actor, method, path, key string, body []byte, run func(context.Context, commandScope) (int, any, error)) (int, any, error) {
	if executor.ledger == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	return executor.ledger.WithIdempotency(ctx, actor, method, path, key, body, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(commandCtx, legacyFixtureCommandScope{ledger: commandLedger})
	})
}

func (executor legacyFixtureIdempotencyExecutor) WithBodyDigest(ctx context.Context, actor domain.Actor, method, path, key, bodyDigest string, run func(context.Context, commandScope) (int, any, error)) (int, any, error) {
	if executor.ledger == nil || run == nil {
		return 0, nil, app.ErrValidation
	}
	return executor.ledger.WithIdempotencyRequestHash(ctx, actor, method, path, key, bodyDigest, func(commandCtx context.Context, commandLedger *app.Ledger) (int, any, error) {
		return run(commandCtx, legacyFixtureCommandScope{ledger: commandLedger})
	})
}

var (
	_ Authenticator            = (*app.Ledger)(nil)
	_ idempotencyExecutor      = legacyFixtureIdempotencyExecutor{}
	_ identityAccessService    = (*app.Ledger)(nil)
	_ evidenceIngestionService = (*app.Ledger)(nil)
	_ riskDecisionService      = (*app.Ledger)(nil)
	_ packageService           = (*app.Ledger)(nil)
	_ verificationService      = (*app.Ledger)(nil)
)

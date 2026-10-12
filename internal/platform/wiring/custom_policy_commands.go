package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func BuildCustomPolicyCommands(factory app.UnitOfWorkFactory) (*riskapp.CustomPolicyCommands, error) {
	if factory == nil {
		return nil, errors.New("custom policy transactions are required")
	}
	return riskapp.NewCustomPolicyCommands(riskapp.CustomPolicyCommandConfig{Authorizer: riskapp.NewCustomPolicyAuthorizer(), Transactions: customPolicyTransactions{factory}, Hasher: customPolicyHasher{}, Clock: application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }), IDs: application.IDGeneratorFunc(application.NewID)})
}

type customPolicyHasher struct{}

func (customPolicyHasher) HashCustomPolicy(p riskdomain.CustomPolicy, release string, checks []riskdomain.PolicyCheck) (string, error) {
	return application.NormalizedJSONHash(map[string]any{"policy": domain.CustomPolicyFromContext(p), "release_id": release, "checks": domain.CustomPolicyChecksFromContext(checks)})
}

type customPolicyTransactions struct{ factory app.UnitOfWorkFactory }

func (t customPolicyTransactions) ExecuteCustomPolicy(ctx context.Context, fn func(context.Context, riskapp.CustomPolicyTransaction) error) error {
	return mapControlWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Risk.(riskapp.CustomPolicyReader)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, customPolicyTransaction{reader, repos.Risk, repos.Audit})
	}))
}

type customPolicyTransaction struct {
	reader riskapp.CustomPolicyReader
	writer app.RiskRepository
	audit  app.AuditRepository
}

func (t customPolicyTransaction) PolicyTenantExists(ctx context.Context, tenant string) (bool, error) {
	v, err := t.reader.PolicyTenantExists(ctx, tenant)
	return v, mapControlWriteError(err)
}
func (t customPolicyTransaction) ReadCustomPolicySubject(ctx context.Context, tenant, kind, id string) (riskapp.GovernanceSubjectReference, error) {
	v, err := t.reader.ReadCustomPolicySubject(ctx, tenant, kind, id)
	return v, mapControlWriteError(err)
}
func (t customPolicyTransaction) ReadCustomPolicy(ctx context.Context, tenant, id string) (riskdomain.CustomPolicy, error) {
	v, err := t.reader.ReadCustomPolicy(ctx, tenant, id)
	return v, mapControlWriteError(err)
}
func (t customPolicyTransaction) ReadCustomPolicyEvidencePresence(ctx context.Context, tenant, release string, types []string) (map[string]bool, error) {
	v, err := t.reader.ReadCustomPolicyEvidencePresence(ctx, tenant, release, types)
	return v, mapControlWriteError(err)
}
func (t customPolicyTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return riskapp.NewCustomPolicyAuthorizer().Authorize(ctx, a, r)
}
func (t customPolicyTransaction) InsertCustomPolicy(ctx context.Context, p riskdomain.CustomPolicy) error {
	return mapControlWriteError(t.writer.InsertCustomPolicy(ctx, domain.CustomPolicyFromContext(p)))
}
func (t customPolicyTransaction) InsertCustomPolicyEvaluation(ctx context.Context, e riskdomain.CustomPolicyEvaluation) error {
	return mapControlWriteError(t.writer.InsertCustomPolicyEvaluation(ctx, domain.CustomPolicyEvaluationFromContext(e)))
}
func (t customPolicyTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	return appendAuditEvent(ctx, t.audit, a)
}

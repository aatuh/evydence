package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

// policyEvaluationRepository binds the existing readiness SQL projection to the
// command transaction. It starts no second transaction and reads no Ledger.
type policyEvaluationRepository struct {
	releaseReader riskapp.PolicyEvaluationReleaseReader
	tx            pgx.Tx
}

var _ riskapp.PolicyEvaluationReader = policyEvaluationRepository{}
var _ experimentalapp.AnomalyReleaseFactsReader = policyEvaluationRepository{}

// Binds only shared presence predicates to the same active command transaction.
// It deliberately excludes readiness packages, bundle signatures and ID lists.
func (r policyEvaluationRepository) ReadAnomalyReleaseFacts(ctx context.Context, tenant, release string, now time.Time) (experimentalapp.AnomalyReleaseFacts, error) {
	var empty experimentalapp.AnomalyReleaseFacts
	if now.IsZero() {
		return empty, app.ErrValidation
	}
	if _, err := r.ReadPolicyEvaluationRelease(ctx, tenant, release); err != nil {
		return empty, err
	}
	build, err := readReleasePresenceFacts(ctx, r.tx, tenant, release)
	if err != nil {
		return empty, err
	}
	critical, _, err := readReleaseUnhandledPresence(ctx, r.tx, tenant, release, now.UTC())
	if err != nil {
		return empty, err
	}
	return experimentalapp.AnomalyReleaseFacts{TenantID: tenant, ReleaseID: release, HasPassedBuild: build.HasPassedBuild, HasVerifiedBuildAttestation: build.HasVerifiedBuildAttestation, UnhandledCritical: critical}, nil
}

func (r policyEvaluationRepository) ReadPolicyEvaluationRelease(ctx context.Context, tenant, release string) (riskapp.GovernanceSubjectReference, error) {
	return r.releaseReader.ReadPolicyEvaluationRelease(ctx, tenant, release)
}
func (r policyEvaluationRepository) ReadPolicyEvaluationSnapshot(ctx context.Context, tenant, release string, now time.Time) (riskapp.ReadinessSnapshot, error) {
	if now.IsZero() {
		return riskapp.ReadinessSnapshot{}, app.ErrValidation
	}
	// The metadata reader acquires the tenant projection fence before any SQL
	// facts are gathered, retaining it through audit/replay completion and commit.
	if _, err := r.ReadPolicyEvaluationRelease(ctx, tenant, release); err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	return readReleaseReadinessSnapshotTx(ctx, r.tx, tenant, release, now.UTC())
}

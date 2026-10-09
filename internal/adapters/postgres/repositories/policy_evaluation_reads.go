package repositories

import (
	"context"

	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

var _ riskapp.PolicyEvaluationReleaseReader = risk{}

func (r risk) ReadPolicyEvaluationRelease(ctx context.Context, tenant, id string) (riskapp.GovernanceSubjectReference, error) {
	return governance(r).ReadWaiverSubject(ctx, tenant, "release", id)
}

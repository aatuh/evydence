package domain

import riskdomain "github.com/aatuh/evydence/internal/risk/domain"

func PolicyEvaluationFromContext(v riskdomain.PolicyEvaluation) PolicyEvaluation {
	return PolicyEvaluation{ID: v.ID, TenantID: v.TenantID, ReleaseID: v.ReleaseID, Result: v.Result, PolicySet: v.PolicySet, Checks: CustomPolicyChecksFromContext(v.Checks), CreatedAt: v.CreatedAt}
}

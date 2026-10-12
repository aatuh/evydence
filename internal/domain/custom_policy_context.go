package domain

import riskdomain "github.com/aatuh/evydence/internal/risk/domain"

// CustomPolicyFromContext preserves the public versioned JSON/hash boundary.
func CustomPolicyFromContext(v riskdomain.CustomPolicy) CustomPolicy {
	var rules []PolicyRule
	if v.Rules != nil {
		rules = make([]PolicyRule, len(v.Rules))
	}
	for i, r := range v.Rules {
		rules[i] = PolicyRule(r)
	}
	return CustomPolicy{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Version: v.Version, Description: v.Description, Rules: rules, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func CustomPolicyToContext(v CustomPolicy) riskdomain.CustomPolicy {
	var rules []riskdomain.PolicyRule
	if v.Rules != nil {
		rules = make([]riskdomain.PolicyRule, len(v.Rules))
	}
	for i, r := range v.Rules {
		rules[i] = riskdomain.PolicyRule(r)
	}
	return riskdomain.CustomPolicy{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Version: v.Version, Description: v.Description, Rules: rules, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
func CustomPolicyChecksFromContext(values []riskdomain.PolicyCheck) []PolicyCheck {
	var checks []PolicyCheck
	if values != nil {
		checks = make([]PolicyCheck, len(values))
	}
	for i, c := range values {
		checks[i] = PolicyCheck(c)
		if c.Missing != nil {
			checks[i].Missing = append(make([]string, 0, len(c.Missing)), c.Missing...)
		}
	}
	return checks
}
func CustomPolicyEvaluationFromContext(v riskdomain.CustomPolicyEvaluation) CustomPolicyEvaluation {
	return CustomPolicyEvaluation{ID: v.ID, TenantID: v.TenantID, PolicyID: v.PolicyID, ReleaseID: v.ReleaseID, Result: v.Result, Checks: CustomPolicyChecksFromContext(v.Checks), InputHash: v.InputHash, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

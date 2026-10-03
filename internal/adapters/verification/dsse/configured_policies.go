package dsse

import "context"

// VerifyConfiguredPolicies evaluates each immutable root policy as a whole.
// A signature accepted under one policy never borrows builder/claim allowances
// from another. With no eligible policy, parsing assigns no cryptographic trust.
func VerifyConfiguredPolicies(ctx context.Context, raw []byte, policies []Policy) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalidPolicy
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if len(policies) == 0 {
		parsed, err := Parse(raw)
		if err != nil {
			return Result{}, err
		}
		parsed.Checks = []Check{
			{Name: "dsse_pae_signature", Result: CheckNotVerified}, {Name: "trusted_root", Result: CheckNotVerified},
			{Name: "payload_type", Result: CheckNotVerified, Detail: parsed.PayloadType}, {Name: "predicate_type", Result: CheckNotVerified, Detail: parsed.PredicateType},
			{Name: "subject_digest", Result: CheckNotVerified}, {Name: "builder_identity", Result: CheckNotVerified}, {Name: "policy_required_claims", Result: CheckNotVerified},
		}
		return parsed, nil
	}
	var candidate Result
	for _, policy := range policies {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		result, err := Verify(ctx, raw, policy)
		if err != nil {
			return Result{}, err
		}
		if result.Passed() {
			return result, nil
		}
		if candidate.Check("dsse_pae_signature") == "" || candidate.Check("dsse_pae_signature") != CheckPassed && result.Check("dsse_pae_signature") == CheckPassed {
			candidate = result
		}
	}
	return candidate, nil
}

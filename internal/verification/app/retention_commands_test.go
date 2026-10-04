package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type retentionReplayGuardTx struct {
	RetentionTransaction // nil mutation ports must never be reached
	authorizer           *trustGuardAuthorizer
	locks                int
	tenant, id           string
	lockErr              error
}

func (x *retentionReplayGuardTx) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return x.authorizer.Authorize(ctx, a, r)
}
func (x *retentionReplayGuardTx) LockObjectRetentionPolicy(_ context.Context, tenant, id string) error {
	x.locks++
	x.tenant, x.id = tenant, id
	return x.lockErr
}

type retentionReplayGuardTransactions struct {
	calls int
	tx    *retentionReplayGuardTx
}

func (x *retentionReplayGuardTransactions) ExecuteRetentionCommand(ctx context.Context, fn func(context.Context, RetentionTransaction) error) error {
	x.calls++
	return fn(ctx, x.tx)
}

type retentionReplayGuardReader struct{ t *testing.T }

func (r retentionReplayGuardReader) ReadObjectRetentionPolicy(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error) {
	r.t.Fatal("guard loaded policy receipt")
	return verificationdomain.ObjectRetentionPolicy{}, ErrValidation
}

func TestRetentionReplayGuardsAuthorizeBeforeLocksWithoutProviderReads(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for _, stage := range []string{"allowed", "policy-denial", "transaction-denial", "missing-policy", "malformed", "cancelled"} {
			t.Run(stage+map[bool]string{false: "/create", true: "/verify"}[verify], func(t *testing.T) {
				policy, txPolicy := &trustGuardAuthorizer{}, &trustGuardAuthorizer{}
				tx := &retentionReplayGuardTx{authorizer: txPolicy}
				transactions := &retentionReplayGuardTransactions{tx: tx}
				provider := &commandRetentionVerifier{}
				c, err := NewRetentionCommands(RetentionCommandConfig{Reader: retentionReplayGuardReader{t}, Transactions: transactions, Verifier: provider, Hasher: newVerificationTestState(), Authorizer: policy,
					Clock: application.ClockFunc(func() time.Time { t.Fatal("guard used clock"); return time.Time{} }), IDs: application.IDGeneratorFunc(func(string) string { t.Fatal("guard allocated ID"); return "" })})
				if err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				input := CreateObjectRetentionPolicyInput{Name: "Lock", Mode: "governance", RetentionDays: 30}
				id := " policy "
				var want error
				policies, txs, locks := 1, 1, 0
				if verify {
					locks = 1
				}
				switch stage {
				case "policy-denial":
					policy.err, want, txs, locks = application.ErrForbidden, application.ErrForbidden, 0, 0
				case "transaction-denial":
					txPolicy.err, want, locks = application.ErrForbidden, application.ErrForbidden, 0
				case "missing-policy":
					if verify {
						tx.lockErr, want = ErrNotFound, ErrNotFound
					}
				case "malformed":
					input.Name = "bad\x00"
					id = "bad\x00"
					want, policies, txs, locks = ErrValidation, 0, 0, 0
				case "cancelled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
					want, policies, txs, locks = context.Canceled, 0, 0, 0
				}
				if verify {
					err = c.AuthorizeVerifyObjectRetentionPolicy(ctx, verificationTestActor(), id)
				} else {
					err = c.AuthorizeCreateObjectRetentionPolicy(ctx, verificationTestActor(), input)
				}
				if !errors.Is(err, want) || policy.calls != policies || transactions.calls != txs || txPolicy.calls != txs || tx.locks != locks || len(provider.requests) != 0 {
					t.Fatal("guard bypassed auth or generated effects", err, policy.calls, transactions.calls, tx.locks)
				}
				if locks > 0 && (tx.tenant != "ten_1" || tx.id != "policy") {
					t.Fatal("guard lost tenant/policy coordinate")
				}
				scope := ScopeAdmin
				if verify {
					scope = ScopeVerifyRead
				}
				for _, a := range []*trustGuardAuthorizer{policy, txPolicy} {
					if a.calls > 0 && a.request != (application.AuthorizationRequest{Scope: scope, TenantWide: true}) {
						t.Fatal("guard broadened scope")
					}
				}
			})
		}
	}
}

type commandRetentionVerifier struct {
	configured  bool
	observation RetentionObservation
	err         error
	hook        func()
	requests    []RetentionRequest
}

func (f *commandRetentionVerifier) VerifyRetention(_ context.Context, request RetentionRequest) (RetentionObservation, bool, error) {
	f.requests = append(f.requests, request)
	if f.hook != nil {
		f.hook()
	}
	return f.observation, f.configured, f.err
}
func focusedRetentionCommands(t *testing.T, state *verificationTestState, verifier RetentionVerifier) *RetentionCommands {
	t.Helper()
	local := newVerificationTestService(t, state)
	commands, err := NewRetentionCommands(RetentionCommandConfig{Reader: state, Transactions: serviceRetentionTransactions{state}, Verifier: verifier, Hasher: local.canonicalHasher, Authorizer: local.authorizer, Clock: local.clock, IDs: local.ids})
	if err != nil {
		t.Fatal(err)
	}
	return commands
}
func TestRetentionCommandsPreserveLocalAndProviderSemanticsAtomically(t *testing.T) {
	for _, mode := range []string{"local", "provider", "unavailable", "cancelled", "audit failure"} {
		t.Run(mode, func(t *testing.T) {
			state := newVerificationTestState()
			hold := true
			verifier := &commandRetentionVerifier{configured: mode != "local", observation: RetentionObservation{Provider: "s3", Bucket: "bucket", ObjectKey: "tenants/ten_1/raw/sample", Mode: "compliance", RetentionDays: 90, Enforced: true, LegalHold: &hold, ObservedAt: verificationTestNow(), Checks: []verificationdomain.VerifyCheck{{Name: "provider_lock", Result: "passed"}}}}
			commands := focusedRetentionCommands(t, state, verifier)
			policy, err := commands.CreateObjectRetentionPolicy(t.Context(), verificationTestActor(), CreateObjectRetentionPolicyInput{Name: " lock ", ObjectKey: "tenants/ten_1/raw/sample", RequireLegalHold: true, Mode: "compliance", RetentionDays: 30})
			if err != nil || policy.Status != "configured" || policy.MaxVerificationAgeHours != 24 || len(state.audit) != 1 {
				t.Fatal("create", policy, err)
			}
			switch mode {
			case "unavailable":
				verifier.err = errors.New("provider password=private-secret")
			case "cancelled":
				verifier.err = context.Canceled
			case "audit failure":
				state.auditErr = errVerificationTestFailure
			}
			verified, err := commands.VerifyObjectRetentionPolicy(t.Context(), verificationTestActor(), policy.ID)
			if mode == "cancelled" || mode == "audit failure" {
				want := verifier.err
				if mode == "audit failure" {
					want = errVerificationTestFailure
				}
				if !errors.Is(err, want) || verified.ID != "" || state.retentionPolicies[policy.ID].Status != "configured" || len(state.audit) != 1 {
					t.Fatal("failed verification mutated state", verified, err)
				}
				return
			}
			wantStatus := "not_verified"
			if mode == "provider" {
				wantStatus = "verified"
			}
			if err != nil || verified.Status != wantStatus || verified.VerificationHash == "" || len(state.audit) != 2 || len(verifier.requests) != 1 || verifier.requests[0].TenantID != "ten_1" {
				t.Fatal("verify", verified, err)
			}
			if mode == "provider" && (verified.VerificationExpiresAt == nil || !verified.VerificationExpiresAt.Equal(verificationTestNow().Add(24*time.Hour))) {
				t.Fatal("receipt expiry lost")
			}
			for _, check := range verified.VerificationChecks {
				if strings.Contains(check.Detail, "private-secret") {
					t.Fatal("provider failure leaked")
				}
			}
		})
	}
}
func TestRetentionCommandsRejectMalformedInputAndFullSnapshotRaces(t *testing.T) {
	state := newVerificationTestState()
	verifier := &commandRetentionVerifier{}
	commands := focusedRetentionCommands(t, state, verifier)
	base := CreateObjectRetentionPolicyInput{Name: "lock", Mode: "governance", RetentionDays: 30}
	for _, mutate := range []func(*CreateObjectRetentionPolicyInput){
		func(v *CreateObjectRetentionPolicyInput) { v.Name = "nul\x00name" },
		func(v *CreateObjectRetentionPolicyInput) { v.ObjectKey = "tenants/ten_1/nul\x00key" },
		func(v *CreateObjectRetentionPolicyInput) { v.Mode = string([]byte{0xff}) },
		func(v *CreateObjectRetentionPolicyInput) { v.RetentionDays = 1 << 31 },
		func(v *CreateObjectRetentionPolicyInput) { v.ObjectPrefix = "tenants/foreign/" },
		func(v *CreateObjectRetentionPolicyInput) { v.Name = strings.Repeat(" ", 4096) + "lock" },
		func(v *CreateObjectRetentionPolicyInput) {
			v.ObjectPrefix = strings.Repeat(" ", 4096) + "tenants/ten_1/"
		},
		func(v *CreateObjectRetentionPolicyInput) {
			v.ObjectKey = strings.Repeat(" ", 4096) + "tenants/ten_1/raw/sample"
		},
		func(v *CreateObjectRetentionPolicyInput) { v.Mode = strings.Repeat(" ", 4096) + "governance" },
	} {
		input := base
		mutate(&input)
		if _, err := commands.CreateObjectRetentionPolicy(t.Context(), verificationTestActor(), input); !errors.Is(err, ErrValidation) || len(state.retentionPolicies) != 0 {
			t.Fatal("invalid retention input", err)
		}
	}
	policy, err := commands.CreateObjectRetentionPolicy(t.Context(), verificationTestActor(), base)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		if _, err := commands.VerifyObjectRetentionPolicy(t.Context(), verificationTestActor(), id); !errors.Is(err, ErrValidation) && !errors.Is(err, ErrNotFound) {
			t.Fatal("invalid ID", err)
		}
	}
	if len(verifier.requests) != 0 {
		t.Fatal("malformed IDs reached provider")
	}
	verifier.hook = func() {
		current := state.retentionPolicies[policy.ID]
		current.VerificationHash = "newer-receipt"
		state.retentionPolicies[policy.ID] = current
	}
	if _, err := commands.VerifyObjectRetentionPolicy(t.Context(), verificationTestActor(), policy.ID); !errors.Is(err, ErrConflict) || state.retentionPolicies[policy.ID].VerificationHash != "newer-receipt" || len(state.audit) != 1 {
		t.Fatal("same-status stale provider response overwrote newer receipt", err)
	}
}

func TestRetentionNormalizationPreservesExactRawLimitsAndDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, prefix string
		invalid      bool
	}{
		{strings.Repeat("é", 2048), strings.Repeat(" ", 4096), false},
		{strings.Repeat("é", 2049), "", true},
		{"Lock", strings.Repeat(" ", 4097), true},
	} {
		in, err := NormalizeObjectRetentionPolicyInput("tenant", CreateObjectRetentionPolicyInput{Name: tc.name, ObjectPrefix: tc.prefix, Mode: " governance ", RetentionDays: 30})
		if tc.invalid {
			if !errors.Is(err, ErrValidation) {
				t.Fatal("raw byte budget bypass", err)
			}
		} else if err != nil || in.Name != tc.name || in.ObjectPrefix != "tenants/tenant/" || in.Mode != "governance" || in.MaxVerificationAgeHours != 24 {
			t.Fatal("exact raw limit or optional-prefix defaults changed", in, err)
		}
	}
	for _, tc := range []struct {
		raw, want string
		invalid   bool
	}{
		{strings.Repeat("é", 512), strings.Repeat("é", 512), false},
		{strings.Repeat("é", 513), "", true},
		{strings.Repeat(" ", 1018) + "policy", "policy", false},
		{strings.Repeat(" ", 1019) + "policy", "", true},
	} {
		id, err := NormalizeObjectRetentionPolicyID(tc.raw)
		if tc.invalid {
			if !errors.Is(err, ErrValidation) {
				t.Fatal("raw ID budget bypass", err)
			}
		} else if err != nil || id != tc.want {
			t.Fatal("valid bounded ID normalization changed", id, err)
		}
	}
}

func TestRetentionCommandsFailClosedOnMalformedProviderObservations(t *testing.T) {
	for _, observation := range []RetentionObservation{
		{Provider: "s3\x00secret", Enforced: true},
		{Provider: "s3", Bucket: string([]byte{0xff}), Enforced: true},
		{Provider: "s3", RetentionDays: 1 << 31, Enforced: true},
		{Checks: make([]verificationdomain.VerifyCheck, MaxRetentionObservationFacts+1)},
		{Limitations: []string{strings.Repeat("x", MaxRetentionObservationBytes+1)}},
	} {
		state := newVerificationTestState()
		verifier := &commandRetentionVerifier{configured: true, observation: observation}
		commands := focusedRetentionCommands(t, state, verifier)
		policy, err := commands.CreateObjectRetentionPolicy(t.Context(), verificationTestActor(), CreateObjectRetentionPolicyInput{Name: "lock", Mode: "governance", RetentionDays: 30})
		if err != nil {
			t.Fatal(err)
		}
		got, err := commands.VerifyObjectRetentionPolicy(t.Context(), verificationTestActor(), policy.ID)
		if err != nil || got.Status != "not_verified" || got.VerificationProvider != "" || len(got.VerificationChecks) != 4 || got.VerificationChecks[2].Result != "error" {
			t.Fatalf("malformed provider trusted got=%#v err=%v", got, err)
		}
	}
}

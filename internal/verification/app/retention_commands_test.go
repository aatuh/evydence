package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

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

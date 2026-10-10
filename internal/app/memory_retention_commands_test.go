package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memoryRetentionCommandReader interface {
	verificationapp.RetentionPolicyReader
	GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	LockObjectRetentionPolicy(context.Context, string, string) error
}

func TestMemoryRetentionCommandsReadCurrentDetachedPolicyAndGuardOnlyIdentity(t *testing.T) {
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Integrity.(memoryRetentionCommandReader)
	if !ok {
		t.Fatal("memory integrity lacks focused retention command reads")
	}
	at, hold := fixedNow(), true
	tx.state.ObjectRetentionPolicies["policy"] = domain.ObjectRetentionPolicy{ID: "policy", TenantID: "tenant", Name: "Lock", Mode: "governance", ObjectPrefix: "tenants/tenant/", RetentionDays: 30, MaxVerificationAgeHours: 24, Status: "verified", VerifiedAt: &at, VerificationLegalHold: &hold, VerificationChecks: []domain.VerifyCheck{{Name: "provider", Result: "passed"}}, VerificationLimitations: []string{"recorded"}, CreatedAt: at}
	p, err := r.ReadObjectRetentionPolicy(t.Context(), "tenant", "policy")
	if err != nil || p.ID != "policy" || p.Name != "Lock" || p.Status != "verified" || len(p.VerificationChecks) != 1 {
		t.Fatal("retention read lost current public policy", err)
	}
	p.VerificationChecks[0].Detail = "caller"
	p.VerificationLimitations[0] = "caller"
	*p.VerifiedAt = at.AddDate(1, 0, 0)
	*p.VerificationLegalHold = false
	if tx.state.ObjectRetentionPolicies["policy"].VerificationChecks[0].Detail != "" || tx.state.ObjectRetentionPolicies["policy"].VerificationLimitations[0] != "recorded" || !tx.state.ObjectRetentionPolicies["policy"].VerifiedAt.Equal(at) || !*tx.state.ObjectRetentionPolicies["policy"].VerificationLegalHold {
		t.Fatal("retention read aliases persisted facts")
	}
	stored := tx.state.ObjectRetentionPolicies["policy"]
	stored.VerificationLimitations = []string{strings.Repeat("x", verificationapp.MaxRetentionPolicyBytes+1)}
	tx.state.ObjectRetentionPolicies[stored.ID] = stored
	if err := r.LockObjectRetentionPolicy(t.Context(), "tenant", "policy"); err != nil {
		t.Fatal("retention replay inspected observation metadata", err)
	}
	if value, err := r.GetObjectRetentionPolicyForUpdate(t.Context(), "tenant", "policy"); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(value, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("oversized retention read returned partial policy", err)
	}
	tx.state.ObjectRetentionPolicies["foreign"] = domain.ObjectRetentionPolicy{ID: "foreign", TenantID: "foreign"}
	if err := r.LockObjectRetentionPolicy(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign retention policy authorized", err)
	}
	if value, err := r.ReadObjectRetentionPolicy(t.Context(), "tenant", "foreign"); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(value, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("foreign retention policy exposed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := r.ReadObjectRetentionPolicy(ctx, "tenant", "policy"); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(value, verificationdomain.ObjectRetentionPolicy{}) {
		t.Fatal("cancelled retention read returned policy", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.LockObjectRetentionPolicy(t.Context(), "tenant", "policy"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed retention guard accepted", err)
	}
}

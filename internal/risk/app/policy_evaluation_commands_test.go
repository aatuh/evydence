package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type policyEvaluationFixture struct {
	release                                GovernanceSubjectReference
	snapshot                               ReadinessSnapshot
	metadataReads, factReads               int
	evaluations                            []riskdomain.PolicyEvaluation
	audits                                 []application.AuditEvent
	readErr, writeErr, auditErr, commitErr error
	snapshotAt                             time.Time
}

func (f *policyEvaluationFixture) ExecutePolicyEvaluation(ctx context.Context, fn func(context.Context, PolicyEvaluationTransaction) error) error {
	e, a := len(f.evaluations), len(f.audits)
	err := fn(ctx, f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil {
		f.evaluations = f.evaluations[:e]
		f.audits = f.audits[:a]
	}
	return err
}
func (f *policyEvaluationFixture) ReadPolicyEvaluationRelease(context.Context, string, string) (GovernanceSubjectReference, error) {
	f.metadataReads++
	return f.release, f.readErr
}
func (f *policyEvaluationFixture) ReadPolicyEvaluationSnapshot(_ context.Context, _, _ string, now time.Time) (ReadinessSnapshot, error) {
	f.factReads++
	f.snapshotAt = now
	return f.snapshot, f.readErr
}

func TestPolicyEvaluationClockIsSampledAfterCurrentReleaseFence(t *testing.T) {
	s, f, a, now := evaluationFixture(t)
	afterFence := now.Add(time.Hour)
	s.config.Clock = application.ClockFunc(func() time.Time {
		if f.metadataReads == 0 {
			return now
		}
		return afterFence
	})
	v, err := s.EvaluateRelease(t.Context(), a, "rel_1")
	if err != nil || !v.CreatedAt.Equal(afterFence) || !f.snapshotAt.Equal(afterFence) || !f.audits[0].OccurredAt.Equal(afterFence) {
		t.Fatal("evaluation used pre-fence expiry/signing time", v, err)
	}
}
func (f *policyEvaluationFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return NewPolicyEvaluationAuthorizer().Authorize(ctx, a, r)
}
func (f *policyEvaluationFixture) InsertPolicyEvaluation(_ context.Context, v riskdomain.PolicyEvaluation) error {
	f.evaluations = append(f.evaluations, v)
	return f.writeErr
}
func (f *policyEvaluationFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, f.auditErr
}
func evaluationFixture(t *testing.T) (*PolicyEvaluationCommands, *policyEvaluationFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC)
	f := &policyEvaluationFixture{release: GovernanceSubjectReference{ID: "rel_1", TenantID: "ten_1", Type: "release", ProductID: "prod_1", ReleaseID: "rel_1"}, snapshot: passingReadinessSnapshot()}
	s, err := NewPolicyEvaluationCommands(PolicyEvaluationCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "ten_1", UserID: "human", Scopes: []string{ScopeVerifyRead}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: []string{ScopeVerifyRead}}}}
	return s, f, a, now.Truncate(time.Microsecond)
}
func TestPolicyEvaluationCommandsPreserveCanonicalChecksAndAtomicAudit(t *testing.T) {
	s, f, a, now := evaluationFixture(t)
	if err := s.AuthorizeEvaluateRelease(t.Context(), a, " rel_1 "); err != nil || f.factReads+len(f.evaluations)+len(f.audits) != 0 {
		t.Fatal("replay hydrated facts or emitted effects", err)
	}
	want, err := EvaluateReadinessSnapshot(f.snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	want.ID = "pe_new"
	v, err := s.EvaluateRelease(t.Context(), a, " rel_1 ")
	if err != nil || !reflect.DeepEqual(v, want) || len(f.evaluations) != 1 || !reflect.DeepEqual(f.evaluations[0], want) || len(f.audits) != 1 || f.audits[0].EntryType != "policy.evaluated" || f.audits[0].SubjectType != "policy_evaluation" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != "human" || f.audits[0].ActorType != "human_user" || !f.audits[0].OccurredAt.Equal(now) {
		t.Fatal("canonical policy contract changed", v, err)
	}
	f.snapshot.UnhandledCritical = true
	v, err = s.EvaluateRelease(t.Context(), a, "rel_1")
	if err != nil || v.Result != "failed" || len(v.Checks) != 13 {
		t.Fatal("failed readiness lost", v, err)
	}
}
func TestPolicyEvaluationCommandsAuthorizeBeforeFactsAndRejectInvalidCoordinates(t *testing.T) {
	for _, bad := range []string{"", " ", "bad\x00", "\xff", strings.Repeat("x", 1025)} {
		s, f, a, _ := evaluationFixture(t)
		if err := s.AuthorizeEvaluateRelease(t.Context(), a, bad); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if v, err := s.EvaluateRelease(t.Context(), a, bad); !errors.Is(err, ErrValidation) || v.ID != "" || f.metadataReads+f.factReads != 0 {
			t.Fatal("bad input read storage", v, err)
		}
	}
	s, f, a, _ := evaluationFixture(t)
	a.ResourceGrants = nil
	if err := s.AuthorizeEvaluateRelease(t.Context(), a, "rel_1"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revoked replay", err)
	}
	if _, err := s.EvaluateRelease(t.Context(), a, "rel_1"); !errors.Is(err, application.ErrForbidden) || f.factReads != 0 {
		t.Fatal("unauthorized fact read", err)
	}
	for _, change := range []func(*policyEvaluationFixture){func(f *policyEvaluationFixture) { f.release.TenantID = "other" }, func(f *policyEvaluationFixture) { f.release.Type = "policy" }, func(f *policyEvaluationFixture) { f.release.ID = "other" }, func(f *policyEvaluationFixture) { f.release.ProductID = "" }, func(f *policyEvaluationFixture) { f.release.ReleaseID = "other" }} {
		s, f, a, _ := evaluationFixture(t)
		change(f)
		if v, err := s.EvaluateRelease(t.Context(), a, "rel_1"); !errors.Is(err, ErrNotFound) || v.ID != "" || f.factReads != 0 {
			t.Fatal("wrong current parent accepted", v, err)
		}
	}
	for _, change := range []func(*ReadinessSnapshot){func(v *ReadinessSnapshot) { v.ProductID = "other" }, func(v *ReadinessSnapshot) { v.ReleaseID = "other" }, func(v *ReadinessSnapshot) { v.TenantID = "other" }, func(v *ReadinessSnapshot) { v.SnapshotVersion = "future" }, func(v *ReadinessSnapshot) { v.PackageCount = -1 }, func(v *ReadinessSnapshot) { v.MissingCustomerStatementIDs = []string{strings.Repeat("x", 1025)} }, func(v *ReadinessSnapshot) { v.IncompleteExceptionIDs = make([]string, 4097) }} {
		s, f, a, _ := evaluationFixture(t)
		change(&f.snapshot)
		if v, err := s.EvaluateRelease(t.Context(), a, "rel_1"); err == nil || v.ID != "" || len(f.evaluations)+len(f.audits) != 0 {
			t.Fatal("invalid or changed snapshot persisted", v, err)
		}
	}
}
func TestPolicyEvaluationCommandsRollbackAndMandatoryDependencies(t *testing.T) {
	for _, stage := range []string{"read", "write", "audit", "commit", "clock", "record ID", "audit ID"} {
		s, f, a, _ := evaluationFixture(t)
		want := ErrConflict
		switch stage {
		case "read":
			f.readErr = want
		case "write":
			f.writeErr = want
		case "audit":
			f.auditErr = want
		case "commit":
			f.commitErr = want
		case "clock":
			s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
			want = ErrValidation
		case "record ID":
			s.config.IDs = application.IDGeneratorFunc(func(string) string { return "" })
			want = ErrValidation
		case "audit ID":
			s.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if p == "ace" {
					return ""
				}
				return "pe_new"
			})
			want = ErrValidation
		}
		if v, err := s.EvaluateRelease(t.Context(), a, "rel_1"); !errors.Is(err, want) || v.ID != "" || len(f.evaluations)+len(f.audits) != 0 {
			t.Fatal("evaluation effects leaked", stage, v, err)
		}
	}
	s, f, a, _ := evaluationFixture(t)
	for _, change := range []func(*PolicyEvaluationCommandConfig){func(c *PolicyEvaluationCommandConfig) { c.Authorizer = nil }, func(c *PolicyEvaluationCommandConfig) { c.Transactions = nil }, func(c *PolicyEvaluationCommandConfig) { c.Clock = nil }, func(c *PolicyEvaluationCommandConfig) { c.IDs = nil }} {
		c := s.config
		change(&c)
		if _, err := NewPolicyEvaluationCommands(c); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.EvaluateRelease(ctx, a, "rel_1"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeEvaluateRelease(ctx, a, "rel_1"); !errors.Is(err, context.Canceled) || f.metadataReads+f.factReads != 0 {
		t.Fatal(err)
	}
}

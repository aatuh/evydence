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

type customPolicyFixture struct {
	policy                                          riskdomain.CustomPolicy
	release                                         GovernanceSubjectReference
	present                                         map[string]bool
	metadataReads, definitionReads, presenceReads   int
	tenantExists                                    bool
	policies                                        []riskdomain.CustomPolicy
	evaluations                                     []riskdomain.CustomPolicyEvaluation
	audits                                          []application.AuditEvent
	readErr, writeErr, auditErr, hashErr, commitErr error
	hashPolicy                                      riskdomain.CustomPolicy
	hashChecks                                      []riskdomain.PolicyCheck
}

func (f *customPolicyFixture) ExecuteCustomPolicy(ctx context.Context, fn func(context.Context, CustomPolicyTransaction) error) error {
	p, e, a := len(f.policies), len(f.evaluations), len(f.audits)
	err := fn(ctx, f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil {
		f.policies = f.policies[:p]
		f.evaluations = f.evaluations[:e]
		f.audits = f.audits[:a]
	}
	return err
}
func (f *customPolicyFixture) PolicyTenantExists(context.Context, string) (bool, error) {
	f.metadataReads++
	return f.tenantExists, f.readErr
}
func (f *customPolicyFixture) ReadCustomPolicySubject(_ context.Context, tenant, kind, id string) (GovernanceSubjectReference, error) {
	f.metadataReads++
	if kind == "release" {
		return f.release, f.readErr
	}
	return GovernanceSubjectReference{ID: f.policy.ID, TenantID: f.policy.TenantID, Type: "policy"}, f.readErr
}
func (f *customPolicyFixture) ReadCustomPolicy(context.Context, string, string) (riskdomain.CustomPolicy, error) {
	f.definitionReads++
	return f.policy, f.readErr
}
func (f *customPolicyFixture) ReadCustomPolicyEvidencePresence(_ context.Context, tenant, release string, types []string) (map[string]bool, error) {
	f.presenceReads++
	return f.present, f.readErr
}
func (f *customPolicyFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return NewCustomPolicyAuthorizer().Authorize(ctx, a, r)
}
func (f *customPolicyFixture) InsertCustomPolicy(_ context.Context, p riskdomain.CustomPolicy) error {
	f.policies = append(f.policies, p)
	return f.writeErr
}
func (f *customPolicyFixture) InsertCustomPolicyEvaluation(_ context.Context, e riskdomain.CustomPolicyEvaluation) error {
	f.evaluations = append(f.evaluations, e)
	return f.writeErr
}
func (f *customPolicyFixture) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, a)
	return application.AuditReceipt{ID: a.ID}, f.auditErr
}
func (f *customPolicyFixture) HashCustomPolicy(p riskdomain.CustomPolicy, _ string, c []riskdomain.PolicyCheck) (string, error) {
	f.hashPolicy = p
	f.hashChecks = c
	return "sha256:" + strings.Repeat("a", 64), f.hashErr
}
func policyFixture(t *testing.T) (*CustomPolicyCommands, *customPolicyFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC)
	f := &customPolicyFixture{tenantExists: true, release: GovernanceSubjectReference{ID: "release", TenantID: "tenant", Type: "release", ProductID: "product", ReleaseID: "release"}, present: map[string]bool{"sbom": true, "vex": false, "build": false}, policy: riskdomain.CustomPolicy{ID: "policy", TenantID: "tenant", Name: "Policy", Version: "1", SchemaVersion: riskdomain.CustomPolicySchemaVersion, CreatedAt: now.Truncate(time.Microsecond), Rules: []riskdomain.PolicyRule{{Name: " SBOM ", EvidenceType: "sbom", Severity: " custom ", Required: true}, {Name: "VEX", EvidenceType: "vex", Severity: "medium", Required: true}, {Name: "optional", EvidenceType: "build", Severity: "anything"}, {Name: "metadata", Severity: "annotation"}}}}
	s, err := NewCustomPolicyCommands(CustomPolicyCommandConfig{Authorizer: f, Transactions: f, Hasher: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(p string) string { return p + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopePolicyWrite, ScopePolicyRead}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopePolicyWrite}}, {ResourceType: "release", ResourceID: "release", Scopes: []string{ScopePolicyRead}}}}
	return s, f, a, now.Truncate(time.Microsecond)
}
func TestCustomPolicyCommandsPreserveRulesAndPresenceSemantics(t *testing.T) {
	s, f, a, now := policyFixture(t)
	in := CreateCustomPolicyInput{Name: " Policy ", Version: " 1 ", Description: " Description ", Rules: append([]riskdomain.PolicyRule(nil), f.policy.Rules...)}
	if err := s.AuthorizeCreateCustomPolicy(t.Context(), a, in); err != nil || len(f.policies)+len(f.audits) != 0 {
		t.Fatal("authorization effects", err)
	}
	p, err := s.CreateCustomPolicy(t.Context(), a, in)
	if err != nil || p.Name != "Policy" || p.Version != "1" || p.Description != "Description" || !reflect.DeepEqual(p.Rules, in.Rules) || !p.CreatedAt.Equal(now) || p.SchemaVersion != riskdomain.CustomPolicySchemaVersion || len(f.policies) != 1 || len(f.audits) != 1 || f.audits[0].ActorID != "human" || f.audits[0].ActorType != "human_user" {
		t.Fatal("policy contract", p, f.audits, err)
	}
	p.Rules[0].Name = "changed"
	if in.Rules[0].Name != " SBOM " {
		t.Fatal("aliased caller rules")
	}
	if err := s.AuthorizeEvaluateCustomPolicy(t.Context(), a, " policy ", " release "); err != nil || f.definitionReads+f.presenceReads != 0 {
		t.Fatal("replay read definition or history", err)
	}
	e, err := s.EvaluateCustomPolicy(t.Context(), a, "policy", "release")
	want := []riskdomain.PolicyCheck{{Name: " SBOM ", Severity: " custom ", Result: "passed", Explanation: "sbom evidence exists"}, {Name: "VEX", Severity: "medium", Result: "failed", Missing: []string{"vex"}, Explanation: "vex evidence is missing"}, {Name: "optional", Severity: "anything", Result: "passed", Explanation: "optional evidence not present"}, {Name: "metadata", Severity: "annotation", Result: "passed", Explanation: "metadata-only custom policy rule recorded"}}
	if err != nil || e.Result != "failed" || !reflect.DeepEqual(e.Checks, want) || !reflect.DeepEqual(f.hashChecks, want) || !reflect.DeepEqual(f.hashPolicy, f.policy) || e.InputHash != "sha256:"+strings.Repeat("a", 64) || !e.CreatedAt.Equal(now) || e.SchemaVersion != riskdomain.CustomPolicyEvalSchemaVersion || len(f.evaluations) != 1 || len(f.audits) != 2 || f.audits[1].PayloadHash != e.InputHash || f.audits[1].SubjectID != e.ID {
		t.Fatal("presence evaluation changed", e, err)
	}
	f.present["vex"] = true
	e, err = s.EvaluateCustomPolicy(t.Context(), a, "policy", "release")
	if err != nil || e.Result != "passed" {
		t.Fatal(e, err)
	}
}
func TestCustomPolicyCommandsRejectBadInputAndCurrentOwnership(t *testing.T) {
	for _, change := range []func(*CreateCustomPolicyInput){func(v *CreateCustomPolicyInput) { v.Name = " " }, func(v *CreateCustomPolicyInput) { v.Version = "bad\x00" }, func(v *CreateCustomPolicyInput) { v.Name = strings.Repeat("x", 1025) }, func(v *CreateCustomPolicyInput) { v.Description = "\xff" }, func(v *CreateCustomPolicyInput) { v.Rules = nil }, func(v *CreateCustomPolicyInput) { v.Rules[0].Name = " " }, func(v *CreateCustomPolicyInput) { v.Rules[0].Severity = " " }, func(v *CreateCustomPolicyInput) { v.Rules[0].EvidenceType = " sbom " }, func(v *CreateCustomPolicyInput) { v.Rules = make([]riskdomain.PolicyRule, 4097) }} {
		s, f, a, _ := policyFixture(t)
		in := CreateCustomPolicyInput{Name: "Policy", Version: "1", Rules: append([]riskdomain.PolicyRule(nil), f.policy.Rules...)}
		change(&in)
		if err := s.AuthorizeCreateCustomPolicy(t.Context(), a, in); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
		if v, err := s.CreateCustomPolicy(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.metadataReads+len(f.policies)+len(f.audits) != 0 {
			t.Fatal("bad input reached storage", v, err)
		}
	}
	for _, change := range []func(*customPolicyFixture){func(f *customPolicyFixture) { f.policy.TenantID = "other" }, func(f *customPolicyFixture) { f.release.TenantID = "other" }, func(f *customPolicyFixture) { f.release.ProductID = "" }, func(f *customPolicyFixture) { f.release.ID = "other" }, func(f *customPolicyFixture) { f.release.Type = "policy" }} {
		s, f, a, _ := policyFixture(t)
		change(f)
		if err := s.AuthorizeEvaluateCustomPolicy(t.Context(), a, "policy", "release"); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
		if e, err := s.EvaluateCustomPolicy(t.Context(), a, "policy", "release"); !errors.Is(err, ErrNotFound) || e.ID != "" || len(f.evaluations)+len(f.audits) != 0 {
			t.Fatal("foreign subject", e, err)
		}
	}
	s, f, a, _ := policyFixture(t)
	a.ResourceGrants = nil
	if err := s.AuthorizeEvaluateCustomPolicy(t.Context(), a, "policy", "release"); !errors.Is(err, application.ErrForbidden) || f.definitionReads+f.presenceReads != 0 {
		t.Fatal("revoked replay", err)
	}
	if _, err := s.CreateCustomPolicy(t.Context(), a, CreateCustomPolicyInput{Name: "Policy", Version: "1", Rules: f.policy.Rules}); !errors.Is(err, application.ErrForbidden) || len(f.policies) != 0 {
		t.Fatal("tenant policy bypass", err)
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopePolicyWrite}}}
	if err := s.AuthorizeCreateCustomPolicy(t.Context(), a, CreateCustomPolicyInput{Name: "Policy", Version: "1", Rules: f.policy.Rules}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("tenant-wide definition accepted product grant", err)
	}
}
func TestCustomPolicyCommandsRollbackAndMandatoryPorts(t *testing.T) {
	for _, stage := range []string{"read", "write", "audit", "hash", "commit", "clock", "ID"} {
		for _, create := range []bool{true, false} {
			s, f, a, _ := policyFixture(t)
			want := ErrConflict
			switch stage {
			case "read":
				f.readErr = want
			case "write":
				f.writeErr = want
			case "audit":
				f.auditErr = want
			case "hash":
				if create {
					continue
				}
				f.hashErr = want
			case "commit":
				f.commitErr = want
			case "clock":
				s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
				want = ErrValidation
			case "ID":
				s.config.IDs = application.IDGeneratorFunc(func(string) string { return "" })
				want = ErrValidation
			}
			var err error
			if create {
				_, err = s.CreateCustomPolicy(t.Context(), a, CreateCustomPolicyInput{Name: "Policy", Version: "1", Rules: f.policy.Rules})
			} else {
				_, err = s.EvaluateCustomPolicy(t.Context(), a, "policy", "release")
			}
			if !errors.Is(err, want) || len(f.policies)+len(f.evaluations)+len(f.audits) != 0 {
				t.Fatal("rollback", stage, create, err)
			}
		}
	}
	s, _, a, _ := policyFixture(t)
	for _, change := range []func(*CustomPolicyCommandConfig){func(c *CustomPolicyCommandConfig) { c.Authorizer = nil }, func(c *CustomPolicyCommandConfig) { c.Transactions = nil }, func(c *CustomPolicyCommandConfig) { c.Hasher = nil }, func(c *CustomPolicyCommandConfig) { c.Clock = nil }, func(c *CustomPolicyCommandConfig) { c.IDs = nil }} {
		c := s.config
		change(&c)
		if _, err := NewCustomPolicyCommands(c); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateCustomPolicy(ctx, a, CreateCustomPolicyInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.EvaluateCustomPolicy(ctx, a, "policy", "release"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCustomPolicyCommandsFailClosedOnIncompletePresenceFacts(t *testing.T) {
	s, f, a, _ := policyFixture(t)
	delete(f.present, "vex")
	if e, err := s.EvaluateCustomPolicy(t.Context(), a, "policy", "release"); !errors.Is(err, ErrValidation) || e.ID != "" || len(f.evaluations)+len(f.audits) != 0 {
		t.Fatal("incomplete evidence facts persisted", e, err)
	}
}

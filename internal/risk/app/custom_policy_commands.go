package app

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const ScopePolicyRead = "policy:read"

type CreateCustomPolicyInput struct {
	Name, Version, Description string
	Rules                      []riskdomain.PolicyRule
}
type CustomPolicyReader interface {
	PolicyTenantExists(context.Context, string) (bool, error)
	ReadCustomPolicySubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	ReadCustomPolicy(context.Context, string, string) (riskdomain.CustomPolicy, error)
	ReadCustomPolicyEvidencePresence(context.Context, string, string, []string) (map[string]bool, error)
}
type CustomPolicyTransaction interface {
	CustomPolicyReader
	application.Authorizer
	application.AuditAppender
	InsertCustomPolicy(context.Context, riskdomain.CustomPolicy) error
	InsertCustomPolicyEvaluation(context.Context, riskdomain.CustomPolicyEvaluation) error
}
type CustomPolicyTransactionRunner interface {
	ExecuteCustomPolicy(context.Context, func(context.Context, CustomPolicyTransaction) error) error
}
type CustomPolicyHasher interface {
	HashCustomPolicy(riskdomain.CustomPolicy, string, []riskdomain.PolicyCheck) (string, error)
}
type CustomPolicyCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions CustomPolicyTransactionRunner
	Hasher       CustomPolicyHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}
type CustomPolicyCommands struct{ config CustomPolicyCommandConfig }

func NewCustomPolicyCommands(c CustomPolicyCommandConfig) (*CustomPolicyCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &CustomPolicyCommands{c}, nil
}
func NewCustomPolicyAuthorizer() application.Authorizer { return customPolicyAuthorizer{} }

type customPolicyAuthorizer struct{}

func (customPolicyAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopePolicyRead && r.Scope != ScopePolicyWrite {
		return application.ErrForbidden
	}
	return (riskResourceWriteAuthorizer{scope: r.Scope, tenantOnly: r.Scope == ScopePolicyWrite}).Authorize(ctx, a, r)
}
func (s *CustomPolicyCommands) prepare(ctx context.Context, a identitydomain.Actor, scope string) error {
	if s == nil {
		return ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: scope, ScopeOnly: true}); err != nil {
		return err
	}
	if !validControlText(a.TenantID, 1024, true) || !validControlText(auditActorID(a), 1024, true) {
		return ErrValidation
	}
	return nil
}
func validCustomPolicyRules(rules []riskdomain.PolicyRule) bool {
	if len(rules) == 0 || len(rules) > 4096 {
		return false
	}
	budget := 8 << 20
	for _, r := range rules {
		if !validControlText(r.Name, 65536, true) || strings.TrimSpace(r.Name) == "" || !validControlText(r.Severity, 128, true) || strings.TrimSpace(r.Severity) == "" || !validControlText(r.EvidenceType, 128, false) || r.EvidenceType != "" && !riskdomain.ValidPolicyEvidenceType(r.EvidenceType) {
			return false
		}
		budget -= len(r.Name) + len(r.Severity) + len(r.EvidenceType)
		if budget < 0 {
			return false
		}
	}
	return true
}
func (s *CustomPolicyCommands) prepareCreate(ctx context.Context, a identitydomain.Actor, in CreateCustomPolicyInput) (CreateCustomPolicyInput, error) {
	if err := s.prepare(ctx, a, ScopePolicyWrite); err != nil {
		return in, err
	}
	if !validControlText(in.Name, 1024, true) || !validControlText(in.Version, 1024, true) || len(a.TenantID)+len(in.Name)+len(in.Version) > 2048 || !validControlText(in.Description, 65536, false) || !validCustomPolicyRules(in.Rules) {
		return in, ErrValidation
	}
	in.Name, in.Version, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version), strings.TrimSpace(in.Description)
	if in.Name == "" || in.Version == "" {
		return in, ErrValidation
	}
	in.Rules = append([]riskdomain.PolicyRule(nil), in.Rules...)
	return in, nil
}
func authorizePolicyTenant(ctx context.Context, tx CustomPolicyTransaction, a identitydomain.Actor) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePolicyWrite, TenantWide: true}); err != nil {
		return err
	}
	exists, err := tx.PolicyTenantExists(ctx, a.TenantID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}
func (s *CustomPolicyCommands) AuthorizeCreateCustomPolicy(ctx context.Context, a identitydomain.Actor, in CreateCustomPolicyInput) error {
	_, err := s.prepareCreate(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteCustomPolicy(ctx, func(ctx context.Context, tx CustomPolicyTransaction) error { return authorizePolicyTenant(ctx, tx, a) })
}
func (s *CustomPolicyCommands) appendAudit(ctx context.Context, tx CustomPolicyTransaction, a identitydomain.Actor, kind, subject, id, hash string, now time.Time) error {
	audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: kind, SubjectType: subject, SubjectID: id, ActorType: auditActorType(a), ActorID: auditActorID(a), PayloadHash: hash, OccurredAt: now}
	if !validControlText(audit.ID, 1024, true) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, audit)
	return err
}
func (s *CustomPolicyCommands) CreateCustomPolicy(ctx context.Context, a identitydomain.Actor, in CreateCustomPolicyInput) (riskdomain.CustomPolicy, error) {
	in, err := s.prepareCreate(ctx, a, in)
	if err != nil {
		return riskdomain.CustomPolicy{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	p := riskdomain.CustomPolicy{ID: s.config.IDs.NewID("cpol"), TenantID: a.TenantID, Name: in.Name, Version: in.Version, Description: in.Description, Rules: in.Rules, SchemaVersion: riskdomain.CustomPolicySchemaVersion, CreatedAt: now}
	if !validRiskLifecycleTime(now) || !validControlText(p.ID, 1024, true) {
		return riskdomain.CustomPolicy{}, ErrValidation
	}
	err = s.config.Transactions.ExecuteCustomPolicy(ctx, func(ctx context.Context, tx CustomPolicyTransaction) error {
		if err := authorizePolicyTenant(ctx, tx, a); err != nil {
			return err
		}
		if err := tx.InsertCustomPolicy(ctx, p); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, "custom_policy.created", "custom_policy", p.ID, "", now)
	})
	if err != nil {
		return riskdomain.CustomPolicy{}, err
	}
	return p, nil
}
func (s *CustomPolicyCommands) prepareEvaluate(ctx context.Context, a identitydomain.Actor, policy, release string) (string, string, error) {
	if err := s.prepare(ctx, a, ScopePolicyRead); err != nil {
		return "", "", err
	}
	if !validControlText(policy, 1024, true) || !validControlText(release, 1024, true) {
		return "", "", ErrValidation
	}
	policy, release = strings.TrimSpace(policy), strings.TrimSpace(release)
	if policy == "" || release == "" {
		return "", "", ErrValidation
	}
	return policy, release, nil
}
func authorizePolicyEvaluation(ctx context.Context, tx CustomPolicyTransaction, a identitydomain.Actor, policy, release string) error {
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePolicyRead, ScopeOnly: true}); err != nil {
		return err
	}
	p, err := tx.ReadCustomPolicySubject(ctx, a.TenantID, "policy", policy)
	if err != nil {
		return err
	}
	if !validGovernanceSubject(p, a.TenantID, "policy", policy) || p.ProductID != "" || p.ReleaseID != "" {
		return ErrNotFound
	}
	r, err := tx.ReadCustomPolicySubject(ctx, a.TenantID, "release", release)
	if err != nil {
		return err
	}
	if !validGovernanceSubject(r, a.TenantID, "release", release) || r.ProductID == "" || r.ReleaseID != release {
		return ErrNotFound
	}
	if !validControlText(r.ProductID, 1024, true) {
		return ErrValidation
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePolicyRead, Resources: subjectResources(r)})
}

// Replay authorization reads current ownership only, not rules or evidence.
func (s *CustomPolicyCommands) AuthorizeEvaluateCustomPolicy(ctx context.Context, a identitydomain.Actor, policy, release string) error {
	policy, release, err := s.prepareEvaluate(ctx, a, policy, release)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteCustomPolicy(ctx, func(ctx context.Context, tx CustomPolicyTransaction) error {
		return authorizePolicyEvaluation(ctx, tx, a, policy, release)
	})
}
func (s *CustomPolicyCommands) EvaluateCustomPolicy(ctx context.Context, a identitydomain.Actor, policy, release string) (riskdomain.CustomPolicyEvaluation, error) {
	policy, release, err := s.prepareEvaluate(ctx, a, policy, release)
	if err != nil {
		return riskdomain.CustomPolicyEvaluation{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	v := riskdomain.CustomPolicyEvaluation{ID: s.config.IDs.NewID("cpe"), TenantID: a.TenantID, PolicyID: policy, ReleaseID: release, Result: "passed", Checks: []riskdomain.PolicyCheck{}, SchemaVersion: riskdomain.CustomPolicyEvalSchemaVersion, CreatedAt: now}
	if !validRiskLifecycleTime(now) || !validControlText(v.ID, 1024, true) {
		return riskdomain.CustomPolicyEvaluation{}, ErrValidation
	}
	err = s.config.Transactions.ExecuteCustomPolicy(ctx, func(ctx context.Context, tx CustomPolicyTransaction) error {
		if err := authorizePolicyEvaluation(ctx, tx, a, policy, release); err != nil {
			return err
		}
		p, err := tx.ReadCustomPolicy(ctx, a.TenantID, policy)
		if err != nil {
			return err
		}
		if p.ID != policy || p.TenantID != a.TenantID {
			return ErrNotFound
		}
		if !validControlText(p.Name, 1024, true) || strings.TrimSpace(p.Name) == "" || !validControlText(p.Version, 1024, true) || strings.TrimSpace(p.Version) == "" || !validControlText(p.Description, 65536, false) || !validControlText(p.SchemaVersion, 1024, true) || !validRiskLifecycleTime(p.CreatedAt) || !validCustomPolicyRules(p.Rules) {
			return ErrValidation
		}
		types := []string{}
		seen := map[string]bool{}
		for _, rule := range p.Rules {
			if rule.EvidenceType != "" && !seen[rule.EvidenceType] {
				types = append(types, rule.EvidenceType)
				seen[rule.EvidenceType] = true
			}
		}
		presence, err := tx.ReadCustomPolicyEvidencePresence(ctx, a.TenantID, release, types)
		if err != nil {
			return err
		}
		if len(presence) != len(types) {
			return ErrValidation
		}
		for _, kind := range types {
			if _, ok := presence[kind]; !ok {
				return ErrValidation
			}
		}
		for _, rule := range p.Rules {
			check := riskdomain.EvaluateCustomPolicyRule(rule, presence[rule.EvidenceType])
			v.Checks = append(v.Checks, check)
			if check.Result == "failed" {
				v.Result = "failed"
			}
		}
		v.InputHash, err = s.config.Hasher.HashCustomPolicy(p, release, v.Checks)
		if err != nil {
			return err
		}
		hash, err := hex.DecodeString(strings.TrimPrefix(v.InputHash, "sha256:"))
		if err != nil || !strings.HasPrefix(v.InputHash, "sha256:") || len(hash) != 32 || strings.ToLower(v.InputHash) != v.InputHash {
			return ErrValidation
		}
		if err := tx.InsertCustomPolicyEvaluation(ctx, v); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, "custom_policy.evaluated", "custom_policy_evaluation", v.ID, v.InputHash, now)
	})
	if err != nil {
		return riskdomain.CustomPolicyEvaluation{}, err
	}
	return v, nil
}

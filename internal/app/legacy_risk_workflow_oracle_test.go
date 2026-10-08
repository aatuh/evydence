package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Unchanged historical Risk commands are package-local test oracles only.

type RecordVulnerabilityWorkflowInput struct {
	FindingID string
	Action    string
	Reason    string
}

type CreateCustomPolicyInput struct {
	Name        string
	Version     string
	Description string
	Rules       []domain.PolicyRule
}

func (l *Ledger) RecordVulnerabilityWorkflow(ctx context.Context, actor domain.Actor, in RecordVulnerabilityWorkflowInput) (domain.VulnerabilityWorkflowRecord, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	if err := require(actor, ScopeSecurityWrite); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	in.FindingID, in.Action, in.Reason = strings.TrimSpace(in.FindingID), strings.TrimSpace(in.Action), strings.TrimSpace(in.Reason)
	if in.FindingID == "" || !validVulnWorkflowAction(in.Action) || in.Reason == "" {
		return domain.VulnerabilityWorkflowRecord{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	scan, _, ok := l.findFindingLocked(actor.TenantID, in.FindingID)
	if !ok {
		return domain.VulnerabilityWorkflowRecord{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	record := domain.VulnerabilityWorkflowRecord{ID: newID("vw"), TenantID: actor.TenantID, FindingID: in.FindingID, ReleaseID: scan.ReleaseID, Action: in.Action, Reason: in.Reason, ActorID: actorID(actor), SchemaVersion: riskdomain.VulnerabilityWorkflowSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertVulnerabilityWorkflow(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "vulnerability_workflow."+record.Action, "vulnerability_finding", record.FindingID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.VulnerabilityWorkflowRecord{}, err
		}
		l.vulnWorkflow[record.ID] = record
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	l.vulnWorkflow[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "vulnerability_workflow."+record.Action, "vulnerability_finding", in.FindingID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	return record, nil
}

func (l *Ledger) CreateCustomPolicy(ctx context.Context, actor domain.Actor, in CreateCustomPolicyInput) (domain.CustomPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomPolicy{}, err
	}
	if err := require(actor, ScopePolicyWrite); err != nil {
		return domain.CustomPolicy{}, err
	}
	in.Name, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || len(in.Rules) == 0 {
		return domain.CustomPolicy{}, ErrValidation
	}
	for _, rule := range in.Rules {
		if strings.TrimSpace(rule.Name) == "" || strings.TrimSpace(rule.Severity) == "" {
			return domain.CustomPolicy{}, ErrValidation
		}
		if rule.EvidenceType != "" && !validPolicyEvidenceType(rule.EvidenceType) {
			return domain.CustomPolicy{}, ErrValidation
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.customPolicies {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name && existing.Version == in.Version {
			return domain.CustomPolicy{}, ErrConflict
		}
	}
	policy := domain.CustomPolicy{ID: newID("cpol"), TenantID: actor.TenantID, Name: in.Name, Version: in.Version, Description: strings.TrimSpace(in.Description), Rules: append([]domain.PolicyRule(nil), in.Rules...), SchemaVersion: domain.CustomPolicySchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertCustomPolicy(ctx, policy); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(policy.CreatedAt, actor.TenantID, "custom_policy.created", "custom_policy", policy.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.CustomPolicy{}, err
		}
		l.customPolicies[policy.ID] = policy
		l.publishCommittedAuditEntryLocked(entry)
		return policy, nil
	}
	l.customPolicies[policy.ID] = policy
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.created", "custom_policy", policy.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomPolicy{}, err
	}
	return policy, nil
}

func (l *Ledger) EvaluateCustomPolicy(ctx context.Context, actor domain.Actor, policyID, releaseID string) (domain.CustomPolicyEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	if err := require(actor, ScopePolicyRead); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	policy, ok := l.customPolicies[strings.TrimSpace(policyID)]
	release, rok := l.releases[strings.TrimSpace(releaseID)]
	if !ok || !rok || policy.TenantID != actor.TenantID || release.TenantID != actor.TenantID {
		return domain.CustomPolicyEvaluation{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopePolicyRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	checks := []domain.PolicyCheck{}
	result := "passed"
	for _, rule := range policy.Rules {
		check := l.evaluatePolicyRuleLocked(actor.TenantID, release.ID, rule)
		checks = append(checks, check)
		if check.Result == "failed" {
			result = "failed"
		}
	}
	inputHash, err := canonicalAnyHash(map[string]any{"policy": policy, "release_id": release.ID, "checks": checks})
	if err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	eval := domain.CustomPolicyEvaluation{ID: newID("cpe"), TenantID: actor.TenantID, PolicyID: policy.ID, ReleaseID: release.ID, Result: result, Checks: checks, InputHash: inputHash, SchemaVersion: domain.CustomPolicyEvalSchemaVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Risk.InsertCustomPolicyEvaluation(ctx, eval); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(eval.CreatedAt, actor.TenantID, "custom_policy.evaluated", "custom_policy_evaluation", eval.ID, actorType(actor), actorID(actor), inputHash, ""))
			return err
		}); err != nil {
			return domain.CustomPolicyEvaluation{}, err
		}
		l.customPolicyEvals[eval.ID] = eval
		l.publishCommittedAuditEntryLocked(entry)
		return eval, nil
	}
	l.customPolicyEvals[eval.ID] = eval
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.evaluated", "custom_policy_evaluation", eval.ID, actorType(actor), actorID(actor), inputHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	return eval, nil
}

func (l *Ledger) evaluatePolicyRuleLocked(tenantID, releaseID string, rule domain.PolicyRule) domain.PolicyCheck {
	present := false
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && item.Type == rule.EvidenceType {
			present = true
			break
		}
	}
	return domain.PolicyCheck(riskdomain.EvaluateCustomPolicyRule(riskdomain.PolicyRule(rule), present))
}

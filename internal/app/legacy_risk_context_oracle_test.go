package app

import (
	"context"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// Historical aggregate behavior exists only for package-local characterization.
// Construct stateless orchestration on demand; no registry or production field.
func (l *Ledger) legacyRiskCommands() *riskapp.Service {
	service, err := riskapp.NewService(riskapp.Config{
		Reader: ledgerRiskReader{ledger: l}, Transactions: ledgerRiskTransactions{ledger: l},
		Authorizer: ledgerContextAuthorizer{ledger: l}, ProjectionRefresher: ledgerRiskProjectionRefresher{ledger: l},
		Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID),
	})
	if err != nil {
		panic("unexpected legacy Risk oracle configuration failure: " + err.Error())
	}
	return service
}

type ledgerRiskProjectionRefresher struct{ ledger *Ledger }

func (r ledgerRiskProjectionRefresher) RefreshRiskProjection(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toRiskContextError(r.ledger.refreshWorkerProjectionLocked(ctx, tenantID))
}

type ledgerRiskReader struct{ ledger *Ledger }

func (r ledgerRiskReader) ResolveFinding(ctx context.Context, tenantID, id string) (riskapp.FindingReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.FindingReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return resolveRiskFindingLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) GetProduct(ctx context.Context, tenantID, id string) (riskapp.ProductReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ProductReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getRiskProductLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) GetRelease(ctx context.Context, tenantID, id string) (riskapp.ReleaseReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ReleaseReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getRiskReleaseLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) GetEvidence(ctx context.Context, tenantID, id string) (riskapp.EvidenceReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.EvidenceReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getRiskEvidenceLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) GetVEX(ctx context.Context, tenantID, id string) (riskapp.VEXReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.VEXReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getRiskVEXLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) GetControl(ctx context.Context, tenantID, id string) (riskapp.ControlReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ControlReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getRiskControlLocked(r.ledger, tenantID, id)
}

func (r ledgerRiskReader) ValidateSupportingReference(ctx context.Context, tenantID, productID, releaseID string, reference riskdomain.SupportingReference) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return validateRiskSupportingReferenceLocked(r.ledger, tenantID, productID, releaseID, reference)
}

func (r ledgerRiskReader) ResolveGovernanceSubject(ctx context.Context, tenantID, subjectType, id string) (riskapp.GovernanceSubjectReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return resolveRiskGovernanceSubjectLocked(r.ledger, nil, tenantID, subjectType, id)
}

func (r ledgerRiskReader) ListVulnerabilityDecisions(ctx context.Context, tenantID string) ([]riskdomain.VulnerabilityDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return listRiskDecisionsLocked(r.ledger, tenantID)
}

func (r ledgerRiskReader) ListExceptions(ctx context.Context, tenantID string) ([]riskdomain.Exception, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return listRiskExceptionsLocked(r.ledger, tenantID), nil
}

func (r ledgerRiskReader) ReadReleaseReadinessSnapshot(ctx context.Context, tenantID, releaseID string) (riskapp.ReadinessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return buildRiskReadinessSnapshotLocked(r.ledger, tenantID, releaseID)
}

type ledgerRiskTransactions struct{ ledger *Ledger }

func (r ledgerRiskTransactions) Execute(ctx context.Context, command riskapp.TransactionCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := newLedgerRiskTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			return toRiskContextError(err)
		}
		tx.publish()
		return nil
	}
	if err := command(ctx, tx); err != nil {
		return toRiskContextError(err)
	}
	return tx.commitCompatibility(ctx)
}

type ledgerRiskTransaction struct {
	ledger       *Ledger
	repositories *Repositories
	decisions    map[string]domain.VulnerabilityDecision
	exceptions   map[string]domain.Exception
	waivers      map[string]domain.Waiver
	approvals    map[string]domain.ApprovalRecord
	policies     map[string]domain.PolicyEvaluation
	audit        []domain.AuditChainEntry
}

func newLedgerRiskTransaction(ledger *Ledger) *ledgerRiskTransaction {
	return &ledgerRiskTransaction{
		ledger: ledger, decisions: map[string]domain.VulnerabilityDecision{}, exceptions: map[string]domain.Exception{},
		waivers: map[string]domain.Waiver{}, approvals: map[string]domain.ApprovalRecord{}, policies: map[string]domain.PolicyEvaluation{},
	}
}

func (t *ledgerRiskTransaction) Decisions() riskapp.Repository            { return t }
func (t *ledgerRiskTransaction) Governance() riskapp.GovernanceRepository { return t }
func (t *ledgerRiskTransaction) Authorization() application.Authorizer {
	return ledgerLockedContextAuthorizer{ledger: t.ledger}
}
func (t *ledgerRiskTransaction) Audit() application.AuditAppender { return t }

func (t *ledgerRiskTransaction) ResolveFinding(ctx context.Context, tenantID, id string) (riskapp.FindingReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.FindingReference{}, err
	}
	return resolveRiskFindingLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) GetProduct(ctx context.Context, tenantID, id string) (riskapp.ProductReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ProductReference{}, err
	}
	return getRiskProductLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) GetRelease(ctx context.Context, tenantID, id string) (riskapp.ReleaseReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ReleaseReference{}, err
	}
	return getRiskReleaseLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) GetEvidence(ctx context.Context, tenantID, id string) (riskapp.EvidenceReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.EvidenceReference{}, err
	}
	return getRiskEvidenceLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) GetVEX(ctx context.Context, tenantID, id string) (riskapp.VEXReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.VEXReference{}, err
	}
	return getRiskVEXLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) GetControl(ctx context.Context, tenantID, id string) (riskapp.ControlReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ControlReference{}, err
	}
	return getRiskControlLocked(t.ledger, tenantID, id)
}

func (t *ledgerRiskTransaction) ValidateSupportingReference(ctx context.Context, tenantID, productID, releaseID string, reference riskdomain.SupportingReference) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return validateRiskSupportingReferenceLocked(t.ledger, tenantID, productID, releaseID, reference)
}

func (t *ledgerRiskTransaction) ResolveGovernanceSubject(ctx context.Context, tenantID, subjectType, id string) (riskapp.GovernanceSubjectReference, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.GovernanceSubjectReference{}, err
	}
	return resolveRiskGovernanceSubjectLocked(t.ledger, t.waivers, tenantID, subjectType, id)
}

func (t *ledgerRiskTransaction) ListVulnerabilityDecisions(ctx context.Context, tenantID string) ([]riskdomain.VulnerabilityDecision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	values, err := listRiskDecisionsLocked(t.ledger, tenantID)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]riskdomain.VulnerabilityDecision, len(values)+len(t.decisions))
	for _, value := range values {
		byID[value.ID] = value
	}
	for _, value := range t.decisions {
		if value.TenantID != tenantID {
			continue
		}
		mapped, err := domain.VulnerabilityDecisionToContextModel(value)
		if err != nil {
			return nil, riskapp.ErrValidation
		}
		byID[mapped.ID] = mapped
	}
	result := make([]riskdomain.VulnerabilityDecision, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	return result, nil
}

func (t *ledgerRiskTransaction) ListExceptions(ctx context.Context, tenantID string) ([]riskdomain.Exception, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	byID := map[string]riskdomain.Exception{}
	for _, value := range listRiskExceptionsLocked(t.ledger, tenantID) {
		byID[value.ID] = value
	}
	for _, value := range t.exceptions {
		if value.TenantID == tenantID {
			byID[value.ID] = exceptionToRiskContext(value)
		}
	}
	result := make([]riskdomain.Exception, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	return result, nil
}

func (t *ledgerRiskTransaction) ReadReleaseReadinessSnapshot(ctx context.Context, tenantID, releaseID string) (riskapp.ReadinessSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	return buildRiskReadinessSnapshotLocked(t.ledger, tenantID, releaseID)
}

func (t *ledgerRiskTransaction) SupersedeAndInsert(ctx context.Context, decision riskdomain.VulnerabilityDecision, superseded []riskdomain.VulnerabilityDecision) error {
	legacy := domain.VulnerabilityDecisionFromContextModel(decision)
	legacySuperseded := make([]domain.VulnerabilityDecision, 0, len(superseded))
	for _, value := range superseded {
		legacySuperseded = append(legacySuperseded, domain.VulnerabilityDecisionFromContextModel(value))
	}
	if t.repositories != nil {
		if err := t.repositories.Decisions.SupersedeAndInsert(ctx, legacy, legacySuperseded); err != nil {
			return toRiskContextError(err)
		}
	}
	for _, value := range legacySuperseded {
		t.decisions[value.ID] = value
	}
	t.decisions[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) InsertException(ctx context.Context, exception riskdomain.Exception) error {
	legacy := exceptionFromRiskContext(exception)
	if _, exists := t.ledger.exceptions[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if _, exists := t.exceptions[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Decisions.InsertException(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.exceptions[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) GetExceptionForUpdate(ctx context.Context, tenantID, id string) (riskdomain.Exception, error) {
	if err := ctx.Err(); err != nil {
		return riskdomain.Exception{}, err
	}
	value, ok := t.exceptions[id]
	if !ok {
		value, ok = t.ledger.exceptions[id]
	}
	if !ok || value.TenantID != tenantID {
		return riskdomain.Exception{}, riskapp.ErrNotFound
	}
	return exceptionToRiskContext(value), nil
}

func (t *ledgerRiskTransaction) ApproveException(ctx context.Context, exception riskdomain.Exception) error {
	legacy := exceptionFromRiskContext(exception)
	current, ok := t.ledger.exceptions[legacy.ID]
	if pending, pendingOK := t.exceptions[legacy.ID]; pendingOK {
		current, ok = pending, true
	}
	if !ok || current.TenantID != legacy.TenantID {
		return riskapp.ErrNotFound
	}
	if current.Approved && !sameExceptionApproval(current, legacy) {
		return riskapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Decisions.ApproveException(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.exceptions[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) GetWaiverForUpdate(ctx context.Context, tenantID, id string) (riskdomain.Waiver, error) {
	if err := ctx.Err(); err != nil {
		return riskdomain.Waiver{}, err
	}
	value, ok := t.waivers[id]
	if !ok {
		value, ok = t.ledger.waivers[id]
	}
	if !ok || value.TenantID != tenantID {
		return riskdomain.Waiver{}, riskapp.ErrNotFound
	}
	return waiverToRiskContext(value), nil
}

func (t *ledgerRiskTransaction) InsertWaiver(ctx context.Context, waiver riskdomain.Waiver) error {
	legacy := waiverFromRiskContext(waiver)
	if _, exists := t.ledger.waivers[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if _, exists := t.waivers[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if legacy.Supersedes != "" {
		previous, ok := t.waivers[legacy.Supersedes]
		if !ok {
			previous, ok = t.ledger.waivers[legacy.Supersedes]
		}
		if !ok || previous.TenantID != legacy.TenantID || previous.SupersededBy != "" {
			return riskapp.ErrConflict
		}
		previous.SupersededBy = legacy.ID
		t.waivers[previous.ID] = previous
	}
	if t.repositories != nil {
		if err := t.repositories.Governance.InsertWaiver(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.waivers[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) ApproveWaiver(ctx context.Context, waiver riskdomain.Waiver) error {
	legacy := waiverFromRiskContext(waiver)
	current, ok := t.waivers[legacy.ID]
	if !ok {
		current, ok = t.ledger.waivers[legacy.ID]
	}
	if !ok || current.TenantID != legacy.TenantID {
		return riskapp.ErrNotFound
	}
	if current.Approved {
		return riskapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Governance.ApproveWaiver(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.waivers[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) InsertApprovalRecord(ctx context.Context, approval riskdomain.ApprovalRecord) error {
	legacy := approvalFromRiskContext(approval)
	if _, exists := t.ledger.approvals[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if _, exists := t.approvals[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Governance.InsertApprovalRecord(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.approvals[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) InsertPolicyEvaluation(ctx context.Context, evaluation riskdomain.PolicyEvaluation) error {
	legacy := policyEvaluationFromRiskContext(evaluation)
	if _, exists := t.ledger.policies[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if _, exists := t.policies[legacy.ID]; exists {
		return riskapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Verification.InsertPolicyEvaluation(ctx, legacy); err != nil {
			return toRiskContextError(err)
		}
	}
	t.policies[legacy.ID] = legacy
	return nil
}

func (t *ledgerRiskTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toRiskContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toRiskContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerRiskTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
	entries := t.ledger.chain[entry.TenantID]
	for _, pending := range t.audit {
		if pending.TenantID == entry.TenantID {
			entries = append(entries, pending)
		}
	}
	entry.Sequence = int64(len(entries) + 1)
	if len(entries) > 0 {
		entry.PreviousEntryHash = entries[len(entries)-1].EntryHash
	}
	return RehashAuditChainEntry(entry)
}

func (t *ledgerRiskTransaction) publish() {
	for id, value := range t.decisions {
		t.ledger.decisions[id] = value
	}
	for id, value := range t.exceptions {
		t.ledger.exceptions[id] = value
	}
	for id, value := range t.waivers {
		t.ledger.waivers[id] = value
	}
	for id, value := range t.approvals {
		t.ledger.approvals[id] = value
	}
	for id, value := range t.policies {
		t.ledger.policies[id] = value
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
}

func (t *ledgerRiskTransaction) commitCompatibility(ctx context.Context) error {
	decisions := cloneVulnerabilityDecisionMap(t.ledger.decisions)
	exceptions := cloneRiskExceptionMap(t.ledger.exceptions)
	waivers := cloneRiskWaiverMap(t.ledger.waivers)
	approvals := cloneRiskApprovalMap(t.ledger.approvals)
	policies := cloneRiskPolicyEvaluationMap(t.ledger.policies)
	chain := cloneAuditChainMap(t.ledger.chain)
	t.publish()
	persist := t.ledger.persistLocked
	if len(t.decisions) > 0 {
		mutation, err := t.ledger.criticalMutationLocked()
		if err != nil {
			t.ledger.decisions = decisions
			t.ledger.exceptions = exceptions
			t.ledger.waivers = waivers
			t.ledger.approvals = approvals
			t.ledger.policies = policies
			t.ledger.chain = chain
			return toRiskContextError(err)
		}
		persist = func(ctx context.Context) error { return t.ledger.persistCriticalLocked(ctx, mutation) }
	}
	if err := persist(ctx); err != nil {
		t.ledger.decisions = decisions
		t.ledger.exceptions = exceptions
		t.ledger.waivers = waivers
		t.ledger.approvals = approvals
		t.ledger.policies = policies
		t.ledger.chain = chain
		return toRiskContextError(err)
	}
	return nil
}

func resolveRiskFindingLocked(ledger *Ledger, tenantID, id string) (riskapp.FindingReference, error) {
	scan, finding, ok := ledger.findFindingLocked(tenantID, strings.TrimSpace(id))
	if !ok {
		return riskapp.FindingReference{}, riskapp.ErrNotFound
	}
	release, ok := ledger.releases[scan.ReleaseID]
	if !ok || release.TenantID != tenantID {
		return riskapp.FindingReference{}, riskapp.ErrNotFound
	}
	sbomID, purl, name := ledger.decisionSBOMContextLocked(tenantID, scan.ReleaseID, finding.Component)
	return riskapp.FindingReference{
		ID: finding.ID, ScanID: scan.ID, TenantID: tenantID, ReleaseID: scan.ReleaseID, ProductID: release.ProductID,
		Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity, State: finding.State,
		SBOMID: sbomID, SBOMComponentPURL: purl, SBOMComponentName: name,
	}, nil
}

func getRiskProductLocked(ledger *Ledger, tenantID, id string) (riskapp.ProductReference, error) {
	value, ok := ledger.products[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return riskapp.ProductReference{}, riskapp.ErrNotFound
	}
	return riskapp.ProductReference{ID: value.ID, TenantID: value.TenantID}, nil
}

func getRiskReleaseLocked(ledger *Ledger, tenantID, id string) (riskapp.ReleaseReference, error) {
	value, ok := ledger.releases[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return riskapp.ReleaseReference{}, riskapp.ErrNotFound
	}
	return riskapp.ReleaseReference{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID}, nil
}

func getRiskEvidenceLocked(ledger *Ledger, tenantID, id string) (riskapp.EvidenceReference, error) {
	value, ok := ledger.evidence[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return riskapp.EvidenceReference{}, riskapp.ErrNotFound
	}
	return riskapp.EvidenceReference{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID}, nil
}

func getRiskVEXLocked(ledger *Ledger, tenantID, id string) (riskapp.VEXReference, error) {
	value, ok := ledger.vexDocuments[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return riskapp.VEXReference{}, riskapp.ErrNotFound
	}
	return riskapp.VEXReference{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, EvidenceID: value.EvidenceID}, nil
}

func getRiskControlLocked(ledger *Ledger, tenantID, id string) (riskapp.ControlReference, error) {
	value, ok := ledger.controls[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return riskapp.ControlReference{}, riskapp.ErrNotFound
	}
	return riskapp.ControlReference{ID: value.ID, TenantID: value.TenantID}, nil
}

func validateRiskSupportingReferenceLocked(ledger *Ledger, tenantID, productID, releaseID string, reference riskdomain.SupportingReference) error {
	legacy := domain.SubjectRef{Type: reference.Type, ID: reference.ID, Digest: reference.Digest}
	if !ledger.decisionSupportingRefInScopeLocked(tenantID, productID, releaseID, legacy) {
		return riskapp.ErrNotFound
	}
	return nil
}

func resolveRiskGovernanceSubjectLocked(ledger *Ledger, pendingWaivers map[string]domain.Waiver, tenantID, subjectType, id string) (riskapp.GovernanceSubjectReference, error) {
	subjectType = strings.TrimSpace(subjectType)
	id = strings.TrimSpace(id)
	result := riskapp.GovernanceSubjectReference{Type: subjectType, ID: id, TenantID: tenantID}
	switch subjectType {
	case "release":
		value, ok := ledger.releases[id]
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
		result.ProductID, result.ReleaseID = value.ProductID, value.ID
	case "finding":
		value, err := resolveRiskFindingLocked(ledger, tenantID, id)
		if err != nil {
			return riskapp.GovernanceSubjectReference{}, err
		}
		result.ProductID, result.ReleaseID = value.ProductID, value.ReleaseID
	case "control":
		value, ok := ledger.controls[id]
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
	case "policy":
		value, ok := ledger.customPolicies[id]
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
	case "contract_diff":
		value, ok := ledger.contractDiffs[id]
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
		result.ProductID, result.ReleaseID = value.ProductID, value.ReleaseID
	case "waiver":
		value, ok := pendingWaivers[id]
		if !ok {
			value, ok = ledger.waivers[id]
		}
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
		owner, err := resolveRiskGovernanceSubjectLocked(ledger, pendingWaivers, tenantID, value.ScopeType, value.ScopeID)
		if err != nil {
			return riskapp.GovernanceSubjectReference{}, err
		}
		result.ProductID, result.ReleaseID = owner.ProductID, owner.ReleaseID
	case "security_review":
		value, ok := ledger.manualDocs[id]
		if !ok || value.TenantID != tenantID || value.DocumentType != "security_review" {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
		result.ProductID, result.ReleaseID = value.ProductID, value.ReleaseID
	case "customer_package":
		value, ok := ledger.customerPackages[id]
		if !ok || value.TenantID != tenantID {
			return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
		}
		result.ProductID, result.ReleaseID = value.ProductID, value.ReleaseID
	default:
		return riskapp.GovernanceSubjectReference{}, riskapp.ErrNotFound
	}
	return result, nil
}

func listRiskDecisionsLocked(ledger *Ledger, tenantID string) ([]riskdomain.VulnerabilityDecision, error) {
	result := make([]riskdomain.VulnerabilityDecision, 0)
	for _, value := range ledger.decisions {
		if value.TenantID != tenantID {
			continue
		}
		mapped, err := domain.VulnerabilityDecisionToContextModel(value)
		if err != nil {
			return nil, riskapp.ErrValidation
		}
		result = append(result, mapped)
	}
	return result, nil
}

func listRiskExceptionsLocked(ledger *Ledger, tenantID string) []riskdomain.Exception {
	result := make([]riskdomain.Exception, 0)
	for _, value := range ledger.exceptions {
		if value.TenantID == tenantID {
			result = append(result, exceptionToRiskContext(value))
		}
	}
	return result
}

func exceptionToRiskContext(value domain.Exception) riskdomain.Exception {
	return riskdomain.Exception{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, FindingID: value.FindingID,
		ControlID: value.ControlID, Reason: value.Reason, Owner: value.Owner, ExpiresAt: value.ExpiresAt,
		Approved: value.Approved, ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt), CreatedAt: value.CreatedAt,
	}
}

func exceptionFromRiskContext(value riskdomain.Exception) domain.Exception {
	return domain.Exception{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, FindingID: value.FindingID,
		ControlID: value.ControlID, Reason: value.Reason, Owner: value.Owner, ExpiresAt: value.ExpiresAt,
		Approved: value.Approved, ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt), CreatedAt: value.CreatedAt,
	}
}

func waiverToRiskContext(value domain.Waiver) riskdomain.Waiver {
	return riskdomain.Waiver{
		ID: value.ID, TenantID: value.TenantID, ScopeType: value.ScopeType, ScopeID: value.ScopeID,
		ControlID: value.ControlID, PolicyID: value.PolicyID, Owner: value.Owner, Risk: value.Risk, Reason: value.Reason,
		ExpiresAt: value.ExpiresAt, Approved: value.Approved, ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt),
		Supersedes: value.Supersedes, SupersededBy: value.SupersededBy, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func waiverFromRiskContext(value riskdomain.Waiver) domain.Waiver {
	return domain.Waiver{
		ID: value.ID, TenantID: value.TenantID, ScopeType: value.ScopeType, ScopeID: value.ScopeID,
		ControlID: value.ControlID, PolicyID: value.PolicyID, Owner: value.Owner, Risk: value.Risk, Reason: value.Reason,
		ExpiresAt: value.ExpiresAt, Approved: value.Approved, ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt),
		Supersedes: value.Supersedes, SupersededBy: value.SupersededBy, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func approvalFromRiskContext(value riskdomain.ApprovalRecord) domain.ApprovalRecord {
	return domain.ApprovalRecord{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		Decision: value.Decision, Reason: value.Reason, ApproverID: value.ApproverID, EvidenceID: value.EvidenceID,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func policyEvaluationFromRiskContext(value riskdomain.PolicyEvaluation) domain.PolicyEvaluation {
	checks := make([]domain.PolicyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, domain.PolicyCheck{
			Name: check.Name, Result: check.Result, Severity: check.Severity,
			Missing: append([]string(nil), check.Missing...), Explanation: check.Explanation, Remediation: check.Remediation,
		})
	}
	return domain.PolicyEvaluation{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Result: value.Result,
		PolicySet: value.PolicySet, Checks: checks, CreatedAt: value.CreatedAt,
	}
}

func policyEvaluationToRiskContext(value domain.PolicyEvaluation) riskdomain.PolicyEvaluation {
	checks := make([]riskdomain.PolicyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, riskdomain.PolicyCheck{
			Name: check.Name, Result: check.Result, Severity: check.Severity,
			Missing: append([]string(nil), check.Missing...), Explanation: check.Explanation, Remediation: check.Remediation,
		})
	}
	return riskdomain.PolicyEvaluation{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Result: value.Result,
		PolicySet: value.PolicySet, Checks: checks, CreatedAt: value.CreatedAt,
	}
}

func cloneRiskWaiverMap(values map[string]domain.Waiver) map[string]domain.Waiver {
	result := make(map[string]domain.Waiver, len(values))
	for key, value := range values {
		value.ApprovedAt = cloneTimePtr(value.ApprovedAt)
		result[key] = value
	}
	return result
}

func cloneRiskApprovalMap(values map[string]domain.ApprovalRecord) map[string]domain.ApprovalRecord {
	result := make(map[string]domain.ApprovalRecord, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneRiskPolicyEvaluationMap(values map[string]domain.PolicyEvaluation) map[string]domain.PolicyEvaluation {
	result := make(map[string]domain.PolicyEvaluation, len(values))
	for key, value := range values {
		result[key] = policyEvaluationFromRiskContext(policyEvaluationToRiskContext(value))
	}
	return result
}

func cloneRiskExceptionMap(values map[string]domain.Exception) map[string]domain.Exception {
	result := make(map[string]domain.Exception, len(values))
	for key, value := range values {
		value.ApprovedAt = cloneTimePtr(value.ApprovedAt)
		result[key] = value
	}
	return result
}

func sameExceptionApproval(left, right domain.Exception) bool {
	if left.Approved != right.Approved || left.ApprovedBy != right.ApprovedBy {
		return false
	}
	if left.ApprovedAt == nil || right.ApprovedAt == nil {
		return left.ApprovedAt == nil && right.ApprovedAt == nil
	}
	return left.ApprovedAt.Equal(*right.ApprovedAt)
}

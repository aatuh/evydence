// Package app owns vulnerability-decision and governance command orchestration.
package app

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const (
	ScopeEvidenceWrite = "evidence:write"
	ScopeEvidenceRead  = "evidence:read"
	ScopeReleaseWrite  = "release:write"
	ScopeVerifyRead    = "verify:read"
	ScopeReportRead    = "report:read"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrForbidden  = application.ErrForbidden
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
)

// FindingReference is the immutable, identifier-only evidence view required
// to bind a decision to one tenant-owned finding.
type FindingReference struct {
	ID                string
	ScanID            string
	TenantID          string
	ReleaseID         string
	ProductID         string
	Vulnerability     string
	Component         string
	Severity          string
	State             string
	SBOMID            string
	SBOMComponentPURL string
	SBOMComponentName string
}

type ProductReference struct {
	ID       string
	TenantID string
}

type ReleaseReference struct {
	ID        string
	TenantID  string
	ProductID string
}

type EvidenceReference struct {
	ID        string
	TenantID  string
	ReleaseID string
}

type VEXReference struct {
	ID         string
	TenantID   string
	ReleaseID  string
	EvidenceID string
}

type ControlReference struct {
	ID       string
	TenantID string
}

// GovernanceSubjectReference is the minimum cross-context coordinate needed
// to authorize a waiver or approval without importing another aggregate.
type GovernanceSubjectReference struct {
	Type      string
	ID        string
	TenantID  string
	ProductID string
	ReleaseID string
}

// Reader exposes only the committed, tenant-scoped references and risk
// records needed by this context. Implementations must never return a record
// owned by another tenant for the requested tenant ID.
type Reader interface {
	ResolveFinding(context.Context, string, string) (FindingReference, error)
	GetProduct(context.Context, string, string) (ProductReference, error)
	GetRelease(context.Context, string, string) (ReleaseReference, error)
	GetEvidence(context.Context, string, string) (EvidenceReference, error)
	GetVEX(context.Context, string, string) (VEXReference, error)
	GetControl(context.Context, string, string) (ControlReference, error)
	ValidateSupportingReference(context.Context, string, string, string, riskdomain.SupportingReference) error
	ResolveGovernanceSubject(context.Context, string, string, string) (GovernanceSubjectReference, error)
	ListVulnerabilityDecisions(context.Context, string) ([]riskdomain.VulnerabilityDecision, error)
	ListExceptions(context.Context, string) ([]riskdomain.Exception, error)
	ReadReleaseReadinessSnapshot(context.Context, string, string) (ReadinessSnapshot, error)
}

// Repository is transaction scoped. Its reads and compare-and-swap writes
// must remain stable until the surrounding transaction commits.
type Repository interface {
	Reader
	SupersedeAndInsert(context.Context, riskdomain.VulnerabilityDecision, []riskdomain.VulnerabilityDecision) error
	InsertException(context.Context, riskdomain.Exception) error
	GetExceptionForUpdate(context.Context, string, string) (riskdomain.Exception, error)
	ApproveException(context.Context, riskdomain.Exception) error
	InsertPolicyEvaluation(context.Context, riskdomain.PolicyEvaluation) error
}

type Transaction interface {
	Decisions() Repository
	Governance() GovernanceRepository
	Authorization() application.Authorizer
	Audit() application.AuditAppender
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

// ProjectionRefresher is a temporary compatibility boundary for worker-owned
// evidence projections. Database-backed query services replace it in EVY-905.
type ProjectionRefresher interface {
	RefreshRiskProjection(context.Context, string) error
}

type Config struct {
	Reader              Reader
	Transactions        TransactionRunner
	Authorizer          application.Authorizer
	ProjectionRefresher ProjectionRefresher
	Clock               application.Clock
	IDs                 application.IDGenerator
}

type Service struct {
	reader              Reader
	transactions        TransactionRunner
	authorizer          application.Authorizer
	projectionRefresher ProjectionRefresher
	clock               application.Clock
	ids                 application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &Service{
		reader: config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		projectionRefresher: config.ProjectionRefresher, clock: config.Clock, ids: config.IDs,
	}, nil
}

type CreateVulnerabilityDecisionInput struct {
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	CustomerVisible bool
	InternalNotes   string
	EvidenceIDs     []string
	SupportingRefs  []riskdomain.SupportingReference
	VEXDocumentID   string
	ReviewedAt      *time.Time
	ReviewDueAt     *time.Time
}

type ListVulnerabilityDecisionsInput struct {
	ProductID     string
	ReleaseID     string
	Vulnerability string
	Component     string
	Status        string
	Active        *bool
}

func (s *Service) CreateVulnerabilityDecision(ctx context.Context, actor identitydomain.Actor, findingID string, input CreateVulnerabilityDecisionInput) (riskdomain.VulnerabilityDecision, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	findingID = strings.TrimSpace(findingID)
	normalized, err := normalizeDecisionInput(input, s.clock.Now())
	if findingID == "" || err != nil {
		return riskdomain.VulnerabilityDecision{}, ErrValidation
	}
	if err := s.refresh(ctx, actor.TenantID); err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	preflight, err := s.reader.ResolveFinding(ctx, actor.TenantID, findingID)
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	if !validFindingReference(preflight, actor.TenantID, findingID) {
		return riskdomain.VulnerabilityDecision{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceWrite, application.ResourceReferences{ProductID: preflight.ProductID, ReleaseID: preflight.ReleaseID}, false); err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}

	var created riskdomain.VulnerabilityDecision
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		finding, err := tx.Decisions().ResolveFinding(ctx, actor.TenantID, findingID)
		if err != nil {
			return err
		}
		if !validFindingReference(finding, actor.TenantID, findingID) || finding != preflight {
			return ErrConflict
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{
			Scope: ScopeEvidenceWrite, Resources: application.ResourceReferences{ProductID: finding.ProductID, ReleaseID: finding.ReleaseID},
		}); err != nil {
			return err
		}
		validated, err := validateDecisionReferences(ctx, tx.Decisions(), actor.TenantID, finding.ReleaseID, finding.ProductID, normalized)
		if err != nil {
			return err
		}
		current, err := tx.Decisions().ListVulnerabilityDecisions(ctx, actor.TenantID)
		if err != nil {
			return err
		}
		created, current, err = s.prepareDecision(actor, finding, validated, current, "api", "", "")
		if err != nil {
			return err
		}
		if err := tx.Decisions().SupersedeAndInsert(ctx, created, current); err != nil {
			return err
		}
		for _, prior := range current {
			if _, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, created.CreatedAt, "vulnerability_decision.superseded", "vulnerability_decision", prior.ID)); err != nil {
				return err
			}
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, created.CreatedAt, "vulnerability_decision.created", "vulnerability_finding", finding.ID))
		return err
	})
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, err
	}
	return cloneDecision(created), nil
}

func (s *Service) ListVulnerabilityDecisions(ctx context.Context, actor identitydomain.Actor, input ListVulnerabilityDecisionsInput) ([]riskdomain.VulnerabilityDecision, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.Vulnerability = strings.TrimSpace(input.Vulnerability)
	input.Component = strings.TrimSpace(input.Component)
	input.Status = strings.TrimSpace(input.Status)
	if input.Status != "" {
		if _, err := riskdomain.ParseDecisionStatus(input.Status); err != nil {
			return nil, ErrValidation
		}
	}
	if err := s.refresh(ctx, actor.TenantID); err != nil {
		return nil, err
	}
	if input.ProductID != "" {
		product, err := s.reader.GetProduct(ctx, actor.TenantID, input.ProductID)
		if err != nil {
			return nil, err
		}
		if product.ID != input.ProductID || product.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ProductID: product.ID}, false); err != nil {
			return nil, err
		}
	}
	if input.ReleaseID != "" {
		release, err := s.reader.GetRelease(ctx, actor.TenantID, input.ReleaseID)
		if err != nil {
			return nil, err
		}
		if !validReleaseReference(release, actor.TenantID, input.ReleaseID) || (input.ProductID != "" && input.ProductID != release.ProductID) {
			return nil, ErrNotFound
		}
		if input.ProductID == "" {
			input.ProductID = release.ProductID
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
			return nil, err
		}
	}
	values, err := s.reader.ListVulnerabilityDecisions(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]riskdomain.VulnerabilityDecision, 0, len(values))
	for _, value := range values {
		if value.TenantID != actor.TenantID || (input.ReleaseID != "" && value.ReleaseID != input.ReleaseID) || (input.Vulnerability != "" && value.Vulnerability != input.Vulnerability) || (input.Component != "" && value.Component != input.Component) || (input.Status != "" && value.Status.String() != input.Status) || (input.Active != nil && *input.Active != (value.SupersededBy == "")) {
			continue
		}
		release, err := s.reader.GetRelease(ctx, actor.TenantID, value.ReleaseID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !validReleaseReference(release, actor.TenantID, value.ReleaseID) || (input.ProductID != "" && release.ProductID != input.ProductID) {
			continue
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return nil, err
		}
		result = append(result, cloneDecision(value))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) VulnerabilityDecisionSummaryReport(ctx context.Context, actor identitydomain.Actor, releaseID string) (riskdomain.VulnerabilityDecisionSummaryReport, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReportRead, application.ResourceReferences{}, true); err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, ErrValidation
	}
	if err := s.refresh(ctx, actor.TenantID); err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, releaseID)
	if err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	if !validReleaseReference(release, actor.TenantID, releaseID) {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReportRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	values, err := s.reader.ListVulnerabilityDecisions(ctx, actor.TenantID)
	if err != nil {
		return riskdomain.VulnerabilityDecisionSummaryReport{}, err
	}
	decisions := make([]riskdomain.VulnerabilityDecisionCustomerSummary, 0)
	for _, value := range values {
		if value.TenantID != actor.TenantID || value.ReleaseID != release.ID || value.SupersededBy != "" || !value.CustomerVisible {
			continue
		}
		decisions = append(decisions, customerDecisionSummary(value))
	}
	sort.Slice(decisions, func(i, j int) bool {
		if decisions[i].CreatedAt.Equal(decisions[j].CreatedAt) {
			return decisions[i].ID < decisions[j].ID
		}
		return decisions[i].CreatedAt.Before(decisions[j].CreatedAt)
	})
	return riskdomain.VulnerabilityDecisionSummaryReport{
		ReportType: "vulnerability_decision_summary", TemplateVersion: "vulnerability-decision-summary.v1.0.0",
		ProductID: release.ProductID, ReleaseID: release.ID, Decisions: decisions,
		Assumptions: []string{
			"Only active vulnerability decisions marked customer_visible are included.",
			"Evidence identifiers point to records in this Evydence instance; raw evidence payload bytes are not included.",
			"reviewed_at records when the decision was reviewed; missing review_due_at means no scheduled follow-up review was recorded.",
		},
		Limitations: []string{
			"This summary supports compliance-readiness review; it is not certification, legal advice, complete SBOM proof, or authoritative vulnerability coverage.",
			"Decision accuracy depends on tenant-supplied evidence, scanner inputs, and review quality.",
			"Review dates are tenant-supplied metadata and do not prove that the underlying vulnerability analysis is still correct.",
		},
		GeneratedAt: s.clock.Now().UTC(),
	}, nil
}

type CreateExceptionInput struct {
	ReleaseID string
	FindingID string
	ControlID string
	Reason    string
	Owner     string
	ExpiresAt time.Time
}

func (s *Service) CreateException(ctx context.Context, actor identitydomain.Actor, input CreateExceptionInput) (riskdomain.Exception, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.Exception{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.Exception{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.Exception{}, err
	}
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.FindingID = strings.TrimSpace(input.FindingID)
	input.ControlID = strings.TrimSpace(input.ControlID)
	input.Reason = strings.TrimSpace(input.Reason)
	input.Owner = strings.TrimSpace(input.Owner)
	now := s.clock.Now().UTC()
	if input.ReleaseID == "" || input.Reason == "" || input.Owner == "" || !input.ExpiresAt.After(now) {
		return riskdomain.Exception{}, ErrValidation
	}
	if input.FindingID != "" {
		if err := s.refresh(ctx, actor.TenantID); err != nil {
			return riskdomain.Exception{}, err
		}
	}
	release, err := s.reader.GetRelease(ctx, actor.TenantID, input.ReleaseID)
	if err != nil {
		return riskdomain.Exception{}, err
	}
	if !validReleaseReference(release, actor.TenantID, input.ReleaseID) {
		return riskdomain.Exception{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
		return riskdomain.Exception{}, err
	}

	exception := riskdomain.Exception{
		ID: s.ids.NewID("ex"), TenantID: actor.TenantID, ReleaseID: input.ReleaseID, FindingID: input.FindingID,
		ControlID: input.ControlID, Reason: input.Reason, Owner: input.Owner, ExpiresAt: input.ExpiresAt.UTC(), CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		currentRelease, err := tx.Decisions().GetRelease(ctx, actor.TenantID, input.ReleaseID)
		if err != nil {
			return err
		}
		if currentRelease != release {
			return ErrConflict
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}}); err != nil {
			return err
		}
		if input.FindingID != "" {
			finding, err := tx.Decisions().ResolveFinding(ctx, actor.TenantID, input.FindingID)
			if err != nil {
				return err
			}
			if finding.TenantID != actor.TenantID || finding.ReleaseID != input.ReleaseID {
				return ErrNotFound
			}
		}
		if input.ControlID != "" {
			control, err := tx.Decisions().GetControl(ctx, actor.TenantID, input.ControlID)
			if err != nil {
				return err
			}
			if control.ID != input.ControlID || control.TenantID != actor.TenantID {
				return ErrNotFound
			}
		}
		if err := tx.Decisions().InsertException(ctx, exception); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "exception.created", "exception", exception.ID))
		return err
	})
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return cloneException(exception), nil
}

func (s *Service) ListExceptions(ctx context.Context, actor identitydomain.Actor, releaseID string) ([]riskdomain.Exception, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, true); err != nil {
		return nil, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID != "" {
		release, err := s.reader.GetRelease(ctx, actor.TenantID, releaseID)
		if err != nil {
			return nil, err
		}
		if !validReleaseReference(release, actor.TenantID, releaseID) {
			return nil, ErrNotFound
		}
		if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
			return nil, err
		}
	}
	values, err := s.reader.ListExceptions(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]riskdomain.Exception, 0, len(values))
	for _, value := range values {
		if value.TenantID != actor.TenantID || (releaseID != "" && value.ReleaseID != releaseID) {
			continue
		}
		release, err := s.reader.GetRelease(ctx, actor.TenantID, value.ReleaseID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}, false); err != nil {
			if errors.Is(err, ErrForbidden) {
				continue
			}
			return nil, err
		}
		result = append(result, cloneException(value))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (s *Service) ApproveException(ctx context.Context, actor identitydomain.Actor, id string) (riskdomain.Exception, error) {
	if err := contextError(ctx); err != nil {
		return riskdomain.Exception{}, err
	}
	if err := validateActor(actor); err != nil {
		return riskdomain.Exception{}, err
	}
	if err := s.authorize(ctx, actor, ScopeReleaseWrite, application.ResourceReferences{}, true); err != nil {
		return riskdomain.Exception{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return riskdomain.Exception{}, ErrNotFound
	}
	now := s.clock.Now().UTC()
	var approved riskdomain.Exception
	err := s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		value, err := tx.Decisions().GetExceptionForUpdate(ctx, actor.TenantID, id)
		if err != nil {
			return err
		}
		if value.ID != id || value.TenantID != actor.TenantID {
			return ErrNotFound
		}
		if !value.ExpiresAt.After(now) {
			return ErrConflict
		}
		release, err := tx.Decisions().GetRelease(ctx, actor.TenantID, value.ReleaseID)
		if err != nil {
			return err
		}
		if !validReleaseReference(release, actor.TenantID, value.ReleaseID) {
			return ErrNotFound
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: release.ProductID, ReleaseID: release.ID}}); err != nil {
			return err
		}
		if value.Approved {
			approved = value
			return nil
		}
		value.Approved = true
		value.ApprovedBy = auditActorID(actor)
		value.ApprovedAt = cloneTimePointer(&now)
		if err := tx.Decisions().ApproveException(ctx, value); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "exception.approved", "exception", value.ID)); err != nil {
			return err
		}
		approved = value
		return nil
	})
	if err != nil {
		return riskdomain.Exception{}, err
	}
	return cloneException(approved), nil
}

func normalizeDecisionInput(input CreateVulnerabilityDecisionInput, now time.Time) (CreateVulnerabilityDecisionInput, error) {
	status, err := riskdomain.ParseDecisionStatus(input.Status)
	if err != nil {
		return CreateVulnerabilityDecisionInput{}, ErrValidation
	}
	input.Status = status.String()
	input.Justification = strings.TrimSpace(input.Justification)
	input.ImpactStatement = strings.TrimSpace(input.ImpactStatement)
	input.ActionStatement = strings.TrimSpace(input.ActionStatement)
	input.InternalNotes = strings.TrimSpace(input.InternalNotes)
	input.VEXDocumentID = strings.TrimSpace(input.VEXDocumentID)
	if input.Justification == "" || len(input.InternalNotes) > 8192 || (input.CustomerVisible && input.ImpactStatement == "") {
		return CreateVulnerabilityDecisionInput{}, ErrValidation
	}
	now = now.UTC()
	reviewedAt := now
	if input.ReviewedAt != nil {
		if input.ReviewedAt.IsZero() || input.ReviewedAt.After(now.Add(time.Minute)) {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		reviewedAt = input.ReviewedAt.UTC()
	}
	input.ReviewedAt = cloneTimePointer(&reviewedAt)
	if input.ReviewDueAt != nil {
		if input.ReviewDueAt.IsZero() || !input.ReviewDueAt.After(reviewedAt) {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		dueAt := input.ReviewDueAt.UTC()
		input.ReviewDueAt = &dueAt
	}
	ids := make([]string, 0, len(input.EvidenceIDs))
	seen := map[string]struct{}{}
	for _, raw := range input.EvidenceIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	input.EvidenceIDs = ids
	if len(input.SupportingRefs) > 20 {
		return CreateVulnerabilityDecisionInput{}, ErrValidation
	}
	refs := make([]riskdomain.SupportingReference, 0, len(input.SupportingRefs))
	seenRefs := map[string]struct{}{}
	for _, reference := range input.SupportingRefs {
		reference.Type = strings.ToLower(strings.TrimSpace(reference.Type))
		reference.ID = strings.TrimSpace(reference.ID)
		if reference.Type == "" || reference.ID == "" || strings.TrimSpace(reference.Digest) != "" {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		key := reference.Type + "\x00" + reference.ID
		if _, ok := seenRefs[key]; ok {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		seenRefs[key] = struct{}{}
		refs = append(refs, reference)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Type == refs[j].Type {
			return refs[i].ID < refs[j].ID
		}
		return refs[i].Type < refs[j].Type
	})
	input.SupportingRefs = refs
	return input, nil
}

func validateDecisionReferences(ctx context.Context, repository Repository, tenantID, releaseID, productID string, input CreateVulnerabilityDecisionInput) (CreateVulnerabilityDecisionInput, error) {
	if input.VEXDocumentID != "" {
		vex, err := repository.GetVEX(ctx, tenantID, input.VEXDocumentID)
		if err != nil {
			return CreateVulnerabilityDecisionInput{}, err
		}
		if vex.ID != input.VEXDocumentID || vex.TenantID != tenantID || vex.ReleaseID != releaseID {
			return CreateVulnerabilityDecisionInput{}, ErrNotFound
		}
	}
	for _, id := range input.EvidenceIDs {
		item, err := repository.GetEvidence(ctx, tenantID, id)
		if err != nil {
			return CreateVulnerabilityDecisionInput{}, err
		}
		if item.ID != id || item.TenantID != tenantID || (item.ReleaseID != "" && releaseID != "" && item.ReleaseID != releaseID) {
			return CreateVulnerabilityDecisionInput{}, ErrNotFound
		}
	}
	for _, reference := range input.SupportingRefs {
		if releaseID == "" {
			return CreateVulnerabilityDecisionInput{}, ErrValidation
		}
		if err := repository.ValidateSupportingReference(ctx, tenantID, productID, releaseID, reference); err != nil {
			return CreateVulnerabilityDecisionInput{}, err
		}
	}
	return input, nil
}

func (s *Service) prepareDecision(actor identitydomain.Actor, finding FindingReference, input CreateVulnerabilityDecisionInput, existing []riskdomain.VulnerabilityDecision, source, evidenceID, vexID string) (riskdomain.VulnerabilityDecision, []riskdomain.VulnerabilityDecision, error) {
	status, err := riskdomain.ParseDecisionStatus(input.Status)
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, nil, ErrValidation
	}
	id := s.ids.NewID("vd")
	superseded := make([]riskdomain.VulnerabilityDecision, 0)
	supersedes := ""
	for _, current := range existing {
		if current.TenantID != actor.TenantID || current.FindingID != finding.ID || current.SupersededBy != "" {
			continue
		}
		if !current.Status.CanTransitionTo(status) {
			return riskdomain.VulnerabilityDecision{}, nil, ErrValidation
		}
		current.SupersededBy = id
		if supersedes == "" {
			supersedes = current.ID
		}
		superseded = append(superseded, cloneDecision(current))
	}
	sort.Slice(superseded, func(i, j int) bool { return superseded[i].ID < superseded[j].ID })
	if vexID == "" {
		vexID = input.VEXDocumentID
	}
	evidenceIDs := append([]string(nil), input.EvidenceIDs...)
	if evidenceID != "" {
		found := false
		for _, id := range evidenceIDs {
			found = found || id == evidenceID
		}
		if !found {
			evidenceIDs = append(evidenceIDs, evidenceID)
			sort.Strings(evidenceIDs)
		}
	}
	created := riskdomain.VulnerabilityDecision{
		ID: id, TenantID: actor.TenantID, FindingID: finding.ID, ScanID: finding.ScanID, ReleaseID: finding.ReleaseID,
		Vulnerability: finding.Vulnerability, Component: finding.Component, SBOMID: finding.SBOMID,
		SBOMComponentPURL: finding.SBOMComponentPURL, SBOMComponentName: finding.SBOMComponentName,
		Status: status, Justification: input.Justification, ImpactStatement: input.ImpactStatement, ActionStatement: input.ActionStatement,
		CustomerVisible: input.CustomerVisible, InternalNotes: input.InternalNotes, Source: source, EvidenceID: evidenceID,
		EvidenceIDs: evidenceIDs, SupportingRefs: append([]riskdomain.SupportingReference(nil), input.SupportingRefs...),
		VEXDocumentID: vexID, Supersedes: supersedes, ApprovedBy: auditActorID(actor), ReviewedAt: cloneTimePointer(input.ReviewedAt),
		ReviewDueAt: cloneTimePointer(input.ReviewDueAt), SchemaVersion: riskdomain.VulnerabilityDecisionVersion, CreatedAt: s.clock.Now().UTC(),
	}
	return created, superseded, nil
}

func (s *Service) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly})
}

func (s *Service) refresh(ctx context.Context, tenantID string) error {
	if s.projectionRefresher == nil {
		return nil
	}
	return s.projectionRefresher.RefreshRiskProjection(ctx, tenantID)
}

func (s *Service) auditEvent(actor identitydomain.Actor, at time.Time, entryType, subjectType, subjectID string) application.AuditEvent {
	return application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: subjectType,
		SubjectID: subjectID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC(),
	}
}

func validateActor(actor identitydomain.Actor) error {
	if strings.TrimSpace(actor.TenantID) == "" || auditActorID(actor) == "" {
		return ErrForbidden
	}
	return nil
}

func validFindingReference(value FindingReference, tenantID, id string) bool {
	return value.ID == id && value.TenantID == tenantID && value.ReleaseID != "" && value.ScanID != ""
}

func validReleaseReference(value ReleaseReference, tenantID, id string) bool {
	return value.ID == id && value.TenantID == tenantID && value.ProductID != ""
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func auditActorType(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func auditActorID(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return strings.TrimSpace(actor.CollectorID)
	}
	if actor.UserID != "" {
		return strings.TrimSpace(actor.UserID)
	}
	return strings.TrimSpace(actor.KeyID)
}

func cloneDecision(value riskdomain.VulnerabilityDecision) riskdomain.VulnerabilityDecision {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.SupportingRefs = append([]riskdomain.SupportingReference(nil), value.SupportingRefs...)
	value.ReviewedAt = cloneTimePointer(value.ReviewedAt)
	value.ReviewDueAt = cloneTimePointer(value.ReviewDueAt)
	return value
}

func cloneException(value riskdomain.Exception) riskdomain.Exception {
	value.ApprovedAt = cloneTimePointer(value.ApprovedAt)
	return value
}

func customerDecisionSummary(value riskdomain.VulnerabilityDecision) riskdomain.VulnerabilityDecisionCustomerSummary {
	return riskdomain.VulnerabilityDecisionCustomerSummary{
		ID: value.ID, FindingID: value.FindingID, ScanID: value.ScanID, ReleaseID: value.ReleaseID,
		Vulnerability: value.Vulnerability, Component: value.Component, SBOMID: value.SBOMID,
		SBOMComponentPURL: value.SBOMComponentPURL, SBOMComponentName: value.SBOMComponentName,
		Status: value.Status.String(), Justification: value.Justification, ImpactStatement: value.ImpactStatement,
		ActionStatement: value.ActionStatement, Source: value.Source, EvidenceID: value.EvidenceID,
		EvidenceIDs: append([]string(nil), value.EvidenceIDs...), SupportingRefs: append([]riskdomain.SupportingReference(nil), value.SupportingRefs...),
		VEXDocumentID: value.VEXDocumentID, ReviewedAt: cloneTimePointer(value.ReviewedAt), ReviewDueAt: cloneTimePointer(value.ReviewDueAt),
		CreatedAt: value.CreatedAt,
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

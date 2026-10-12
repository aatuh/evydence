package app

import (
	"sort"
	"strings"
	"time"

	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// VEXStatement is the parser-independent decision input produced from a
// validated OpenVEX or CycloneDX document.
type VEXStatement struct {
	Index           int
	Vulnerability   string
	Products        []string
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
}

// VEXFinding is the immutable, tenant-scoped finding view used for matching.
type VEXFinding struct {
	ID                string
	ScanID            string
	TenantID          string
	ReleaseID         string
	Vulnerability     string
	Component         string
	SBOMID            string
	SBOMComponentPURL string
	SBOMComponentName string
}

type VEXMappingInput struct {
	TenantID          string
	ReleaseID         string
	VEXDocumentID     string
	EvidenceID        string
	ActorID           string
	Source            string
	CreatedAt         time.Time
	Statements        []VEXStatement
	Findings          []VEXFinding
	ExistingDecisions []riskdomain.VulnerabilityDecision
}

type VEXMappingFailure struct {
	StatementIndex int
	Code           string
	Detail         string
}

type VEXMappingResult struct {
	Created      []riskdomain.VulnerabilityDecision
	Superseded   []riskdomain.VulnerabilityDecision
	Failures     []VEXMappingFailure
	HadDuplicate bool
}

type VEXDecisionIDGenerator interface {
	DecisionID(string, string, string) string
}

type VEXDecisionIDFunc func(string, string, string) string

func (f VEXDecisionIDFunc) DecisionID(vexID, findingID, status string) string {
	return f(vexID, findingID, status)
}

// MapVEXDecisions applies parser-independent matching, ambiguity,
// idempotency, and append-only supersession policy without persistence or
// network access.
func MapVEXDecisions(input VEXMappingInput, ids VEXDecisionIDGenerator) (VEXMappingResult, error) {
	input = normalizeVEXMappingInput(input)
	if ids == nil || input.TenantID == "" || input.ReleaseID == "" || input.VEXDocumentID == "" || input.ActorID == "" || input.Source == "" || input.CreatedAt.IsZero() {
		return VEXMappingResult{}, ErrValidation
	}
	findings := append([]VEXFinding(nil), input.Findings...)
	for index := range findings {
		findings[index] = normalizeVEXFinding(findings[index])
		if findings[index].ID == "" || findings[index].ScanID == "" || findings[index].TenantID != input.TenantID || findings[index].ReleaseID != input.ReleaseID || findings[index].Vulnerability == "" {
			return VEXMappingResult{}, ErrNotFound
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ScanID == findings[j].ScanID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].ScanID < findings[j].ScanID
	})
	decisions := make(map[string]riskdomain.VulnerabilityDecision, len(input.ExistingDecisions))
	for _, decision := range input.ExistingDecisions {
		if decision.ID == "" || decision.TenantID != input.TenantID || (decision.ReleaseID != "" && decision.ReleaseID != input.ReleaseID) {
			return VEXMappingResult{}, ErrNotFound
		}
		decisions[decision.ID] = cloneDecision(decision)
	}
	result := VEXMappingResult{}
	seenFindings := map[string]struct{}{}
	for statementOffset, statement := range input.Statements {
		statement = normalizeVEXStatement(statement)
		statementIndex := statement.Index
		if statementIndex <= 0 {
			statementIndex = statementOffset + 1
		}
		status, err := riskdomain.ParseDecisionStatus(statement.Status)
		if err != nil || statement.Vulnerability == "" {
			return VEXMappingResult{}, ErrValidation
		}
		matches := matchingVEXFindings(findings, statement)
		if !unambiguousVEXMatches(matches, statement.Products) {
			result.Failures = append(result.Failures, VEXMappingFailure{StatementIndex: statementIndex, Code: "ambiguous_finding", Detail: "Multiple plausible findings matched this VEX statement; no decision was applied."})
			continue
		}
		if len(matches) == 0 {
			result.Failures = append(result.Failures, VEXMappingFailure{StatementIndex: statementIndex, Code: "finding_not_found", Detail: "No matching vulnerability scan finding was found for this VEX statement."})
			continue
		}
		for _, finding := range matches {
			if _, seen := seenFindings[finding.ID]; seen {
				result.HadDuplicate = true
				continue
			}
			seenFindings[finding.ID] = struct{}{}
			if vexDecisionExists(decisions, input.VEXDocumentID, finding.ID) {
				continue
			}
			decisionID := strings.TrimSpace(ids.DecisionID(input.VEXDocumentID, finding.ID, status.String()))
			if decisionID == "" {
				return VEXMappingResult{}, ErrValidation
			}
			if _, exists := decisions[decisionID]; exists {
				continue
			}
			activeIDs := activeVEXDecisionIDs(decisions, finding.ID)
			for _, activeID := range activeIDs {
				prior := decisions[activeID]
				prior.SupersededBy = decisionID
				decisions[activeID] = prior
				result.Superseded = append(result.Superseded, cloneDecision(prior))
			}
			var supersedes string
			if len(activeIDs) > 0 {
				supersedes = activeIDs[0]
			}
			reviewedAt := input.CreatedAt
			var evidenceIDs []string
			if input.EvidenceID != "" {
				evidenceIDs = []string{input.EvidenceID}
			}
			decision := riskdomain.VulnerabilityDecision{
				ID: decisionID, TenantID: input.TenantID, FindingID: finding.ID, ScanID: finding.ScanID,
				ReleaseID: input.ReleaseID, Vulnerability: finding.Vulnerability, Component: finding.Component,
				SBOMID: finding.SBOMID, SBOMComponentPURL: finding.SBOMComponentPURL, SBOMComponentName: finding.SBOMComponentName,
				Status: status, Justification: statement.Justification, ImpactStatement: statement.ImpactStatement,
				ActionStatement: statement.ActionStatement, CustomerVisible: statement.ImpactStatement != "",
				Source: input.Source, EvidenceID: input.EvidenceID, EvidenceIDs: evidenceIDs,
				VEXDocumentID: input.VEXDocumentID, Supersedes: supersedes, ApprovedBy: input.ActorID,
				ReviewedAt: &reviewedAt, SchemaVersion: riskdomain.VulnerabilityDecisionVersion, CreatedAt: input.CreatedAt,
			}
			decisions[decision.ID] = decision
			result.Created = append(result.Created, cloneDecision(decision))
		}
	}
	return result, nil
}

func matchingVEXFindings(findings []VEXFinding, statement VEXStatement) []VEXFinding {
	products := make(map[string]struct{}, len(statement.Products))
	for _, product := range statement.Products {
		products[product] = struct{}{}
	}
	result := make([]VEXFinding, 0)
	for _, finding := range findings {
		if finding.Vulnerability != statement.Vulnerability {
			continue
		}
		if len(products) > 0 && finding.Component != "" {
			if _, ok := products[finding.Component]; !ok {
				continue
			}
		}
		result = append(result, finding)
	}
	return result
}

func unambiguousVEXMatches(matches []VEXFinding, products []string) bool {
	if len(matches) < 2 {
		return true
	}
	components := map[string]struct{}{}
	for _, finding := range matches {
		if finding.Component == "" {
			return false
		}
		if _, duplicate := components[finding.Component]; duplicate {
			return false
		}
		components[finding.Component] = struct{}{}
	}
	return len(products) > 0 && len(matches) <= len(products)
}

func vexDecisionExists(decisions map[string]riskdomain.VulnerabilityDecision, vexID, findingID string) bool {
	for _, decision := range decisions {
		if decision.VEXDocumentID == vexID && decision.FindingID == findingID {
			return true
		}
	}
	return false
}

func activeVEXDecisionIDs(decisions map[string]riskdomain.VulnerabilityDecision, findingID string) []string {
	result := make([]string, 0)
	for id, decision := range decisions {
		if decision.FindingID == findingID && decision.SupersededBy == "" {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

func normalizeVEXMappingInput(input VEXMappingInput) VEXMappingInput {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.VEXDocumentID = strings.TrimSpace(input.VEXDocumentID)
	input.EvidenceID = strings.TrimSpace(input.EvidenceID)
	input.ActorID = strings.TrimSpace(input.ActorID)
	input.Source = strings.TrimSpace(input.Source)
	input.CreatedAt = input.CreatedAt.UTC()
	return input
}

func normalizeVEXStatement(value VEXStatement) VEXStatement {
	value.Vulnerability = strings.TrimSpace(value.Vulnerability)
	value.Status = strings.TrimSpace(value.Status)
	value.Justification = strings.TrimSpace(value.Justification)
	value.ImpactStatement = strings.TrimSpace(value.ImpactStatement)
	value.ActionStatement = strings.TrimSpace(value.ActionStatement)
	set := map[string]struct{}{}
	for _, product := range value.Products {
		if product = strings.TrimSpace(product); product != "" {
			set[product] = struct{}{}
		}
	}
	value.Products = value.Products[:0]
	for product := range set {
		value.Products = append(value.Products, product)
	}
	sort.Strings(value.Products)
	return value
}

func normalizeVEXFinding(value VEXFinding) VEXFinding {
	value.ID = strings.TrimSpace(value.ID)
	value.ScanID = strings.TrimSpace(value.ScanID)
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.ReleaseID = strings.TrimSpace(value.ReleaseID)
	value.Vulnerability = strings.TrimSpace(value.Vulnerability)
	value.Component = strings.TrimSpace(value.Component)
	value.SBOMID = strings.TrimSpace(value.SBOMID)
	value.SBOMComponentPURL = strings.TrimSpace(value.SBOMComponentPURL)
	value.SBOMComponentName = strings.TrimSpace(value.SBOMComponentName)
	return value
}

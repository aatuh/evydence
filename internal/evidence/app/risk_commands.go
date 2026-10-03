package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type UploadSecurityScanInput struct {
	ProductID  string
	ReleaseID  string
	ArtifactID string
	Category   string
	Format     string
	Scanner    string
	TargetRef  string
	Raw        []byte
}

type UploadManualSecurityDocumentInput struct {
	ProductID    string
	ReleaseID    string
	DocumentType string
	Title        string
	Sensitivity  string
	Raw          []byte
	MediaType    string
}

type CreateSBOMDiffInput struct {
	BaseSBOMID   string
	TargetSBOMID string
	ReleaseID    string
}

type CreateContractDiffInput struct {
	BaseContractID   string
	TargetContractID string
	ReleaseID        string
}

func (s *Service) UploadSecurityScan(ctx context.Context, actor identitydomain.Actor, input UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	return s.uploadSecurityScan(ctx, actor, input)
}

func (s *Service) UploadAPISecurityScan(ctx context.Context, actor identitydomain.Actor, input UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	input.Category = "api_security"
	return s.uploadSecurityScan(ctx, actor, input)
}

func (s *Service) uploadSecurityScan(ctx context.Context, actor identitydomain.Actor, input UploadSecurityScanInput) (evidencedomain.SecurityScan, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	if err := s.authorize(ctx, actor, ScopeSecurityWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.ArtifactID = strings.TrimSpace(input.ArtifactID)
	input.Category = strings.TrimSpace(input.Category)
	input.Format = strings.TrimSpace(input.Format)
	input.Scanner = strings.TrimSpace(input.Scanner)
	input.TargetRef = strings.TrimSpace(input.TargetRef)
	if !validPayloadSize(int64(len(input.Raw)), EvidenceDocumentLimit) || !validSecurityScanCategory(input.Category) || input.Scanner == "" || input.TargetRef == "" {
		return evidencedomain.SecurityScan{}, ErrValidation
	}
	scope := EvidenceScope{ProductID: input.ProductID, ReleaseID: input.ReleaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	resources := resourceReferences(scope)
	if err := s.authorize(ctx, actor, ScopeSecurityWrite, resources, false); err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	if input.ArtifactID != "" {
		if err := s.validateAndAuthorizeArtifactReference(ctx, actor, ScopeSecurityWrite, input.ArtifactID, ""); err != nil {
			return evidencedomain.SecurityScan{}, err
		}
	}
	parsed, err := parseSecurityScan(input.Format, input.Raw)
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	if input.Format == "" {
		input.Format = parsed.Format
	}
	payloadHash := hashPayload(input.Raw)
	stagedPayload, err := s.objects.StagePayload(ctx, actor.TenantID, "application/json", payloadHash, input.Raw)
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	subjects := []evidencedomain.SubjectRef(nil)
	if input.ArtifactID != "" {
		subjects = []evidencedomain.SubjectRef{{Type: "artifact", ID: input.ArtifactID}}
	}
	prepared, err := s.prepareEvidenceForScope(ctx, actor, ScopeSecurityWrite, CreateEvidenceInput{
		ProductID: input.ProductID, ReleaseID: input.ReleaseID, Type: input.Category, Subtype: input.Format,
		Title: input.Category + " scan", SourceSystem: input.Scanner, ObservedAt: s.clock.Now(),
		PayloadRef: stagedPayload.Reference(), PayloadHash: payloadHash, PayloadMediaType: "application/json",
		PayloadSize: int64(len(input.Raw)), StagedPayload: stagedPayload, SubjectRefs: subjects,
		Metadata:    map[string]any{"scanner": input.Scanner, "target_ref": input.TargetRef, "finding_count": parsed.FindingCount},
		Limitations: []string{"Scanner output is recorded as technical evidence; Evydence does not treat scanner findings as authoritative."},
	})
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	scan := evidencedomain.SecurityScan{
		ID: s.ids.NewID("secscan"), TenantID: actor.TenantID, ProductID: input.ProductID, ReleaseID: input.ReleaseID,
		ArtifactID: input.ArtifactID, Category: input.Category, Format: input.Format, Scanner: input.Scanner, TargetRef: input.TargetRef,
		EvidenceID: prepared.item.ID, PayloadRef: stagedPayload.Reference(), PayloadHash: payloadHash,
		FindingCount: parsed.FindingCount, Summary: cloneIntMap(parsed.Summary), Redacted: input.Category == "secret_scan",
		Quarantined:   input.Category == "secret_scan" && parsed.FindingCount > 0,
		SchemaVersion: evidencedomain.SecurityScanSchemaVersion, CreatedAt: s.clock.Now().UTC(),
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertSecurityScan(ctx, scan); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, scan.CreatedAt, "security_scan.uploaded", "security_scan", scan.ID, payloadHash))
		return err
	})
	if err != nil {
		return evidencedomain.SecurityScan{}, err
	}
	return cloneSecurityScan(scan), nil
}

func (s *Service) UploadManualSecurityDocument(ctx context.Context, actor identitydomain.Actor, input UploadManualSecurityDocumentInput) (evidencedomain.ManualSecurityDocument, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	if err := s.authorize(ctx, actor, ScopeSecurityWrite, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.DocumentType = strings.TrimSpace(input.DocumentType)
	input.Title = strings.TrimSpace(input.Title)
	input.Sensitivity = strings.TrimSpace(input.Sensitivity)
	if !validPayloadSize(int64(len(input.Raw)), EvidenceDocumentLimit) || !validManualDocumentType(input.DocumentType) || input.Title == "" || !validSensitivity(input.Sensitivity) {
		return evidencedomain.ManualSecurityDocument{}, ErrValidation
	}
	scope := EvidenceScope{ProductID: input.ProductID, ReleaseID: input.ReleaseID}
	if err := s.reader.ValidateScope(ctx, actor.TenantID, scope); err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	if err := s.authorize(ctx, actor, ScopeSecurityWrite, resourceReferences(scope), false); err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	mediaType := nonEmpty(input.MediaType, "application/octet-stream")
	payloadHash := hashPayload(input.Raw)
	stagedPayload, err := s.objects.StagePayload(ctx, actor.TenantID, mediaType, payloadHash, input.Raw)
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	prepared, err := s.prepareEvidenceForScope(ctx, actor, ScopeSecurityWrite, CreateEvidenceInput{
		ProductID: input.ProductID, ReleaseID: input.ReleaseID, Type: input.DocumentType, Subtype: "manual", Title: input.Title,
		SourceSystem: "manual", ObservedAt: s.clock.Now(), PayloadRef: stagedPayload.Reference(), PayloadHash: payloadHash,
		PayloadMediaType: mediaType, PayloadSize: int64(len(input.Raw)), StagedPayload: stagedPayload,
		Metadata:    map[string]any{"sensitivity": input.Sensitivity},
		Limitations: []string{"Manual security evidence is lower default trust and requires human review."},
	})
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	document := evidencedomain.ManualSecurityDocument{
		ID: s.ids.NewID("msd"), TenantID: actor.TenantID, ProductID: input.ProductID, ReleaseID: input.ReleaseID,
		DocumentType: input.DocumentType, Title: input.Title, Sensitivity: input.Sensitivity, EvidenceID: prepared.item.ID,
		PayloadRef: stagedPayload.Reference(), PayloadHash: payloadHash, SchemaVersion: evidencedomain.ManualSecurityDocSchemaVersion,
		CreatedAt: s.clock.Now().UTC(),
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := s.persistPreparedEvidence(ctx, tx, actor, &prepared); err != nil {
			return err
		}
		if err := tx.Ingestion().InsertManualSecurityDocument(ctx, document); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, document.CreatedAt, "manual_security_document.uploaded", "manual_security_document", document.ID, payloadHash))
		return err
	})
	if err != nil {
		return evidencedomain.ManualSecurityDocument{}, err
	}
	return document, nil
}

func (s *Service) CreateSBOMDiff(ctx context.Context, actor identitydomain.Actor, input CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	input.BaseSBOMID = strings.TrimSpace(input.BaseSBOMID)
	input.TargetSBOMID = strings.TrimSpace(input.TargetSBOMID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	if input.BaseSBOMID == "" || input.TargetSBOMID == "" || input.BaseSBOMID == input.TargetSBOMID {
		return evidencedomain.SBOMDiff{}, ErrValidation
	}
	if s.projectionRefresher != nil {
		if err := s.projectionRefresher.RefreshWorkerProjection(ctx, actor.TenantID); err != nil {
			return evidencedomain.SBOMDiff{}, err
		}
	}
	base, err := s.reader.GetSBOM(ctx, actor.TenantID, input.BaseSBOMID)
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	target, err := s.reader.GetSBOM(ctx, actor.TenantID, input.TargetSBOMID)
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	if !returnedSBOMMatches(base, actor.TenantID, input.BaseSBOMID) || !returnedSBOMMatches(target, actor.TenantID, input.TargetSBOMID) {
		return evidencedomain.SBOMDiff{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ReleaseID: base.ReleaseID, ArtifactID: base.ArtifactID}, false); err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ReleaseID: target.ReleaseID, ArtifactID: target.ArtifactID}, false); err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	if input.ReleaseID != "" {
		if input.ReleaseID != base.ReleaseID && input.ReleaseID != target.ReleaseID {
			return evidencedomain.SBOMDiff{}, ErrValidation
		}
		if err := s.reader.ValidateScope(ctx, actor.TenantID, EvidenceScope{ReleaseID: input.ReleaseID}); err != nil {
			return evidencedomain.SBOMDiff{}, err
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ReleaseID: input.ReleaseID}, false); err != nil {
			return evidencedomain.SBOMDiff{}, err
		}
	}
	added, removed, unchanged := diffComponents(base.Components, target.Components)
	now := s.clock.Now().UTC()
	diff := evidencedomain.SBOMDiff{
		ID: s.ids.NewID("sdiff"), TenantID: actor.TenantID, BaseSBOMID: base.ID, TargetSBOMID: target.ID,
		ReleaseID: input.ReleaseID, AddedComponents: added, RemovedComponents: removed, UnchangedCount: unchanged,
		SchemaVersion: evidencedomain.SBOMDiffSchemaVersion, CreatedAt: now,
	}
	for _, component := range added {
		diff.DependencyChanges = append(diff.DependencyChanges, evidencedomain.DependencyChange{
			ID: s.ids.NewID("depchg"), TenantID: actor.TenantID, SBOMDiffID: diff.ID, ChangeType: "added",
			Component: component, SchemaVersion: evidencedomain.DependencyChangeSchemaVersion, CreatedAt: now,
		})
	}
	for _, component := range removed {
		diff.DependencyChanges = append(diff.DependencyChanges, evidencedomain.DependencyChange{
			ID: s.ids.NewID("depchg"), TenantID: actor.TenantID, SBOMDiffID: diff.ID, ChangeType: "removed",
			Component: component, SchemaVersion: evidencedomain.DependencyChangeSchemaVersion, CreatedAt: now,
		})
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if input.ReleaseID != "" {
			if err := tx.Evidence().ValidateScope(ctx, actor.TenantID, EvidenceScope{ReleaseID: input.ReleaseID}); err != nil {
				return err
			}
		}
		currentBase, err := tx.Ingestion().GetSBOM(ctx, actor.TenantID, base.ID)
		if err != nil {
			return err
		}
		currentTarget, err := tx.Ingestion().GetSBOM(ctx, actor.TenantID, target.ID)
		if err != nil {
			return err
		}
		if !returnedSBOMMatches(currentBase, actor.TenantID, base.ID) || !returnedSBOMMatches(currentTarget, actor.TenantID, target.ID) {
			return ErrNotFound
		}
		if !reflect.DeepEqual(currentBase, base) || !reflect.DeepEqual(currentTarget, target) {
			return ErrConflict
		}
		if err := tx.Ingestion().InsertSBOMDiff(ctx, diff); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, "sbom.diffed", "sbom_diff", diff.ID, ""))
		return err
	})
	if err != nil {
		return evidencedomain.SBOMDiff{}, err
	}
	return cloneSBOMDiff(diff), nil
}

func (s *Service) CreateContractDiff(ctx context.Context, actor identitydomain.Actor, input CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	if err := contextError(ctx); err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{}, true); err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	input.BaseContractID = strings.TrimSpace(input.BaseContractID)
	input.TargetContractID = strings.TrimSpace(input.TargetContractID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	if input.BaseContractID == "" || input.TargetContractID == "" || input.BaseContractID == input.TargetContractID {
		return evidencedomain.ContractDiff{}, ErrValidation
	}
	if s.projectionRefresher != nil {
		if err := s.projectionRefresher.RefreshWorkerProjection(ctx, actor.TenantID); err != nil {
			return evidencedomain.ContractDiff{}, err
		}
	}
	base, err := s.reader.GetOpenAPIContract(ctx, actor.TenantID, input.BaseContractID)
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	target, err := s.reader.GetOpenAPIContract(ctx, actor.TenantID, input.TargetContractID)
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	if !returnedContractMatches(base, actor.TenantID, input.BaseContractID) || !returnedContractMatches(target, actor.TenantID, input.TargetContractID) {
		return evidencedomain.ContractDiff{}, ErrNotFound
	}
	if base.ProductID != target.ProductID {
		return evidencedomain.ContractDiff{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ProductID: base.ProductID, ReleaseID: base.ReleaseID}, false); err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	if err := s.authorize(ctx, actor, ScopeEvidenceRead, application.ResourceReferences{ProductID: target.ProductID, ReleaseID: target.ReleaseID}, false); err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	if input.ReleaseID != "" {
		requestedScope := EvidenceScope{ProductID: base.ProductID, ReleaseID: input.ReleaseID}
		if err := s.reader.ValidateScope(ctx, actor.TenantID, requestedScope); err != nil {
			return evidencedomain.ContractDiff{}, err
		}
		if err := s.authorize(ctx, actor, ScopeEvidenceRead, resourceReferences(requestedScope), false); err != nil {
			return evidencedomain.ContractDiff{}, err
		}
	}
	result, breaking, nonBreaking := evaluateContractDifference(base, target)
	now := s.clock.Now().UTC()
	diff := evidencedomain.ContractDiff{
		ID: s.ids.NewID("cdiff"), TenantID: actor.TenantID, BaseContractID: base.ID, TargetContractID: target.ID,
		ProductID: base.ProductID, ReleaseID: input.ReleaseID, Result: result, BreakingChanges: breaking,
		NonBreakingChanges: nonBreaking, SchemaVersion: evidencedomain.ContractDiffSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if input.ReleaseID != "" {
			if err := tx.Evidence().ValidateScope(ctx, actor.TenantID, EvidenceScope{ProductID: base.ProductID, ReleaseID: input.ReleaseID}); err != nil {
				return err
			}
		}
		currentBase, err := tx.Ingestion().GetOpenAPIContract(ctx, actor.TenantID, base.ID)
		if err != nil {
			return err
		}
		currentTarget, err := tx.Ingestion().GetOpenAPIContract(ctx, actor.TenantID, target.ID)
		if err != nil {
			return err
		}
		if !returnedContractMatches(currentBase, actor.TenantID, base.ID) || !returnedContractMatches(currentTarget, actor.TenantID, target.ID) {
			return ErrNotFound
		}
		if !reflect.DeepEqual(currentBase, base) || !reflect.DeepEqual(currentTarget, target) {
			return ErrConflict
		}
		if err := tx.Ingestion().InsertContractDiff(ctx, diff); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.subjectAuditEvent(actor, now, "openapi_contract.diffed", "contract_diff", diff.ID, ""))
		return err
	})
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	return cloneContractDiff(diff), nil
}

func returnedSBOMMatches(value evidencedomain.SBOM, tenantID, id string) bool {
	return value.TenantID == tenantID && value.ID == id
}

func returnedContractMatches(value evidencedomain.OpenAPIContract, tenantID, id string) bool {
	return value.TenantID == tenantID && value.ID == id
}

func (s *Service) subjectAuditEvent(actor identitydomain.Actor, atTime time.Time, entryType, subjectType, subjectID, payloadHash string) application.AuditEvent {
	return application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: subjectType, SubjectID: subjectID,
		ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: atTime.UTC(), PayloadHash: payloadHash,
	}
}

type parsedSecurityScan struct {
	Format       string
	FindingCount int
	Summary      map[string]int
}

func parseSecurityScan(format string, raw []byte) (parsedSecurityScan, error) {
	if strings.TrimSpace(format) == "" {
		format = "generic"
	}
	if format == "sarif" {
		var document struct {
			Version string `json:"version"`
			Runs    []struct {
				Results []struct {
					Level string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := strictDecode(raw, &document); err != nil || document.Version == "" {
			return parsedSecurityScan{}, ErrValidation
		}
		summary := map[string]int{}
		total := 0
		for _, run := range document.Runs {
			for _, result := range run.Results {
				total++
				summary[nonEmpty(strings.ToLower(result.Level), "warning")]++
			}
		}
		return parsedSecurityScan{Format: "sarif", FindingCount: total, Summary: summary}, nil
	}
	var document struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := strictDecode(raw, &document); err != nil {
		return parsedSecurityScan{}, ErrValidation
	}
	summary := map[string]int{}
	for _, finding := range document.Findings {
		summary[nonEmpty(strings.ToLower(finding.Severity), "unknown")]++
	}
	return parsedSecurityScan{Format: strings.TrimSpace(format), FindingCount: len(document.Findings), Summary: summary}, nil
}

func strictDecode(raw []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrValidation
	}
	return nil
}

func hashPayload(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validPayloadSize(size, limit int64) bool { return size > 0 && limit > 0 && size <= limit }

func validSecurityScanCategory(category string) bool {
	switch category {
	case "sast", "dast", "secret_scan", "license_scan", "api_security":
		return true
	default:
		return false
	}
}

func validManualDocumentType(documentType string) bool {
	switch documentType {
	case "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

func validSensitivity(sensitivity string) bool {
	switch sensitivity {
	case "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func diffComponents(base, target []evidencedomain.SBOMComponent) ([]evidencedomain.SBOMComponent, []evidencedomain.SBOMComponent, int) {
	baseSet := make(map[string]evidencedomain.SBOMComponent, len(base))
	targetSet := make(map[string]evidencedomain.SBOMComponent, len(target))
	for _, component := range base {
		baseSet[componentKey(component)] = component
	}
	for _, component := range target {
		targetSet[componentKey(component)] = component
	}
	added, removed := []evidencedomain.SBOMComponent{}, []evidencedomain.SBOMComponent{}
	unchanged := 0
	for key, component := range targetSet {
		if _, ok := baseSet[key]; ok {
			unchanged++
			continue
		}
		added = append(added, component)
	}
	for key, component := range baseSet {
		if _, ok := targetSet[key]; !ok {
			removed = append(removed, component)
		}
	}
	sortComponents(added)
	sortComponents(removed)
	return added, removed, unchanged
}

func sortComponents(values []evidencedomain.SBOMComponent) {
	sort.Slice(values, func(i, j int) bool { return componentKey(values[i]) < componentKey(values[j]) })
}

func componentKey(component evidencedomain.SBOMComponent) string {
	if component.Identity != "" {
		return component.Identity
	}
	if component.PURL != "" {
		return component.PURL
	}
	return component.Name + "@" + component.Version
}

func diffOpenAPIOperations(base, target evidencedomain.OpenAPIContract) ([]string, []string) {
	baseOps := indexOpenAPIOperations(base.Operations)
	targetOps := indexOpenAPIOperations(target.Operations)
	breaking, nonBreaking := []string{}, []string{}
	for key, baseOperation := range baseOps {
		targetOperation, ok := targetOps[key]
		label := openAPIOperationLabel(baseOperation)
		if !ok {
			breaking = append(breaking, "operation removed: "+label)
			continue
		}
		if !baseOperation.RequestBodyRequired && targetOperation.RequestBodyRequired {
			breaking = append(breaking, "request body became required: "+label)
		}
		if fields := missingStrings(baseOperation.RequiredRequestFields, targetOperation.RequiredRequestFields); len(fields) > 0 {
			breaking = append(breaking, "required request fields added for "+label+": "+strings.Join(fields, ","))
		}
		if statuses := missingStrings(targetOperation.ResponseStatuses, baseOperation.ResponseStatuses); len(statuses) > 0 {
			breaking = append(breaking, "response statuses removed for "+label+": "+strings.Join(statuses, ","))
		}
		if statuses := missingStrings(baseOperation.ResponseStatuses, targetOperation.ResponseStatuses); len(statuses) > 0 {
			nonBreaking = append(nonBreaking, "response statuses added for "+label+": "+strings.Join(statuses, ","))
		}
		if !baseOperation.Deprecated && targetOperation.Deprecated {
			nonBreaking = append(nonBreaking, "operation deprecated: "+label)
		}
	}
	for key, targetOperation := range targetOps {
		if _, ok := baseOps[key]; !ok {
			nonBreaking = append(nonBreaking, "operation added: "+openAPIOperationLabel(targetOperation))
		}
	}
	sort.Strings(breaking)
	sort.Strings(nonBreaking)
	return breaking, nonBreaking
}

func indexOpenAPIOperations(operations []evidencedomain.OpenAPIOperation) map[string]evidencedomain.OpenAPIOperation {
	result := make(map[string]evidencedomain.OpenAPIOperation, len(operations))
	for _, operation := range operations {
		if strings.TrimSpace(operation.Path) == "" || strings.TrimSpace(operation.Method) == "" {
			continue
		}
		operation.Method = strings.ToUpper(strings.TrimSpace(operation.Method))
		operation.Path = strings.TrimSpace(operation.Path)
		result[operation.Method+" "+operation.Path] = operation
	}
	return result
}

func openAPIOperationLabel(operation evidencedomain.OpenAPIOperation) string {
	return strings.ToUpper(strings.TrimSpace(operation.Method)) + " " + strings.TrimSpace(operation.Path)
}

func missingStrings(have, want []string) []string {
	present := map[string]struct{}{}
	for _, value := range have {
		value = strings.TrimSpace(value)
		if value != "" {
			present[value] = struct{}{}
		}
	}
	missing := []string{}
	for _, value := range want {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := present[value]; !ok {
			missing = append(missing, value)
		}
	}
	sort.Strings(missing)
	return missing
}

func cloneSBOM(value evidencedomain.SBOM) evidencedomain.SBOM {
	value.Components = append([]evidencedomain.SBOMComponent(nil), value.Components...)
	return value
}

func cloneOpenAPIContract(value evidencedomain.OpenAPIContract) evidencedomain.OpenAPIContract {
	value.Operations = append([]evidencedomain.OpenAPIOperation(nil), value.Operations...)
	for index := range value.Operations {
		value.Operations[index].RequiredRequestFields = append([]string(nil), value.Operations[index].RequiredRequestFields...)
		value.Operations[index].ResponseStatuses = append([]string(nil), value.Operations[index].ResponseStatuses...)
	}
	return value
}

func cloneSecurityScan(value evidencedomain.SecurityScan) evidencedomain.SecurityScan {
	value.Summary = cloneIntMap(value.Summary)
	return value
}

func cloneSBOMDiff(value evidencedomain.SBOMDiff) evidencedomain.SBOMDiff {
	value.AddedComponents = append([]evidencedomain.SBOMComponent(nil), value.AddedComponents...)
	value.RemovedComponents = append([]evidencedomain.SBOMComponent(nil), value.RemovedComponents...)
	value.DependencyChanges = append([]evidencedomain.DependencyChange(nil), value.DependencyChanges...)
	return value
}

func cloneContractDiff(value evidencedomain.ContractDiff) evidencedomain.ContractDiff {
	value.BreakingChanges = append([]string(nil), value.BreakingChanges...)
	value.NonBreakingChanges = append([]string(nil), value.NonBreakingChanges...)
	return value
}

func cloneIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]int, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

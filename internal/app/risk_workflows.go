package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type CreateIncidentInput struct {
	ProductID string
	ReleaseID string
	Title     string
	Severity  string
	OpenedAt  time.Time
}

type RecordIncidentTimelineInput struct {
	EventType  string
	Summary    string
	EvidenceID string
	OccurredAt time.Time
}

type CreateRemediationTaskInput struct {
	IncidentID string
	ReleaseID  string
	Title      string
	Owner      string
	DueAt      *time.Time
	EvidenceID string
}

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

type RecordVulnerabilityWorkflowInput struct {
	FindingID string
	Action    string
	Reason    string
}

type CreateContractDiffInput struct {
	BaseContractID   string
	TargetContractID string
	ReleaseID        string
}

type CreateCustomPolicyInput struct {
	Name        string
	Version     string
	Description string
	Rules       []domain.PolicyRule
}

func (l *Ledger) CreateIncident(ctx context.Context, actor domain.Actor, in CreateIncidentInput) (domain.Incident, error) {
	if err := ctx.Err(); err != nil {
		return domain.Incident{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.Incident{}, err
	}
	in.ProductID, in.ReleaseID = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	in.Title, in.Severity = strings.TrimSpace(in.Title), strings.ToLower(strings.TrimSpace(in.Severity))
	if in.ProductID == "" || in.Title == "" || !validSeverity(in.Severity) {
		return domain.Incident{}, ErrValidation
	}
	if in.OpenedAt.IsZero() {
		in.OpenedAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.Incident{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.Incident{}, err
	}
	incident := domain.Incident{
		ID:            newID("inc"),
		TenantID:      actor.TenantID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Title:         in.Title,
		Severity:      in.Severity,
		Status:        "open",
		OpenedAt:      in.OpenedAt.UTC(),
		SchemaVersion: domain.IncidentSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.incidents[incident.ID] = incident
	_, _ = l.appendChainLocked(actor.TenantID, "incident.created", "incident", incident.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Incident{}, err
	}
	return incident, nil
}

func (l *Ledger) RecordIncidentTimelineEvent(ctx context.Context, actor domain.Actor, incidentID string, in RecordIncidentTimelineInput) (domain.IncidentTimelineEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	in.EventType, in.Summary = strings.TrimSpace(in.EventType), strings.TrimSpace(in.Summary)
	if in.EventType == "" || in.Summary == "" {
		return domain.IncidentTimelineEvent{}, ErrValidation
	}
	if in.OccurredAt.IsZero() {
		in.OccurredAt = l.now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	incident, ok := l.incidents[strings.TrimSpace(incidentID)]
	if !ok || incident.TenantID != actor.TenantID {
		return domain.IncidentTimelineEvent{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	if in.EvidenceID != "" {
		item, ok := l.evidence[strings.TrimSpace(in.EvidenceID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.IncidentTimelineEvent{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, refsForEvidence(item)); err != nil {
			return domain.IncidentTimelineEvent{}, err
		}
	}
	event := domain.IncidentTimelineEvent{
		ID:            newID("it"),
		TenantID:      actor.TenantID,
		IncidentID:    incident.ID,
		EventType:     in.EventType,
		Summary:       in.Summary,
		EvidenceID:    strings.TrimSpace(in.EvidenceID),
		OccurredAt:    in.OccurredAt.UTC(),
		SchemaVersion: domain.IncidentTimelineSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.timeline[event.ID] = event
	_, _ = l.appendChainLocked(actor.TenantID, "incident.timeline_recorded", "incident", incident.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.IncidentTimelineEvent{}, err
	}
	return event, nil
}

func (l *Ledger) CreateRemediationTask(ctx context.Context, actor domain.Actor, in CreateRemediationTaskInput) (domain.RemediationTask, error) {
	if err := ctx.Err(); err != nil {
		return domain.RemediationTask{}, err
	}
	if err := require(actor, ScopeIncidentWrite); err != nil {
		return domain.RemediationTask{}, err
	}
	in.IncidentID, in.ReleaseID = strings.TrimSpace(in.IncidentID), strings.TrimSpace(in.ReleaseID)
	in.Title, in.Owner = strings.TrimSpace(in.Title), strings.TrimSpace(in.Owner)
	if in.Title == "" || in.Owner == "" || (in.IncidentID == "" && in.ReleaseID == "") {
		return domain.RemediationTask{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.IncidentID != "" {
		incident, ok := l.incidents[in.IncidentID]
		if !ok || incident.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	if in.ReleaseID != "" {
		release, ok := l.releases[in.ReleaseID]
		if !ok || release.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	if in.EvidenceID != "" {
		item, ok := l.evidence[strings.TrimSpace(in.EvidenceID)]
		if !ok || item.TenantID != actor.TenantID {
			return domain.RemediationTask{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeIncidentWrite, refsForEvidence(item)); err != nil {
			return domain.RemediationTask{}, err
		}
	}
	task := domain.RemediationTask{
		ID:            newID("rt"),
		TenantID:      actor.TenantID,
		IncidentID:    in.IncidentID,
		ReleaseID:     in.ReleaseID,
		Title:         in.Title,
		Owner:         in.Owner,
		Status:        "open",
		DueAt:         in.DueAt,
		EvidenceID:    strings.TrimSpace(in.EvidenceID),
		SchemaVersion: domain.RemediationTaskSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.tasks[task.ID] = task
	_, _ = l.appendChainLocked(actor.TenantID, "remediation_task.created", "remediation_task", task.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.RemediationTask{}, err
	}
	return task, nil
}

func (l *Ledger) IncidentReport(ctx context.Context, actor domain.Actor, incidentID string) (domain.IncidentReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.IncidentReport{}, err
	}
	if err := require(actor, ScopeIncidentRead); err != nil {
		return domain.IncidentReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	incident, ok := l.incidents[strings.TrimSpace(incidentID)]
	if !ok || incident.TenantID != actor.TenantID {
		return domain.IncidentReport{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeIncidentRead, resourceRefs{ProductID: incident.ProductID, ReleaseID: incident.ReleaseID, IncidentID: incident.ID}); err != nil {
		return domain.IncidentReport{}, err
	}
	timeline := []domain.IncidentTimelineEvent{}
	linked := []string{}
	for _, event := range l.timeline {
		if event.TenantID == actor.TenantID && event.IncidentID == incident.ID {
			timeline = append(timeline, event)
			if event.EvidenceID != "" {
				linked = append(linked, event.EvidenceID)
			}
		}
	}
	sort.Slice(timeline, func(i, j int) bool { return timeline[i].OccurredAt.Before(timeline[j].OccurredAt) })
	tasks := []domain.RemediationTask{}
	for _, task := range l.tasks {
		if task.TenantID == actor.TenantID && task.IncidentID == incident.ID {
			tasks = append(tasks, task)
			if task.EvidenceID != "" {
				linked = append(linked, task.EvidenceID)
			}
		}
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].CreatedAt.Before(tasks[j].CreatedAt) })
	result := "open"
	if incident.Status == "closed" {
		result = "closed"
	}
	return domain.IncidentReport{
		ReportType:      "incident_package",
		TemplateVersion: "incident-package.v1.0.0",
		IncidentID:      incident.ID,
		Result:          result,
		Timeline:        timeline,
		Tasks:           tasks,
		LinkedEvidence:  sortedStrings(linked),
		Assumptions:     []string{"Incident evidence is limited to records stored in this Evydence tenant."},
		Limitations:     []string{"This report organizes incident evidence and does not prove root cause completeness or remediation sufficiency."},
		GeneratedAt:     l.now(),
	}, nil
}

func (l *Ledger) UploadSecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	return l.uploadSecurityScan(ctx, actor, in)
}

func (l *Ledger) UploadAPISecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	in.Category = "api_security"
	return l.uploadSecurityScan(ctx, actor, in)
}

func (l *Ledger) uploadSecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	if err := ctx.Err(); err != nil {
		return domain.SecurityScan{}, err
	}
	if err := require(actor, ScopeSecurityWrite); err != nil {
		return domain.SecurityScan{}, err
	}
	in.Category, in.Format = strings.TrimSpace(in.Category), strings.TrimSpace(in.Format)
	in.Scanner, in.TargetRef = strings.TrimSpace(in.Scanner), strings.TrimSpace(in.TargetRef)
	if len(in.Raw) == 0 || len(in.Raw) > 20<<20 || !validSecurityScanCategory(in.Category) || in.Scanner == "" || in.TargetRef == "" {
		return domain.SecurityScan{}, ErrValidation
	}
	parsed, err := parseSecurityScan(in.Format, in.Raw)
	if err != nil {
		return domain.SecurityScan{}, err
	}
	if in.Format == "" {
		in.Format = parsed.Format
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, strings.TrimSpace(in.ProductID), "", strings.TrimSpace(in.ReleaseID)); err != nil {
		l.mu.Unlock()
		return domain.SecurityScan{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ProductID: strings.TrimSpace(in.ProductID), ReleaseID: strings.TrimSpace(in.ReleaseID)}); err != nil {
		l.mu.Unlock()
		return domain.SecurityScan{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(in.Raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "security-scan", "application/json", payloadHash, in.Raw)
	if err != nil {
		return domain.SecurityScan{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:        in.ProductID,
		ReleaseID:        in.ReleaseID,
		Type:             in.Category,
		Subtype:          in.Format,
		Title:            in.Category + " scan",
		SourceSystem:     in.Scanner,
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/json",
		PayloadSize:      int64(len(in.Raw)),
		SubjectRefs:      subjectForArtifact(in.ArtifactID),
		Metadata:         map[string]any{"scanner": in.Scanner, "target_ref": in.TargetRef, "finding_count": parsed.FindingCount},
		Limitations:      []string{"Scanner output is recorded as technical evidence; Evydence does not treat scanner findings as authoritative."},
	})
	if err != nil {
		return domain.SecurityScan{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.SecurityScan{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.SecurityScan{}, err
	}
	if in.ArtifactID != "" {
		artifact, ok := l.artifacts[strings.TrimSpace(in.ArtifactID)]
		if !ok || artifact.TenantID != actor.TenantID {
			return domain.SecurityScan{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: artifact.ID}); err != nil {
			return domain.SecurityScan{}, err
		}
	}
	scan := domain.SecurityScan{
		ID:            newID("secscan"),
		TenantID:      actor.TenantID,
		ProductID:     strings.TrimSpace(in.ProductID),
		ReleaseID:     strings.TrimSpace(in.ReleaseID),
		ArtifactID:    strings.TrimSpace(in.ArtifactID),
		Category:      in.Category,
		Format:        in.Format,
		Scanner:       in.Scanner,
		TargetRef:     in.TargetRef,
		EvidenceID:    item.ID,
		PayloadRef:    payloadRef,
		PayloadHash:   payloadHash,
		FindingCount:  parsed.FindingCount,
		Summary:       parsed.Summary,
		Redacted:      in.Category == "secret_scan",
		Quarantined:   in.Category == "secret_scan" && parsed.FindingCount > 0,
		SchemaVersion: domain.SecurityScanSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.securityScans[scan.ID] = scan
	_, _ = l.appendChainLocked(actor.TenantID, "security_scan.uploaded", "security_scan", scan.ID, actorType(actor), actorID(actor), payloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SecurityScan{}, err
	}
	return scan, nil
}

func (l *Ledger) UploadManualSecurityDocument(ctx context.Context, actor domain.Actor, in UploadManualSecurityDocumentInput) (domain.ManualSecurityDocument, error) {
	if err := ctx.Err(); err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	if err := require(actor, ScopeSecurityWrite); err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	in.DocumentType, in.Title, in.Sensitivity = strings.TrimSpace(in.DocumentType), strings.TrimSpace(in.Title), strings.TrimSpace(in.Sensitivity)
	if len(in.Raw) == 0 || len(in.Raw) > 20<<20 || !validManualDocType(in.DocumentType) || in.Title == "" || !validSensitivity(in.Sensitivity) {
		return domain.ManualSecurityDocument{}, ErrValidation
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, strings.TrimSpace(in.ProductID), "", strings.TrimSpace(in.ReleaseID)); err != nil {
		l.mu.Unlock()
		return domain.ManualSecurityDocument{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ProductID: strings.TrimSpace(in.ProductID), ReleaseID: strings.TrimSpace(in.ReleaseID)}); err != nil {
		l.mu.Unlock()
		return domain.ManualSecurityDocument{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(in.Raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "manual-security-document", nonEmpty(in.MediaType, "application/octet-stream"), payloadHash, in.Raw)
	if err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:        in.ProductID,
		ReleaseID:        in.ReleaseID,
		Type:             in.DocumentType,
		Subtype:          "manual",
		Title:            in.Title,
		SourceSystem:     "manual",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: nonEmpty(in.MediaType, "application/octet-stream"),
		PayloadSize:      int64(len(in.Raw)),
		Metadata:         map[string]any{"sensitivity": in.Sensitivity},
		Limitations:      []string{"Manual security evidence is lower default trust and requires human review."},
	})
	if err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, in.ProductID, "", in.ReleaseID); err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ProductID: in.ProductID, ReleaseID: in.ReleaseID}); err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	doc := domain.ManualSecurityDocument{
		ID:            newID("msd"),
		TenantID:      actor.TenantID,
		ProductID:     strings.TrimSpace(in.ProductID),
		ReleaseID:     strings.TrimSpace(in.ReleaseID),
		DocumentType:  in.DocumentType,
		Title:         in.Title,
		Sensitivity:   in.Sensitivity,
		EvidenceID:    item.ID,
		PayloadRef:    payloadRef,
		PayloadHash:   payloadHash,
		SchemaVersion: domain.ManualSecurityDocSchemaVersion,
		CreatedAt:     l.now(),
	}
	l.manualDocs[doc.ID] = doc
	_, _ = l.appendChainLocked(actor.TenantID, "manual_security_document.uploaded", "manual_security_document", doc.ID, actorType(actor), actorID(actor), payloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ManualSecurityDocument{}, err
	}
	return doc, nil
}

func (l *Ledger) UploadSPDXSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.SBOM{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.SBOM{}, ErrValidation
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		Packages    []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}
	if err := strictDecode(raw, &doc); err != nil || !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		return domain.SBOM{}, ErrValidation
	}
	components := []domain.SBOMComponent{}
	for _, pkg := range doc.Packages {
		if strings.TrimSpace(pkg.Name) == "" {
			return domain.SBOM{}, ErrValidation
		}
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purl = ref.ReferenceLocator
				break
			}
		}
		components = append(components, domain.SBOMComponent{Name: pkg.Name, Version: pkg.VersionInfo, PURL: purl})
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, "", "", strings.TrimSpace(releaseID)); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: strings.TrimSpace(releaseID)}); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	l.mu.Unlock()
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "sbom-spdx", "application/spdx+json", payloadHash, raw)
	if err != nil {
		return domain.SBOM{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID:        releaseID,
		Type:             "sbom",
		Subtype:          "spdx",
		Title:            "SPDX SBOM",
		SourceSystem:     "api",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/spdx+json",
		PayloadSize:      int64(len(raw)),
		SubjectRefs:      subjectForArtifact(artifactID),
		Metadata:         map[string]any{"sbom_format": "spdx", "sbom_spec_version": doc.SPDXVersion, "component_count": len(components), "parser_version": "spdx-json.v1"},
		Limitations:      []string{"SBOM ingestion validates document shape but does not prove SBOM completeness."},
	})
	if err != nil {
		return domain.SBOM{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sbom := domain.SBOM{ID: newID("sbom"), TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: releaseID, ArtifactID: artifactID, Format: "spdx", SpecVersion: doc.SPDXVersion, ComponentCount: len(components), Components: components, CreatedAt: l.now()}
	l.sboms[sbom.ID] = sbom
	_, _ = l.appendChainLocked(actor.TenantID, "sbom.parsed", "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

func (l *Ledger) CreateSBOMDiff(ctx context.Context, actor domain.Actor, in CreateSBOMDiffInput) (domain.SBOMDiff, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOMDiff{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.SBOMDiff{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	base, bok := l.sboms[strings.TrimSpace(in.BaseSBOMID)]
	target, tok := l.sboms[strings.TrimSpace(in.TargetSBOMID)]
	if !bok || !tok || base.TenantID != actor.TenantID || target.TenantID != actor.TenantID {
		return domain.SBOMDiff{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: base.ReleaseID, ArtifactID: base.ArtifactID}); err != nil {
		return domain.SBOMDiff{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ReleaseID: target.ReleaseID, ArtifactID: target.ArtifactID}); err != nil {
		return domain.SBOMDiff{}, err
	}
	added, removed, unchanged := diffComponents(base.Components, target.Components)
	diff := domain.SBOMDiff{
		ID:                newID("sdiff"),
		TenantID:          actor.TenantID,
		BaseSBOMID:        base.ID,
		TargetSBOMID:      target.ID,
		ReleaseID:         strings.TrimSpace(in.ReleaseID),
		AddedComponents:   added,
		RemovedComponents: removed,
		UnchangedCount:    unchanged,
		SchemaVersion:     domain.SBOMDiffSchemaVersion,
		CreatedAt:         l.now(),
	}
	for _, component := range added {
		change := domain.DependencyChange{ID: newID("depchg"), TenantID: actor.TenantID, SBOMDiffID: diff.ID, ChangeType: "added", Component: component, SchemaVersion: domain.DependencyChangeSchemaVersion, CreatedAt: l.now()}
		l.depChanges[change.ID] = change
		diff.DependencyChanges = append(diff.DependencyChanges, change)
	}
	for _, component := range removed {
		change := domain.DependencyChange{ID: newID("depchg"), TenantID: actor.TenantID, SBOMDiffID: diff.ID, ChangeType: "removed", Component: component, SchemaVersion: domain.DependencyChangeSchemaVersion, CreatedAt: l.now()}
		l.depChanges[change.ID] = change
		diff.DependencyChanges = append(diff.DependencyChanges, change)
	}
	l.sbomDiffs[diff.ID] = diff
	_, _ = l.appendChainLocked(actor.TenantID, "sbom.diffed", "sbom_diff", diff.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SBOMDiff{}, err
	}
	return diff, nil
}

func (l *Ledger) UploadCycloneDXVEX(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.VEXDocument, error) {
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.VEXDocument{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.VEXDocument{}, ErrValidation
	}
	var doc struct {
		BOMFormat       string `json:"bomFormat"`
		SpecVersion     string `json:"specVersion"`
		Vulnerabilities []struct {
			ID       string `json:"id"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Detail        string   `json:"detail"`
				Response      []string `json:"response"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := strictDecode(raw, &doc); err != nil || strings.ToLower(doc.BOMFormat) != "cyclonedx" || len(doc.Vulnerabilities) == 0 {
		return domain.VEXDocument{}, ErrValidation
	}
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, "", "", strings.TrimSpace(releaseID)); err != nil {
		l.mu.Unlock()
		return domain.VEXDocument{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: strings.TrimSpace(releaseID)}); err != nil {
		l.mu.Unlock()
		return domain.VEXDocument{}, err
	}
	l.mu.Unlock()
	statusSummary := map[string]int{}
	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "vex-cyclonedx", "application/vnd.cyclonedx+json", payloadHash, raw)
	if err != nil {
		return domain.VEXDocument{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ReleaseID: releaseID, Type: "vex", Subtype: "cyclonedx", Title: "CycloneDX VEX", SourceSystem: "api", ObservedAt: l.now(),
		PayloadRef: payloadRef, PayloadHash: payloadHash, PayloadMediaType: "application/vnd.cyclonedx+json", PayloadSize: int64(len(raw)),
		SubjectRefs: subjectForArtifact(artifactID), Metadata: map[string]any{"format": "cyclonedx", "spec_version": doc.SpecVersion},
	})
	if err != nil {
		return domain.VEXDocument{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	vex := domain.VEXDocument{ID: newID("vex"), TenantID: actor.TenantID, EvidenceID: item.ID, ReleaseID: releaseID, ArtifactID: artifactID, Format: "cyclonedx", Author: "cyclonedx", Version: doc.SpecVersion, StatementCount: len(doc.Vulnerabilities), StatusSummary: statusSummary, SchemaVersion: domain.VEXDocumentSchemaVersion, CreatedAt: l.now()}
	for _, vuln := range doc.Vulnerabilities {
		status := cyclonedxAnalysisStatus(vuln.Analysis.State)
		if status == "" || strings.TrimSpace(vuln.ID) == "" {
			return domain.VEXDocument{}, ErrValidation
		}
		statusSummary[status]++
		for _, scan := range l.scans {
			if scan.TenantID != actor.TenantID || scan.ReleaseID != releaseID {
				continue
			}
			for _, finding := range scan.Findings {
				if finding.Vulnerability != vuln.ID {
					continue
				}
				decision := domain.VulnerabilityDecision{ID: newID("vd"), TenantID: actor.TenantID, FindingID: finding.ID, ScanID: scan.ID, ReleaseID: releaseID, Vulnerability: finding.Vulnerability, Component: finding.Component, Status: status, Justification: nonEmpty(vuln.Analysis.Justification, "cyclonedx_vex"), ImpactStatement: vuln.Analysis.Detail, ActionStatement: strings.Join(vuln.Analysis.Response, ","), Source: "cyclonedx_vex", EvidenceID: item.ID, VEXDocumentID: vex.ID, SchemaVersion: domain.VulnerabilityDecisionVersion, CreatedAt: l.now()}
				l.decisions[decision.ID] = decision
			}
		}
	}
	l.vexDocuments[vex.ID] = vex
	_, _ = l.appendChainLocked(actor.TenantID, "vex.parsed", "vex_document", vex.ID, "api_key", actor.KeyID, payloadHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.VEXDocument{}, err
	}
	return vex, nil
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
	scan, _, ok := l.findFindingLocked(actor.TenantID, in.FindingID)
	if !ok {
		return domain.VulnerabilityWorkflowRecord{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeSecurityWrite, resourceRefs{ReleaseID: scan.ReleaseID}); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	record := domain.VulnerabilityWorkflowRecord{ID: newID("vw"), TenantID: actor.TenantID, FindingID: in.FindingID, ReleaseID: scan.ReleaseID, Action: in.Action, Reason: in.Reason, ActorID: actorID(actor), SchemaVersion: "vulnerability-workflow.v1.0.0", CreatedAt: l.now()}
	l.vulnWorkflow[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "vulnerability_workflow."+record.Action, "vulnerability_finding", in.FindingID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.VulnerabilityWorkflowRecord{}, err
	}
	return record, nil
}

func (l *Ledger) VulnerabilityPostureReport(ctx context.Context, actor domain.Actor, releaseID string) (domain.VulnerabilityPostureReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.VulnerabilityPostureReport{}, err
	}
	if err := require(actor, ScopeSecurityRead); err != nil {
		return domain.VulnerabilityPostureReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if strings.TrimSpace(releaseID) != "" {
		release, ok := l.releases[strings.TrimSpace(releaseID)]
		if !ok || release.TenantID != actor.TenantID {
			return domain.VulnerabilityPostureReport{}, ErrNotFound
		}
		if err := l.authorizeResourceLocked(actor, ScopeSecurityRead, resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}); err != nil {
			return domain.VulnerabilityPostureReport{}, err
		}
	}
	summary := map[string]int{}
	openCritical := 0
	for _, scan := range l.scans {
		if scan.TenantID != actor.TenantID || (releaseID != "" && scan.ReleaseID != releaseID) {
			continue
		}
		for _, finding := range scan.Findings {
			summary[strings.ToLower(finding.Severity)]++
			if strings.EqualFold(finding.Severity, "critical") && strings.EqualFold(finding.State, "open") {
				openCritical++
			}
		}
	}
	return domain.VulnerabilityPostureReport{ReportType: "vulnerability_posture", TemplateVersion: "vulnerability-posture.v1.0.0", ReleaseID: releaseID, Summary: summary, OpenCritical: openCritical, Assumptions: []string{"Posture reflects scans uploaded to this tenant only."}, Limitations: []string{"Scanner coverage and vulnerability databases are not independently verified by Evydence."}, GeneratedAt: l.now()}, nil
}

func (l *Ledger) CreateContractDiff(ctx context.Context, actor domain.Actor, in CreateContractDiffInput) (domain.ContractDiff, error) {
	if err := ctx.Err(); err != nil {
		return domain.ContractDiff{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.ContractDiff{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	base, bok := l.contracts[strings.TrimSpace(in.BaseContractID)]
	target, tok := l.contracts[strings.TrimSpace(in.TargetContractID)]
	if !bok || !tok || base.TenantID != actor.TenantID || target.TenantID != actor.TenantID || base.ProductID != target.ProductID {
		return domain.ContractDiff{}, ErrNotFound
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: base.ProductID, ReleaseID: base.ReleaseID}); err != nil {
		return domain.ContractDiff{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, resourceRefs{ProductID: target.ProductID, ReleaseID: target.ReleaseID}); err != nil {
		return domain.ContractDiff{}, err
	}
	result := "unchanged"
	breaking, nonBreaking := []string{}, []string{}
	if base.Hash != target.Hash {
		result = "changed"
		if target.PathCount < base.PathCount {
			result = "breaking"
			breaking = append(breaking, "target contract has fewer paths than base contract")
		}
		if target.PathCount > base.PathCount {
			nonBreaking = append(nonBreaking, "target contract has additional paths")
		}
	}
	diff := domain.ContractDiff{ID: newID("cdiff"), TenantID: actor.TenantID, BaseContractID: base.ID, TargetContractID: target.ID, ProductID: base.ProductID, ReleaseID: strings.TrimSpace(in.ReleaseID), Result: result, BreakingChanges: breaking, NonBreakingChanges: nonBreaking, SchemaVersion: domain.ContractDiffSchemaVersion, CreatedAt: l.now()}
	l.contractDiffs[diff.ID] = diff
	_, _ = l.appendChainLocked(actor.TenantID, "openapi_contract.diffed", "contract_diff", diff.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ContractDiff{}, err
	}
	return diff, nil
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
	l.customPolicies[policy.ID] = policy
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.created", "custom_policy", policy.ID, "api_key", actor.KeyID, "", "")
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
	l.customPolicyEvals[eval.ID] = eval
	_, _ = l.appendChainLocked(actor.TenantID, "custom_policy.evaluated", "custom_policy_evaluation", eval.ID, "api_key", actor.KeyID, inputHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CustomPolicyEvaluation{}, err
	}
	return eval, nil
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
		var doc struct {
			Version string `json:"version"`
			Runs    []struct {
				Results []struct {
					Level string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := strictDecode(raw, &doc); err != nil || doc.Version == "" {
			return parsedSecurityScan{}, ErrValidation
		}
		summary := map[string]int{}
		total := 0
		for _, run := range doc.Runs {
			for _, result := range run.Results {
				total++
				summary[nonEmpty(strings.ToLower(result.Level), "warning")]++
			}
		}
		return parsedSecurityScan{Format: "sarif", FindingCount: total, Summary: summary}, nil
	}
	var doc struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := strictDecode(raw, &doc); err != nil {
		return parsedSecurityScan{}, ErrValidation
	}
	summary := map[string]int{}
	for _, finding := range doc.Findings {
		summary[nonEmpty(strings.ToLower(finding.Severity), "unknown")]++
	}
	return parsedSecurityScan{Format: strings.TrimSpace(format), FindingCount: len(doc.Findings), Summary: summary}, nil
}

func strictDecode(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ErrValidation
	}
	return nil
}

func diffComponents(base, target []domain.SBOMComponent) ([]domain.SBOMComponent, []domain.SBOMComponent, int) {
	baseSet, targetSet := map[string]domain.SBOMComponent{}, map[string]domain.SBOMComponent{}
	for _, component := range base {
		baseSet[componentKey(component)] = component
	}
	for _, component := range target {
		targetSet[componentKey(component)] = component
	}
	added, removed := []domain.SBOMComponent{}, []domain.SBOMComponent{}
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

func sortComponents(values []domain.SBOMComponent) {
	sort.Slice(values, func(i, j int) bool { return componentKey(values[i]) < componentKey(values[j]) })
}

func componentKey(component domain.SBOMComponent) string {
	if component.PURL != "" {
		return component.PURL
	}
	return component.Name + "@" + component.Version
}

func cyclonedxAnalysisStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "resolved":
		return "fixed"
	case "not_affected":
		return "not_affected"
	case "exploitable", "in_triage":
		return "affected"
	default:
		return ""
	}
}

func (l *Ledger) evaluatePolicyRuleLocked(tenantID, releaseID string, rule domain.PolicyRule) domain.PolicyCheck {
	if rule.EvidenceType == "" {
		return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: "metadata-only custom policy rule recorded"}
	}
	for _, item := range l.evidence {
		if item.TenantID == tenantID && item.ReleaseID == releaseID && item.Type == rule.EvidenceType {
			return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: rule.EvidenceType + " evidence exists"}
		}
	}
	if rule.Required {
		return domain.PolicyCheck{Name: rule.Name, Result: "failed", Severity: rule.Severity, Missing: []string{rule.EvidenceType}, Explanation: rule.EvidenceType + " evidence is missing"}
	}
	return domain.PolicyCheck{Name: rule.Name, Result: "passed", Severity: rule.Severity, Explanation: "optional evidence not present"}
}

func validSeverity(severity string) bool {
	switch severity {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validSecurityScanCategory(category string) bool {
	switch category {
	case "sast", "dast", "secret_scan", "license_scan", "api_security":
		return true
	default:
		return false
	}
}

func validManualDocType(typ string) bool {
	switch typ {
	case "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

func validSensitivity(value string) bool {
	switch value {
	case "internal", "confidential", "restricted":
		return true
	default:
		return false
	}
}

func validVulnWorkflowAction(action string) bool {
	switch action {
	case "scanner_metadata", "sla_set", "scanner_disagreement", "superseded", "reopened":
		return true
	default:
		return false
	}
}

func validPolicyEvidenceType(typ string) bool {
	switch typ {
	case "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "artifact", "build", "build_attestation", "openapi_contract", "release_bundle", "exception", "sast", "dast", "secret_scan", "license_scan", "api_security", "deployment", "threat_model", "security_review", "pen_test_report":
		return true
	default:
		return false
	}
}

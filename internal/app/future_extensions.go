package app

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type CreateEvidenceSummaryInput struct {
	SubjectType string
	SubjectID   string
	EvidenceIDs []string
}

type CreateQuestionnaireDraftInput struct {
	TemplateID string
	ProductID  string
	ReleaseID  string
}

type CreateGraphSnapshotInput struct {
	ProductID string
	ReleaseID string
}

type CreateSaaSEditionProfileInput struct {
	Name           string
	Region         string
	AdminTenantID  string
	IsolationModel string
}

type CreatePublicTransparencyLogInput struct {
	Name      string
	Endpoint  string
	PublicKey string
}

type PublishPublicTransparencyLogEntryInput struct {
	LogID        string
	CheckpointID string
	ExternalID   string
}

type VerifyPublicTransparencyLogEntryInput struct {
	LeafHash       string
	RootHash       string
	LeafIndex      int
	TreeSize       int
	InclusionProof []string
	Source         string
}

type CreateMarketplaceCollectorInput struct {
	Name         string
	Provider     string
	Version      string
	Publisher    string
	ManifestHash string
	SignatureID  string
	SBOMID       string
	ScanID       string
}

type CreatePDFReportPackageInput struct {
	ReportType string
	ProductID  string
	ReleaseID  string
	Title      string
}

type AnomalyReportInput struct {
	SubjectType string
	SubjectID   string
}

type CreateSigningOperationInput struct {
	ProviderID        string
	SubjectType       string
	SubjectID         string
	PayloadHash       string
	ExternalSignature string
}

const signingRequestProfile = verificationapp.ProviderSigningProfile

type VerifyProviderIdentityInput struct {
	ProviderType  string
	ProviderID    string
	Subject       string
	IDToken       string
	SAMLAssertion string
	AccessToken   string
}

func (l *Ledger) CreateEvidenceSummary(ctx context.Context, actor domain.Actor, in CreateEvidenceSummaryInput) (domain.EvidenceSummary, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceSummary{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.EvidenceSummary{}, err
	}
	subjectType, subjectID := strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	if subjectType == "" || subjectID == "" {
		return domain.EvidenceSummary{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID)
	if err != nil {
		return domain.EvidenceSummary{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, refs); err != nil {
		return domain.EvidenceSummary{}, err
	}
	evidenceIDs := sortedStrings(in.EvidenceIDs)
	if len(evidenceIDs) > MaxEvidenceSummaryItems {
		return domain.EvidenceSummary{}, ErrValidation
	}
	if len(evidenceIDs) == 0 {
		var exceeded bool
		evidenceIDs, exceeded = l.evidenceIDsForRefsBoundedLocked(actor.TenantID, refs, "", MaxEvidenceSummaryItems)
		if exceeded {
			return domain.EvidenceSummary{}, ErrValidation
		}
	}
	if len(evidenceIDs) == 0 {
		return domain.EvidenceSummary{}, ErrValidation
	}
	citations := make([]domain.EvidenceCitation, 0, len(evidenceIDs))
	titles := make([]string, 0, len(evidenceIDs))
	for _, id := range evidenceIDs {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != actor.TenantID {
			return domain.EvidenceSummary{}, ErrNotFound
		}
		if !evidenceMatchesRefs(item, refs) {
			return domain.EvidenceSummary{}, ErrValidation
		}
		citations = append(citations, domain.EvidenceCitation{EvidenceID: item.ID, Type: item.Type, Title: item.Title, CanonicalHash: item.CanonicalHash})
		titles = append(titles, item.Title)
	}
	summaryText := "Technical evidence recorded for " + subjectType + " " + subjectID + ": " + strings.Join(titles, "; ") + "."
	summary := domain.EvidenceSummary{
		ID:            newID("sum"),
		TenantID:      actor.TenantID,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		EvidenceIDs:   evidenceIDs,
		Summary:       summaryText,
		Citations:     citations,
		Assumptions:   []string{"Summary is generated only from explicitly linked Evydence records."},
		Limitations:   []string{"This summary supports evidence review and does not assert legal compliance, certification, or release security."},
		SchemaVersion: domain.EvidenceSummaryVersion,
		CreatedAt:     l.now(),
	}
	encodedSummary, err := json.Marshal(summary)
	if err != nil {
		return domain.EvidenceSummary{}, err
	}
	if len(encodedSummary) > MaxGeneratedReportBytes {
		return domain.EvidenceSummary{}, ErrValidation
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertEvidenceSummary(ctx, summary); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(summary.CreatedAt, actor.TenantID, "evidence_summary.created", "evidence_summary", summary.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.EvidenceSummary{}, err
		}
		l.evidenceSummaries[summary.ID] = summary
		l.publishCommittedAuditEntryLocked(entry)
		return summary, nil
	}
	l.evidenceSummaries[summary.ID] = summary
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_summary.created", "evidence_summary", summary.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceSummary{}, err
	}
	return summary, nil
}

func (l *Ledger) CreateQuestionnaireDraft(ctx context.Context, actor domain.Actor, in CreateQuestionnaireDraftInput) (domain.QuestionnaireDraft, error) {
	if err := ctx.Err(); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	if err := require(actor, ScopePackageRead); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	normalized, err := packageapp.NormalizeQuestionnaireDraftInput(packageapp.CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return domain.QuestionnaireDraft{}, ErrValidation
	}
	in = CreateQuestionnaireDraftInput{TemplateID: normalized.TemplateID, ProductID: normalized.ProductID, ReleaseID: normalized.ReleaseID}
	l.mu.Lock()
	defer l.mu.Unlock()
	template, ok := l.questionTemplates[strings.TrimSpace(in.TemplateID)]
	if !ok || template.TenantID != actor.TenantID {
		return domain.QuestionnaireDraft{}, ErrNotFound
	}
	if err := l.ensureScopeLocked(actor.TenantID, strings.TrimSpace(in.ProductID), "", strings.TrimSpace(in.ReleaseID)); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopePackageRead, resourceRefs{ProductID: strings.TrimSpace(in.ProductID), ReleaseID: strings.TrimSpace(in.ReleaseID)}); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	responses := make([]domain.QuestionnaireResponse, 0, len(template.Questions))
	for _, question := range template.Questions {
		response, err := l.questionnaireResponseForQuestionLocked(actor, ScopePackageRead, question, in.ProductID, in.ReleaseID)
		if err != nil {
			return domain.QuestionnaireDraft{}, err
		}
		responses = append(responses, response)
	}
	hash, err := canonicalAnyHash(responses)
	if err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	draft := domain.QuestionnaireDraft{
		ID:            newID("qdr"),
		TenantID:      actor.TenantID,
		TemplateID:    template.ID,
		ProductID:     strings.TrimSpace(in.ProductID),
		ReleaseID:     strings.TrimSpace(in.ReleaseID),
		Responses:     responses,
		ManifestHash:  hash,
		Limitations:   []string{"Generated answers are drafts based on stored evidence and do not provide compliance conclusions."},
		SchemaVersion: domain.QuestionnaireDraftVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertQuestionnaireDraft(ctx, draft); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(draft.CreatedAt, actor.TenantID, "questionnaire_draft.created", "questionnaire_draft", draft.ID, actorType(actor), actorID(actor), hash, ""))
			return err
		}); err != nil {
			return domain.QuestionnaireDraft{}, err
		}
		l.questionDrafts[draft.ID] = draft
		l.publishCommittedAuditEntryLocked(entry)
		return draft, nil
	}
	l.questionDrafts[draft.ID] = draft
	_, _ = l.appendChainLocked(actor.TenantID, "questionnaire_draft.created", "questionnaire_draft", draft.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.QuestionnaireDraft{}, err
	}
	return draft, nil
}

func (l *Ledger) CreateGraphSnapshot(ctx context.Context, actor domain.Actor, in CreateGraphSnapshotInput) (domain.EvidenceGraphSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	normalized, err := packageapp.NormalizeGraphSnapshotInput(packageapp.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, ErrValidation
	}
	productID, releaseID := normalized.ProductID, normalized.ReleaseID
	l.mu.Lock()
	defer l.mu.Unlock()
	scope, err := l.authorizeGraphSnapshotLocked(actor, normalized)
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	refs := resourceRefs{ProductID: productID, ReleaseID: releaseID}
	roots := []packagedomain.GraphNode{}
	if productID != "" {
		product := l.products[productID]
		roots = append(roots, packagedomain.GraphNode{ID: product.ID, Type: "product", Label: product.Name})
	}
	if releaseID != "" {
		release := l.releases[releaseID]
		roots = append(roots, packagedomain.GraphNode{ID: release.ID, Type: "release", Label: release.Version})
	}
	remainingNodes := MaxEvidenceGraphNodes - len(roots)
	evidenceIDs, exceeded := l.evidenceIDsForRefsBoundedLocked(actor.TenantID, refs, "", remainingNodes)
	if exceeded {
		return domain.EvidenceGraphSnapshot{}, ErrValidation
	}
	items := make([]packageapp.GraphSnapshotEvidence, 0, len(evidenceIDs))
	for _, id := range evidenceIDs {
		item := l.evidence[id]
		if item.ReleaseID != "" {
			parent, ok := l.releases[item.ReleaseID]
			if !ok || parent.TenantID != actor.TenantID || parent.ProductID != scope.Resources.ProductID {
				return domain.EvidenceGraphSnapshot{}, ErrNotFound
			}
		}
		if len(item.SubjectRefs) > MaxEvidenceGraphEdges {
			return domain.EvidenceGraphSnapshot{}, ErrValidation
		}
		v := packageapp.GraphSnapshotEvidence{ID: item.ID, TenantID: item.TenantID, ProductID: item.ProductID, ReleaseID: item.ReleaseID, Title: item.Title}
		for _, ref := range item.SubjectRefs {
			v.References = append(v.References, packageapp.GraphSnapshotReference{Type: ref.Type, ID: ref.ID})
		}
		items = append(items, v)
	}
	projection, err := packageapp.BuildGraphSnapshotProjection(scope, roots, items)
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, fromPackageContextError(err)
	}
	hash, err := canonicalAnyHash(packageapp.GraphSnapshotHashMaterial(projection))
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	projection.ID, projection.GraphHash, projection.CreatedAt = newID("grf"), hash, l.now()
	graph := graphSnapshotLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertEvidenceGraphSnapshot(ctx, graph); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(graph.CreatedAt, actor.TenantID, "evidence_graph_snapshot.created", "evidence_graph_snapshot", graph.ID, actorType(actor), actorID(actor), hash, ""))
			return err
		}); err != nil {
			return domain.EvidenceGraphSnapshot{}, err
		}
		l.graphSnapshots[graph.ID] = graphSnapshotLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return graph, nil
	}
	l.graphSnapshots[graph.ID] = graphSnapshotLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_graph_snapshot.created", "evidence_graph_snapshot", graph.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	return graph, nil
}

func (l *Ledger) CreateSaaSEditionProfile(ctx context.Context, actor domain.Actor, in CreateSaaSEditionProfileInput) (domain.SaaSEditionProfile, error) {
	if err := ctx.Err(); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	if err := l.AuthorizeCreateSaaSEditionProfile(ctx, actor, in); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	normalized, err := experimentalapp.NormalizeSaaSProfileInput(saasProfileInput(in))
	if err != nil {
		return domain.SaaSEditionProfile{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[normalized.AdminTenantID]; !ok {
		return domain.SaaSEditionProfile{}, ErrNotFound
	}
	if _, ok := l.tenants[actor.TenantID]; !ok {
		return domain.SaaSEditionProfile{}, ErrNotFound
	}
	cfgHash, err := experimentalapp.SaaSProfileConfigHash(saasProfileInput(in))
	if err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	projection, err := experimentalapp.BuildSaaSProfile(newID("saas"), actor.TenantID, normalized, cfgHash, l.now())
	if err != nil {
		return domain.SaaSEditionProfile{}, fromExperimentalCommandError(err)
	}
	profile := SaaSProfileLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertSaaSEditionProfile(ctx, profile); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(profile.CreatedAt, actor.TenantID, "saas_profile.created", "saas_profile", profile.ID, actorType(actor), actorID(actor), cfgHash, ""))
			return err
		}); err != nil {
			return domain.SaaSEditionProfile{}, err
		}
		l.saasProfiles[profile.ID] = SaaSProfileLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return profile, nil
	}
	l.saasProfiles[profile.ID] = SaaSProfileLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "saas_profile.created", "saas_profile", profile.ID, actorType(actor), actorID(actor), cfgHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	return profile, nil
}

func (l *Ledger) CreatePublicTransparencyLog(ctx context.Context, actor domain.Actor, in CreatePublicTransparencyLogInput) (domain.PublicTransparencyLog, error) {
	if err := ctx.Err(); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	if err := l.AuthorizeCreatePublicTransparencyLog(ctx, actor, in); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[actor.TenantID]; !ok {
		return domain.PublicTransparencyLog{}, ErrNotFound
	}
	projection, err := experimentalapp.BuildPublicTransparencyLog(newID("ptl"), actor.TenantID, publicTransparencyLogInput(in), l.now())
	if err != nil {
		return domain.PublicTransparencyLog{}, fromExperimentalCommandError(err)
	}
	record := PublicTransparencyLogLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertPublicTransparencyLog(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "public_transparency_log.created", "public_transparency_log", record.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLog{}, err
		}
		l.publicLogs[record.ID] = record
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	l.publicLogs[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "public_transparency_log.created", "public_transparency_log", record.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	return record, nil
}

func (l *Ledger) PublishPublicTransparencyLogEntry(ctx context.Context, actor domain.Actor, in PublishPublicTransparencyLogEntryInput) (domain.PublicTransparencyLogEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	if err := l.AuthorizePublishPublicTransparencyLogEntry(ctx, actor, in); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	normalized, err := experimentalapp.NormalizePublicTransparencyPublicationInput(publicTransparencyPublicationInput(in))
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	source, err := l.publicTransparencyPublicationSourceLocked(ctx, actor.TenantID, normalized)
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	projection, err := experimentalapp.BuildPublicTransparencyPublication(newID("pte"), actor.TenantID, normalized, source, l.now())
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	entry := PublicTransparencyPublicationLegacyRecord(projection)
	entryHash := entry.EntryHash
	if l.unitOfWork != nil {
		var auditEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertPublicTransparencyLogEntry(ctx, entry); err != nil {
				return err
			}
			var err error
			auditEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(entry.CreatedAt, actor.TenantID, "public_transparency_log_entry.published", "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entryHash, ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLogEntry{}, err
		}
		l.publicLogEntries[entry.ID] = entry
		l.publishCommittedAuditEntryLocked(auditEntry)
		return entry, nil
	}
	l.publicLogEntries[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, "public_transparency_log_entry.published", "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entryHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return entry, nil
}

func (l *Ledger) VerifyPublicTransparencyLogEntry(ctx context.Context, actor domain.Actor, id string, in VerifyPublicTransparencyLogEntryInput) (domain.PublicTransparencyLogEntry, error) {
	if err := l.AuthorizeVerifyPublicTransparencyLogEntry(ctx, actor, id, in); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	current, err := l.publicTransparencyVerificationSourceLocked(ctx, actor.TenantID, strings.TrimSpace(id))
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return l.verifyPublicTransparencyEntryLocked(ctx, actor, in, current)
}

func (l *Ledger) verifyPublicTransparencyEntryLocked(ctx context.Context, actor domain.Actor, in VerifyPublicTransparencyLogEntryInput, current experimentaldomain.PublicTransparencyLogEntry) (domain.PublicTransparencyLogEntry, error) {
	now := l.now()
	verified, err := experimentalapp.BuildPublicTransparencyVerification(current, publicTransparencyProofInput(in), strings.TrimSpace(in.Source), now)
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	entry := PublicTransparencyVerificationLegacyRecord(verified)
	eventType := "public_transparency_log_entry." + entry.State
	if l.unitOfWork != nil {
		var auditEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.UpdatePublicTransparencyLogEntry(ctx, entry, current.State); err != nil {
				return err
			}
			var err error
			auditEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, eventType, "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entry.InclusionProofHash, ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLogEntry{}, err
		}
		l.publicLogEntries[entry.ID] = entry
		l.publishCommittedAuditEntryLocked(auditEntry)
		return PublicTransparencyVerificationLegacyRecord(verified), nil
	}
	l.publicLogEntries[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, eventType, "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entry.InclusionProofHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return PublicTransparencyVerificationLegacyRecord(verified), nil
}

func verifyRFC6962StyleProof(leafHash, rootHash string, leafIndex, treeSize int, proof []string) bool {
	return experimentalapp.VerifyPublicTransparencyProof(leafHash, rootHash, leafIndex, treeSize, proof)
}

func transparencyParentHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func decodeSHA256Digest(value string) ([]byte, error) {
	if !validSHA256Digest(value) {
		return nil, ErrValidation
	}
	return hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func (l *Ledger) CreateMarketplaceCollector(ctx context.Context, actor domain.Actor, in CreateMarketplaceCollectorInput) (domain.MarketplaceCollector, error) {
	if err := ctx.Err(); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	if err := l.AuthorizeCreateMarketplaceCollector(ctx, actor, in); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	normalized, err := experimentalapp.NormalizeMarketplaceCollectorInput(marketplaceCollectorInput(in))
	if err != nil {
		return domain.MarketplaceCollector{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeMarketplaceReferencesLocked(ctx, actor.TenantID, normalized); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	projection, err := experimentalapp.BuildMarketplaceCollector(newID("mpc"), actor.TenantID, normalized, l.now())
	if err != nil {
		return domain.MarketplaceCollector{}, fromExperimentalCommandError(err)
	}
	collector := MarketplaceCollectorLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertMarketplaceCollector(ctx, collector); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(collector.CreatedAt, actor.TenantID, "marketplace_collector.created", "marketplace_collector", collector.ID, actorType(actor), actorID(actor), collector.ManifestHash, ""))
			return err
		}); err != nil {
			return domain.MarketplaceCollector{}, err
		}
		l.marketplaceCollectors[collector.ID] = MarketplaceCollectorLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return collector, nil
	}
	l.marketplaceCollectors[collector.ID] = MarketplaceCollectorLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "marketplace_collector.created", "marketplace_collector", collector.ID, actorType(actor), actorID(actor), collector.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	return collector, nil
}

func (l *Ledger) ListMarketplaceCollectors(ctx context.Context, actor domain.Actor) ([]domain.MarketplaceCollector, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.resourceAllowedLocked(actor, ScopeCollectorRead, resourceRefs{}) {
		return nil, ErrForbidden
	}
	out := []domain.MarketplaceCollector{}
	for _, collector := range l.marketplaceCollectors {
		if collector.TenantID == actor.TenantID {
			out = append(out, cloneLocalMarketplaceCollector(collector))
		}
	}
	sortMarketplaceCollectors(out)
	return out, nil
}

func (l *Ledger) MarketplaceCollectorHealth(ctx context.Context, actor domain.Actor, id string) (domain.MarketplaceCollectorHealthReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.MarketplaceCollectorHealthReport{}, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return domain.MarketplaceCollectorHealthReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.resourceAllowedLocked(actor, ScopeCollectorRead, resourceRefs{}) {
		return domain.MarketplaceCollectorHealthReport{}, ErrForbidden
	}
	collector, ok := l.marketplaceCollectors[strings.TrimSpace(id)]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.MarketplaceCollectorHealthReport{}, ErrNotFound
	}
	collector = cloneLocalMarketplaceCollector(collector)
	checks := []domain.VerifyCheck{{Name: "manifest_digest", Result: "passed", Detail: "collector package manifest digest is recorded"}}
	result := "verified"
	if collector.SignatureID == "" {
		result = "incomplete"
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "failed", Detail: "collector package signature evidence is missing"})
	} else if sig, ok := l.signatures[collector.SignatureID]; !ok || sig.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "failed", Detail: "collector package signature evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "passed"})
	}
	if collector.SBOMID == "" {
		result = worseHealth(result, "incomplete")
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "failed", Detail: "collector package SBOM evidence is missing"})
	} else if sbom, ok := l.sboms[collector.SBOMID]; !ok || sbom.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "failed", Detail: "collector package SBOM evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "passed"})
	}
	if collector.ScanID == "" {
		result = worseHealth(result, "incomplete")
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "failed", Detail: "collector package vulnerability scan evidence is missing"})
	} else if scan, ok := l.scans[collector.ScanID]; !ok || scan.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "failed", Detail: "collector package vulnerability scan evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "passed"})
	}
	return domain.MarketplaceCollectorHealthReport{
		ReportType:        "marketplace_collector_health",
		CollectorID:       collector.ID,
		Name:              collector.Name,
		Provider:          collector.Provider,
		Version:           collector.Version,
		SupplyChainStatus: result,
		Checks:            checks,
		Collector:         collector,
		Assumptions:       []string{"Health is based on evidence recorded in Evydence for this tenant."},
		Limitations:       []string{"This report does not prove marketplace trust, package safety, or provider endorsement."},
		GeneratedAt:       l.now(),
	}, nil
}

func worseHealth(current, candidate string) string {
	if current == "failed" || candidate == "failed" {
		return "failed"
	}
	if current == "incomplete" || candidate == "incomplete" {
		return "incomplete"
	}
	return "verified"
}

type oidcJWTHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

type oidcJWTClaims struct {
	Issuer        string `json:"iss"`
	Audience      any    `json:"aud"`
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	ExpiresAt     int64  `json:"exp"`
	NotBefore     int64  `json:"nbf,omitempty"`
	IssuedAt      int64  `json:"iat,omitempty"`
}

func verifyOIDCIDToken(provider domain.SSOProvider, expectedSubject, token string, now time.Time) ([]domain.VerifyCheck, error) {
	checks := []domain.VerifyCheck{}
	if len(token) > 16*1024 {
		return []domain.VerifyCheck{{Name: "id_token_size", Result: "failed"}}, ErrVerificationFailed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return []domain.VerifyCheck{{Name: "id_token_shape", Result: "failed"}}, ErrVerificationFailed
	}
	headerBody, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	var header oidcJWTHeader
	if err := json.Unmarshal(headerBody, &header); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_header", Result: "failed"}}, ErrVerificationFailed
	}
	if (header.Alg != "EdDSA" && header.Alg != "RS256") || strings.TrimSpace(header.KID) == "" {
		return []domain.VerifyCheck{{Name: "id_token_algorithm", Result: "failed"}}, ErrVerificationFailed
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	unsigned := parts[0] + "." + parts[1]
	if err := verifyOIDCJWTSignature(provider.JWKS, header, []byte(unsigned), signature); err != nil {
		return []domain.VerifyCheck{{Name: "id_token_signature", Result: "failed"}}, ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "id_token_signature", Result: "passed"})
	claimsBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return checksWithFailure(checks, "id_token_claims"), ErrVerificationFailed
	}
	var claims oidcJWTClaims
	if err := json.Unmarshal(claimsBody, &claims); err != nil {
		return checksWithFailure(checks, "id_token_claims"), ErrVerificationFailed
	}
	if claims.Issuer != provider.Issuer {
		return checksWithFailure(checks, "issuer"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "issuer", Result: "passed"})
	if !audienceContains(claims.Audience, provider.ClientID) {
		return checksWithFailure(checks, "audience"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "audience", Result: "passed"})
	if claims.Subject == "" || claims.Subject != expectedSubject {
		return checksWithFailure(checks, "subject"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "subject", Result: "passed"})
	if claims.ExpiresAt == 0 || !time.Unix(claims.ExpiresAt, 0).After(now) {
		return checksWithFailure(checks, "expiry"), ErrVerificationFailed
	}
	if claims.NotBefore != 0 && time.Unix(claims.NotBefore, 0).After(now.Add(time.Minute)) {
		return checksWithFailure(checks, "not_before"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "token_time", Result: "passed"})
	if claims.Email != "" && !claims.EmailVerified {
		return checksWithFailure(checks, "email_verified"), ErrVerificationFailed
	}
	if claims.Email != "" {
		checks = append(checks, domain.VerifyCheck{Name: "email_verified", Result: "passed"})
	}
	return checks, nil
}

func oidcJWKEd25519Key(jwks map[string]any, kid string) (ed25519.PublicKey, error) {
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil, errors.New("jwks missing keys")
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok || key["kid"] != kid || key["kty"] != "OKP" || key["crv"] != "Ed25519" {
			continue
		}
		x, _ := key["x"].(string)
		pub, err := base64.RawURLEncoding.DecodeString(x)
		if err == nil && len(pub) == ed25519.PublicKeySize {
			return ed25519.PublicKey(pub), nil
		}
	}
	return nil, errors.New("matching jwk not found")
}

func verifyOIDCJWTSignature(jwks map[string]any, header oidcJWTHeader, unsigned, signature []byte) error {
	switch header.Alg {
	case "EdDSA":
		if len(signature) != ed25519.SignatureSize {
			return errors.New("invalid ed25519 signature size")
		}
		key, err := oidcJWKEd25519Key(jwks, header.KID)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, unsigned, signature) {
			return errors.New("invalid ed25519 signature")
		}
		return nil
	case "RS256":
		key, err := oidcJWKRSAKey(jwks, header.KID)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(unsigned)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature)
	default:
		return errors.New("unsupported jwt algorithm")
	}
}

func oidcJWKRSAKey(jwks map[string]any, kid string) (*rsa.PublicKey, error) {
	keys, ok := jwks["keys"].([]any)
	if !ok {
		return nil, errors.New("jwks missing keys")
	}
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok || key["kid"] != kid || key["kty"] != "RSA" {
			continue
		}
		nValue, _ := key["n"].(string)
		eValue, _ := key["e"].(string)
		modulusBytes, err := base64.RawURLEncoding.DecodeString(nValue)
		if err != nil || len(modulusBytes) == 0 {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.DecodeString(eValue)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 8 {
			continue
		}
		exponent := 0
		for _, b := range exponentBytes {
			exponent = exponent<<8 + int(b)
		}
		if exponent < 3 {
			continue
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}, nil
	}
	return nil, errors.New("matching rsa jwk not found")
}

func checksWithFailure(checks []domain.VerifyCheck, name string) []domain.VerifyCheck {
	return append(checks, domain.VerifyCheck{Name: name, Result: "failed"})
}

func audienceContains(audience any, expected string) bool {
	switch got := audience.(type) {
	case string:
		return got == expected
	case []any:
		for _, item := range got {
			if value, ok := item.(string); ok && value == expected {
				return true
			}
		}
	}
	return false
}

type samlAssertionDocument struct {
	XMLName    xml.Name                `xml:"Assertion"`
	Issuer     string                  `xml:"Issuer"`
	Subject    samlAssertionSubject    `xml:"Subject"`
	Conditions samlAssertionConditions `xml:"Conditions"`
	Signature  samlAssertionSignature  `xml:"Signature"`
}

type samlAssertionSubject struct {
	NameID string `xml:"NameID"`
}

type samlAssertionConditions struct {
	NotBefore    string                  `xml:"NotBefore,attr"`
	NotOnOrAfter string                  `xml:"NotOnOrAfter,attr"`
	Audience     samlAudienceRestriction `xml:"AudienceRestriction"`
}

type samlAudienceRestriction struct {
	Audience string `xml:"Audience"`
}

type samlAssertionSignature struct {
	Algorithm      string `xml:"Algorithm,attr"`
	SignatureValue string `xml:"SignatureValue"`
}

func verifySAMLAssertion(provider domain.SSOProvider, expectedSubject, assertion string, now time.Time) ([]domain.VerifyCheck, error) {
	if len(assertion) > 128*1024 {
		return []domain.VerifyCheck{{Name: "saml_assertion_size", Result: "failed"}}, ErrVerificationFailed
	}
	if len(provider.SAMLSigningCertificates) == 0 {
		return []domain.VerifyCheck{{Name: "saml_signing_certificate", Result: "failed"}}, ErrVerificationFailed
	}
	var doc samlAssertionDocument
	decoder := xml.NewDecoder(strings.NewReader(assertion))
	decoder.Strict = true
	if err := decoder.Decode(&doc); err != nil {
		return []domain.VerifyCheck{{Name: "saml_assertion_shape", Result: "failed"}}, ErrVerificationFailed
	}
	checks := []domain.VerifyCheck{{Name: "saml_assertion_shape", Result: "passed"}}
	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.Conditions.NotBefore))
	if err != nil {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	notOnOrAfter, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.Conditions.NotOnOrAfter))
	if err != nil {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	signatureValue, err := base64.StdEncoding.DecodeString(strings.TrimSpace(doc.Signature.SignatureValue))
	if err != nil || strings.TrimSpace(doc.Signature.Algorithm) != "rsa-sha256" {
		return checksWithFailure(checks, "saml_assertion_signature"), ErrVerificationFailed
	}
	payload := samlAssertionSignaturePayload(strings.TrimSpace(doc.Issuer), strings.TrimSpace(doc.Conditions.Audience.Audience), strings.TrimSpace(doc.Subject.NameID), notBefore.UTC().Format(time.RFC3339), notOnOrAfter.UTC().Format(time.RFC3339))
	if err := verifySAMLAssertionSignature(provider.SAMLSigningCertificates, []byte(payload), signatureValue); err != nil {
		return checksWithFailure(checks, "saml_assertion_signature"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "saml_assertion_signature", Result: "passed"})
	if strings.TrimSpace(doc.Issuer) != provider.Issuer {
		return checksWithFailure(checks, "issuer"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "issuer", Result: "passed"})
	if strings.TrimSpace(doc.Conditions.Audience.Audience) != provider.ClientID {
		return checksWithFailure(checks, "audience"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "audience", Result: "passed"})
	if strings.TrimSpace(doc.Subject.NameID) == "" || strings.TrimSpace(doc.Subject.NameID) != expectedSubject {
		return checksWithFailure(checks, "subject"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "subject", Result: "passed"})
	if notBefore.After(now.Add(time.Minute)) || !notOnOrAfter.After(now) {
		return checksWithFailure(checks, "saml_assertion_time"), ErrVerificationFailed
	}
	checks = append(checks, domain.VerifyCheck{Name: "saml_assertion_time", Result: "passed"})
	return checks, nil
}

func samlAssertionSignaturePayload(issuer, audience, subject, notBefore, notOnOrAfter string) string {
	return strings.Join([]string{issuer, audience, subject, notBefore, notOnOrAfter}, "\n")
}

func verifySAMLAssertionSignature(certs []string, payload, signature []byte) error {
	sum := sha256.Sum256(payload)
	for _, raw := range certs {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature) == nil {
			return nil
		}
	}
	return errors.New("no configured saml signing certificate verified assertion")
}

func (l *Ledger) CreatePDFReportPackage(ctx context.Context, actor domain.Actor, in CreatePDFReportPackageInput) (domain.PDFReportPackage, error) {
	if err := ctx.Err(); err != nil {
		return domain.PDFReportPackage{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.PDFReportPackage{}, err
	}
	v, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title})
	if err != nil {
		return domain.PDFReportPackage{}, fromPackageContextError(err)
	}
	reportType, title, productID, releaseID := v.ReportType, v.Title, v.ProductID, v.ReleaseID
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.authorizeProductReleaseLocked(actor, ScopeReportRead, productID, releaseID); err != nil {
		return domain.PDFReportPackage{}, err
	}
	body, err := packageapp.PDFReportPayload(v)
	if err != nil {
		return domain.PDFReportPackage{}, fromPackageContextError(err)
	}
	digest := hashBytes(body)
	stagedPayload, err := l.stagePayload(ctx, actor.TenantID, "application/pdf", digest, body)
	if err != nil {
		return domain.PDFReportPackage{}, err
	}
	ref := stagedPayload.Reference()
	record := domain.PDFReportPackage{ID: newID("pdf"), TenantID: actor.TenantID, ReportType: reportType, ProductID: productID, ReleaseID: releaseID, Title: title, PayloadRef: ref, PayloadHash: digest, PayloadSize: int64(len(body)), Limitations: []string{"PDF output is reproducible report packaging and does not provide legal compliance or security certification."}, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := l.persistStagedObjectPayload(ctx, repos, stagedPayload); err != nil {
				return err
			}
			if err := repos.Future.InsertPDFReportPackage(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "pdf_report.created", "pdf_report", record.ID, actorType(actor), actorID(actor), digest, ""))
			return err
		}); err != nil {
			return domain.PDFReportPackage{}, err
		}
		saved := record
		saved.Limitations = append([]string(nil), record.Limitations...)
		l.pdfReports[record.ID] = saved
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	saved := record
	saved.Limitations = append([]string(nil), record.Limitations...)
	l.pdfReports[record.ID] = saved
	_, _ = l.appendChainLocked(actor.TenantID, "pdf_report.created", "pdf_report", record.ID, actorType(actor), actorID(actor), digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PDFReportPackage{}, err
	}
	return record, nil
}

func (l *Ledger) GenerateAnomalyReport(ctx context.Context, actor domain.Actor, in AnomalyReportInput) (domain.AnomalyReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.AnomalyReport{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.AnomalyReport{}, err
	}
	v, err := experimentalapp.NormalizeAnomalyInput(experimentalapp.AnomalyReportInput{SubjectType: in.SubjectType, SubjectID: in.SubjectID})
	if err != nil {
		return domain.AnomalyReport{}, fromExperimentalCommandError(err)
	}
	subjectType, subjectID := v.SubjectType, v.SubjectID
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID)
	if err != nil {
		return domain.AnomalyReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, refs); err != nil {
		return domain.AnomalyReport{}, err
	}
	var facts experimentalapp.AnomalyReleaseFacts
	if subjectType == "release" {
		facts = experimentalapp.AnomalyReleaseFacts{TenantID: actor.TenantID, ReleaseID: subjectID, HasPassedBuild: l.checkReleaseHasPassedBuildLocked(actor.TenantID, subjectID).Result == "passed", HasVerifiedBuildAttestation: l.checkReleaseHasBuildAttestationLocked(actor.TenantID, subjectID).Result == "passed", UnhandledCritical: len(l.unhandledCriticalFindingsLocked(actor.TenantID, subjectID)) > 0}
	}
	report := anomalyReportFromContext(experimentalapp.BuildAnomalyReport(newID("ano"), actor.TenantID, v, l.now(), facts))
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertAnomalyReport(ctx, report); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(report.CreatedAt, actor.TenantID, "anomaly_report.created", "anomaly_report", report.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.AnomalyReport{}, err
		}
		l.anomalyReports[report.ID] = cloneLocalAnomalyReport(report)
		l.publishCommittedAuditEntryLocked(entry)
		return report, nil
	}
	l.anomalyReports[report.ID] = cloneLocalAnomalyReport(report)
	_, _ = l.appendChainLocked(actor.TenantID, "anomaly_report.created", "anomaly_report", report.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.AnomalyReport{}, err
	}
	return report, nil
}

func (l *Ledger) CreateSigningOperation(ctx context.Context, actor domain.Actor, in CreateSigningOperationInput) (domain.SigningOperation, error) {
	if err := ctx.Err(); err != nil {
		return domain.SigningOperation{}, err
	}
	if err := l.AuthorizeCreateSigningOperation(ctx, actor, in); err != nil {
		return domain.SigningOperation{}, err
	}
	if strings.TrimSpace(in.ExternalSignature) != "" {
		return domain.SigningOperation{}, ErrValidation
	}
	v, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash})
	if err != nil {
		return domain.SigningOperation{}, mapSigningOperationContextError(err)
	}
	providerID, subjectType, subjectID, payloadHash := v.ProviderID, v.SubjectType, v.SubjectID, v.PayloadHash
	l.mu.Lock()
	provider, ok := l.signingProviders[providerID]
	if !ok || provider.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.SigningOperation{}, ErrNotFound
	}
	if _, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID); err != nil {
		l.mu.Unlock()
		return domain.SigningOperation{}, err
	}
	providerActive := provider.Status == "active"
	l.mu.Unlock()

	checks := []domain.VerifyCheck{
		{Name: "provider_active", Result: "passed"},
		{Name: "payload_hash_valid", Result: "passed"},
	}
	if !providerActive {
		checks[0].Result = "failed"
	}
	signatureAlgorithm := "external-" + provider.Type
	if l.signer == nil {
		return domain.SigningOperation{}, ErrValidation
	}
	if !providerActive {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	request := SigningRequest{
		Profile:              signingRequestProfile,
		TenantID:             actor.TenantID,
		ProviderID:           provider.ID,
		ProviderType:         provider.Type,
		ExpectedProviderType: provider.Type,
		KeyRef:               provider.KeyRef,
		SubjectType:          subjectType,
		SubjectID:            subjectID,
		PayloadHash:          payloadHash,
		RequestID:            newID("sreq"),
		Nonce:                newID("snonce"),
	}
	canonicalPayloadHash, err := canonicalSigningRequestHash(request)
	if err != nil {
		return domain.SigningOperation{}, ErrValidation
	}
	request.CanonicalPayloadHash = canonicalPayloadHash
	signed, err := l.signer.Sign(ctx, request)
	if err != nil {
		return domain.SigningOperation{}, err
	}
	if err := validateSigningResult(request, signed); err != nil {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	signed = SanitizeSigningResultMetadata(signed)
	signatureValue := strings.TrimSpace(signed.Signature)
	if signatureValue == "" || len(signatureValue) > 32768 {
		return domain.SigningOperation{}, ErrValidation
	}
	if strings.TrimSpace(signed.Algorithm) != "" {
		signatureAlgorithm = strings.TrimSpace(signed.Algorithm)
	}
	checks = append(checks, signed.Checks...)
	checks = append(checks,
		domain.VerifyCheck{Name: "canonical_signing_request", Result: "passed", Detail: request.Profile},
		domain.VerifyCheck{Name: "signing_executor_invoked", Result: "passed", Detail: strings.TrimSpace(signed.KeyID)},
	)
	result := "passed"
	for _, check := range checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	provider, ok = l.signingProviders[providerID]
	if !ok || provider.TenantID != actor.TenantID {
		return domain.SigningOperation{}, ErrNotFound
	}
	if err := verificationapp.ValidateSigningOperationProvider(verificationapp.SigningOperationProvider{ID: provider.ID, TenantID: provider.TenantID, Type: provider.Type, Status: provider.Status, KeyRef: provider.KeyRef}, actor.TenantID, providerID); err != nil {
		return domain.SigningOperation{}, mapSigningOperationContextError(err)
	}
	if provider.Type != request.ProviderType || provider.KeyRef != request.KeyRef {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	if _, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID); err != nil {
		return domain.SigningOperation{}, err
	}
	signature := domain.Signature{ID: newID("sig"), TenantID: actor.TenantID, SubjectType: subjectType, SubjectID: subjectID, KeyID: provider.ID, Algorithm: signatureAlgorithm, Value: signatureValue, CreatedAt: l.now()}
	op := domain.SigningOperation{ID: newID("sop"), TenantID: actor.TenantID, ProviderID: provider.ID, SubjectType: subjectType, SubjectID: subjectID, PayloadHash: payloadHash, CanonicalPayloadHash: request.CanonicalPayloadHash, RequestID: request.RequestID, ProviderRequestID: strings.TrimSpace(signed.ProviderRequestID), SignatureRef: signature.ID, Result: result, Checks: checks, SchemaVersion: domain.SigningOperationVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertSigningOperation(ctx, signature, op); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(op.CreatedAt, actor.TenantID, "signing_operation.created", "signing_operation", op.ID, actorType(actor), actorID(actor), op.PayloadHash, signature.ID))
			return err
		}); err != nil {
			return domain.SigningOperation{}, err
		}
		l.signatures[signature.ID] = signature
		l.signingOperations[op.ID] = cloneLocalSigningOperation(op)
		l.publishCommittedAuditEntryLocked(entry)
		if result != "passed" {
			return op, ErrVerificationFailed
		}
		return op, nil
	}
	l.signatures[signature.ID] = signature
	l.signingOperations[op.ID] = cloneLocalSigningOperation(op)
	_, _ = l.appendChainLocked(actor.TenantID, "signing_operation.created", "signing_operation", op.ID, actorType(actor), actorID(actor), op.PayloadHash, signature.ID)
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningOperation{}, err
	}
	if result != "passed" {
		return op, ErrVerificationFailed
	}
	return op, nil
}

func canonicalSigningRequestHash(request SigningRequest) (string, error) {
	v, err := verificationapp.CanonicalProviderSigningRequestHash(signingRequestToVerification(request))
	return v, mapSigningOperationContextError(err)
}

func validateSigningResult(request SigningRequest, result SigningResult) error {
	return mapSigningOperationContextError(verificationapp.ValidateProviderSigningResult(signingRequestToVerification(request), SigningResultToVerification(result)))
}

func (l *Ledger) VerifyProviderIdentity(ctx context.Context, actor domain.Actor, in VerifyProviderIdentityInput) (domain.ProviderVerification, error) {
	record, err := l.verifyProviderIdentity(ctx, actor, identityapp.VerifyProviderIdentityInput{
		ProviderType: in.ProviderType, ProviderID: in.ProviderID, Subject: in.Subject,
		IDToken: in.IDToken, SAMLAssertion: in.SAMLAssertion, AccessToken: in.AccessToken,
	})
	return ProviderVerificationFromIdentity(record), fromIdentityContextError(err)
}

func (l *Ledger) ensureFutureSubjectLocked(tenantID, subjectType, subjectID string) (resourceRefs, error) {
	switch subjectType {
	case "tenant":
		if subjectID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{}, nil
	case "product":
		product, ok := l.products[subjectID]
		if !ok || product.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: product.ID}, nil
	case "release":
		release, ok := l.releases[subjectID]
		if !ok || release.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: release.ProductID, ReleaseID: release.ID}, nil
	case "evidence":
		item, ok := l.evidence[subjectID]
		if !ok || item.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return refsForEvidence(item), nil
	case "build":
		build, ok := l.buildRuns[subjectID]
		if !ok || build.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProjectID: build.ProjectID, ReleaseID: build.ReleaseID}, nil
	case "customer_package":
		pkg, ok := l.customerPackages[subjectID]
		if !ok || pkg.TenantID != tenantID {
			return resourceRefs{}, ErrNotFound
		}
		return resourceRefs{ProductID: pkg.ProductID, ReleaseID: pkg.ReleaseID, CustomerPackageID: pkg.ID}, nil
	default:
		return resourceRefs{}, ErrValidation
	}
}

func (l *Ledger) evidenceIDsForQuestionLocked(tenantID string, question domain.QuestionnaireQuestion, productID, releaseID string) []string {
	if question.ControlID != "" {
		ids := []string{}
		for _, link := range l.controlLinks {
			if link.TenantID == tenantID && link.ControlID == question.ControlID && scopeMatches(link.ProductID, productID) && scopeMatches(link.ReleaseID, releaseID) {
				if link.SubjectType == "evidence" {
					ids = append(ids, link.SubjectID)
				}
			}
		}
		return sortedStrings(ids)
	}
	return l.evidenceIDsForRefsLocked(tenantID, resourceRefs{ProductID: strings.TrimSpace(productID), ReleaseID: strings.TrimSpace(releaseID)}, strings.TrimSpace(question.EvidenceType))
}

func (l *Ledger) questionnaireResponseForQuestionLocked(actor domain.Actor, scope string, question domain.QuestionnaireQuestion, productID, releaseID string) (domain.QuestionnaireResponse, error) {
	var response domain.QuestionnaireResponse
	if entry, ok := l.questionnaireAnswerLibraryMatchLocked(actor, scope, question, productID, releaseID); ok {
		response = domain.QuestionnaireResponse{
			QuestionID:  question.ID,
			Answer:      entry.Answer,
			EvidenceIDs: append([]string(nil), entry.EvidenceIDs...),
			Limitations: append([]string(nil), entry.Limitations...),
		}
	} else {
		ids := l.evidenceIDsForQuestionLocked(actor.TenantID, question, productID, releaseID)
		answer := "No matching evidence is recorded for this question."
		if len(ids) > 0 {
			answer = "Evidence is available for review in the linked evidence records."
		}
		response = domain.QuestionnaireResponse{QuestionID: question.ID, Answer: answer, EvidenceIDs: ids, Limitations: []string{"Questionnaire responses summarize recorded evidence and require human review."}}
	}
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	if releaseID != "" {
		release, ok := l.releases[releaseID]
		if !ok || release.TenantID != actor.TenantID || productID != "" && release.ProductID != productID {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
		productID = release.ProductID
	}
	for _, id := range response.EvidenceIDs {
		item, ok := l.evidence[id]
		if !ok || item.TenantID != actor.TenantID {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
		refs := refsForEvidence(item)
		if productID != "" && !l.productCoversRefsLocked(actor.TenantID, productID, refs) || releaseID != "" && !l.releaseCoversRefsLocked(actor.TenantID, releaseID, refs) {
			return domain.QuestionnaireResponse{}, ErrNotFound
		}
	}
	return response, nil
}

func (l *Ledger) questionnaireAnswerLibraryMatchLocked(actor domain.Actor, scope string, question domain.QuestionnaireQuestion, productID, releaseID string) (domain.QuestionnaireAnswerLibraryEntry, bool) {
	productID, releaseID = strings.TrimSpace(productID), strings.TrimSpace(releaseID)
	candidates := []domain.QuestionnaireAnswerLibraryEntry{}
	for _, entry := range l.answerLibrary {
		if entry.TenantID != actor.TenantID || !questionnaireAnswerMatchesQuestion(entry, question) {
			continue
		}
		if entry.ProductID != "" && entry.ProductID != productID {
			continue
		}
		if entry.ReleaseID != "" && entry.ReleaseID != releaseID {
			continue
		}
		if err := l.authorizeResourceLocked(actor, scope, resourceRefs{ProductID: entry.ProductID, ReleaseID: entry.ReleaseID}); err != nil {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		return domain.QuestionnaireAnswerLibraryEntry{}, false
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := questionnaireAnswerSpecificity(candidates[i], question), questionnaireAnswerSpecificity(candidates[j], question)
		if left != right {
			return left > right
		}
		if !candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].CreatedAt.After(candidates[j].CreatedAt)
		}
		return candidates[i].ID < candidates[j].ID
	})
	return candidates[0], true
}

func questionnaireAnswerMatchesQuestion(entry domain.QuestionnaireAnswerLibraryEntry, question domain.QuestionnaireQuestion) bool {
	return packageapp.DraftAnswerMatchesQuestion(packageapp.DraftAnswerCandidate{QuestionID: entry.QuestionID, ControlID: entry.ControlID, EvidenceType: entry.EvidenceType}, packageapp.DraftQuestion{ID: question.ID, ControlID: question.ControlID, EvidenceType: question.EvidenceType})
}

func questionnaireAnswerSpecificity(entry domain.QuestionnaireAnswerLibraryEntry, question domain.QuestionnaireQuestion) int {
	return packageapp.DraftAnswerSpecificity(packageapp.DraftAnswerCandidate{QuestionID: entry.QuestionID, ControlID: entry.ControlID, EvidenceType: entry.EvidenceType, ProductID: entry.ProductID, ReleaseID: entry.ReleaseID}, packageapp.DraftQuestion{ID: question.ID, ControlID: question.ControlID, EvidenceType: question.EvidenceType})
}

func (l *Ledger) evidenceIDsForRefsLocked(tenantID string, refs resourceRefs, evidenceType string) []string {
	ids, _ := l.evidenceIDsForRefsBoundedLocked(tenantID, refs, evidenceType, len(l.evidence)+1)
	return ids
}

// evidenceIDsForRefsBoundedLocked returns no partial list when a traversal
// exceeds its caller-provided budget. Callers therefore fail closed rather
// than silently presenting a truncated graph or report as complete.
func (l *Ledger) evidenceIDsForRefsBoundedLocked(tenantID string, refs resourceRefs, evidenceType string, limit int) ([]string, bool) {
	if limit <= 0 {
		return nil, true
	}
	ids := []string{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID {
			continue
		}
		if evidenceType != "" && item.Type != evidenceType {
			continue
		}
		if evidenceMatchesRefs(item, refs) {
			if len(ids) == limit {
				return nil, true
			}
			ids = append(ids, item.ID)
		}
	}
	return sortedStrings(ids), false
}

func evidenceMatchesRefs(item domain.EvidenceItem, refs resourceRefs) bool {
	if refs.ProductID != "" && item.ProductID != refs.ProductID {
		return false
	}
	if refs.ProjectID != "" && item.ProjectID != refs.ProjectID {
		return false
	}
	if refs.ReleaseID != "" && item.ReleaseID != refs.ReleaseID {
		return false
	}
	return true
}

func sortMarketplaceCollectors(items []domain.MarketplaceCollector) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1].ID > items[j].ID; j-- {
			items[j-1], items[j] = items[j], items[j-1]
		}
	}
}

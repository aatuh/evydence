package app

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
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

type VerifyProviderIdentityInput struct {
	ProviderType  string
	ProviderID    string
	Subject       string
	IDToken       string
	SAMLAssertion string
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
	if len(evidenceIDs) == 0 {
		evidenceIDs = l.evidenceIDsForRefsLocked(actor.TenantID, refs, "")
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
	if strings.TrimSpace(in.TemplateID) == "" {
		return domain.QuestionnaireDraft{}, ErrValidation
	}
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
		ids := l.evidenceIDsForQuestionLocked(actor.TenantID, question, in.ProductID, in.ReleaseID)
		answer := "No matching evidence is recorded for this question."
		if len(ids) > 0 {
			answer = "Evidence is available for this question in " + strings.Join(ids, ", ") + "."
		}
		responses = append(responses, domain.QuestionnaireResponse{
			QuestionID:  question.ID,
			Answer:      answer,
			EvidenceIDs: ids,
			Limitations: []string{"Draft response is evidence-backed but requires human review before external use."},
		})
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
	productID, releaseID := strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	if productID == "" && releaseID == "" {
		return domain.EvidenceGraphSnapshot{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, productID, "", releaseID); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	refs := resourceRefs{ProductID: productID, ReleaseID: releaseID}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceRead, refs); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	nodes := []domain.GraphNode{}
	edges := []domain.GraphEdge{}
	if productID != "" {
		product := l.products[productID]
		nodes = append(nodes, domain.GraphNode{ID: product.ID, Type: "product", Label: product.Name})
	}
	if releaseID != "" {
		release := l.releases[releaseID]
		nodes = append(nodes, domain.GraphNode{ID: release.ID, Type: "release", Label: release.Version})
		if productID != "" {
			edges = append(edges, domain.GraphEdge{From: productID, To: release.ID, Relationship: "has_release"})
		}
	}
	for _, id := range l.evidenceIDsForRefsLocked(actor.TenantID, refs, "") {
		item := l.evidence[id]
		nodes = append(nodes, domain.GraphNode{ID: item.ID, Type: "evidence", Label: item.Title})
		if item.ReleaseID != "" {
			edges = append(edges, domain.GraphEdge{From: item.ReleaseID, To: item.ID, Relationship: "has_evidence"})
		} else if item.ProductID != "" {
			edges = append(edges, domain.GraphEdge{From: item.ProductID, To: item.ID, Relationship: "has_evidence"})
		}
		for _, ref := range item.SubjectRefs {
			if ref.ID != "" {
				edges = append(edges, domain.GraphEdge{From: item.ID, To: ref.ID, Relationship: "references_" + ref.Type})
			}
		}
	}
	hash, err := canonicalAnyHash(struct {
		Nodes []domain.GraphNode `json:"nodes"`
		Edges []domain.GraphEdge `json:"edges"`
	}{Nodes: nodes, Edges: edges})
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	graph := domain.EvidenceGraphSnapshot{
		ID:            newID("grf"),
		TenantID:      actor.TenantID,
		ProductID:     productID,
		ReleaseID:     releaseID,
		Nodes:         nodes,
		Edges:         edges,
		GraphHash:     hash,
		Limitations:   []string{"Snapshot includes stored Evydence adjacency only; absence of a node is not proof that evidence does not exist elsewhere."},
		SchemaVersion: domain.EvidenceGraphSnapshotVersion,
		CreatedAt:     l.now(),
	}
	l.graphSnapshots[graph.ID] = graph
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
	if !actorHasExactScope(actor, ScopeInstanceAdmin) {
		return domain.SaaSEditionProfile{}, ErrForbidden
	}
	name, region, adminTenantID, isolation := strings.TrimSpace(in.Name), strings.TrimSpace(in.Region), strings.TrimSpace(in.AdminTenantID), strings.TrimSpace(in.IsolationModel)
	if name == "" || region == "" || adminTenantID == "" || isolation == "" {
		return domain.SaaSEditionProfile{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[adminTenantID]; !ok {
		return domain.SaaSEditionProfile{}, ErrNotFound
	}
	cfgHash, err := canonicalAnyHash(in)
	if err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	profile := domain.SaaSEditionProfile{
		ID:             newID("saas"),
		TenantID:       actor.TenantID,
		Name:           name,
		Region:         region,
		AdminTenantID:  adminTenantID,
		IsolationModel: isolation,
		Status:         "proposed",
		ConfigHash:     cfgHash,
		Limitations:    []string{"This profile records SaaS edition configuration intent; it is not a deployment readiness certification."},
		SchemaVersion:  domain.SaaSEditionProfileVersion,
		CreatedAt:      l.now(),
	}
	l.saasProfiles[profile.ID] = profile
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
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	name, endpoint, publicKey := strings.TrimSpace(in.Name), strings.TrimSpace(in.Endpoint), strings.TrimSpace(in.PublicKey)
	if name == "" || publicKey == "" || !strings.HasPrefix(endpoint, "https://") {
		return domain.PublicTransparencyLog{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := domain.PublicTransparencyLog{ID: newID("ptl"), TenantID: actor.TenantID, Name: name, Endpoint: endpoint, PublicKey: publicKey, State: "configured", SchemaVersion: domain.PublicTransparencyLogVersion, CreatedAt: l.now()}
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
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	logID, checkpointID, externalID := strings.TrimSpace(in.LogID), strings.TrimSpace(in.CheckpointID), strings.TrimSpace(in.ExternalID)
	if logID == "" || checkpointID == "" || externalID == "" {
		return domain.PublicTransparencyLogEntry{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	logRecord, ok := l.publicLogs[logID]
	if !ok || logRecord.TenantID != actor.TenantID {
		return domain.PublicTransparencyLogEntry{}, ErrNotFound
	}
	checkpoint, ok := l.transparency[checkpointID]
	if !ok || checkpoint.TenantID != actor.TenantID {
		return domain.PublicTransparencyLogEntry{}, ErrNotFound
	}
	batch, ok := l.merkleBatches[checkpoint.BatchID]
	if !ok || batch.TenantID != actor.TenantID {
		return domain.PublicTransparencyLogEntry{}, ErrNotFound
	}
	entryHash, err := canonicalAnyHash(struct {
		LogID        string `json:"log_id"`
		CheckpointID string `json:"checkpoint_id"`
		MerkleRoot   string `json:"merkle_root"`
		ExternalID   string `json:"external_id"`
	}{LogID: logRecord.ID, CheckpointID: checkpoint.ID, MerkleRoot: batch.RootHash, ExternalID: externalID})
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	entry := domain.PublicTransparencyLogEntry{ID: newID("pte"), TenantID: actor.TenantID, LogID: logRecord.ID, CheckpointID: checkpoint.ID, MerkleBatchID: batch.ID, ExternalID: externalID, EntryHash: entryHash, State: "published", SchemaVersion: domain.PublicTransparencyEntryVersion, CreatedAt: l.now()}
	l.publicLogEntries[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, "public_transparency_log_entry.published", "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entryHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return entry, nil
}

func (l *Ledger) CreateMarketplaceCollector(ctx context.Context, actor domain.Actor, in CreateMarketplaceCollectorInput) (domain.MarketplaceCollector, error) {
	if err := ctx.Err(); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	name, provider, version, publisher := strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider), strings.TrimSpace(in.Version), strings.TrimSpace(in.Publisher)
	if name == "" || provider == "" || version == "" || publisher == "" || !validDigest(strings.TrimSpace(in.ManifestHash)) {
		return domain.MarketplaceCollector{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if in.SignatureID != "" {
		sig, ok := l.signatures[strings.TrimSpace(in.SignatureID)]
		if !ok || sig.TenantID != actor.TenantID {
			return domain.MarketplaceCollector{}, ErrNotFound
		}
	}
	if in.SBOMID != "" {
		sbom, ok := l.sboms[strings.TrimSpace(in.SBOMID)]
		if !ok || sbom.TenantID != actor.TenantID {
			return domain.MarketplaceCollector{}, ErrNotFound
		}
	}
	if in.ScanID != "" {
		scan, ok := l.scans[strings.TrimSpace(in.ScanID)]
		if !ok || scan.TenantID != actor.TenantID {
			return domain.MarketplaceCollector{}, ErrNotFound
		}
	}
	collector := domain.MarketplaceCollector{
		ID:            newID("mpc"),
		TenantID:      actor.TenantID,
		Name:          name,
		Provider:      provider,
		Version:       version,
		Publisher:     publisher,
		ManifestHash:  strings.TrimSpace(in.ManifestHash),
		SignatureID:   strings.TrimSpace(in.SignatureID),
		SBOMID:        strings.TrimSpace(in.SBOMID),
		ScanID:        strings.TrimSpace(in.ScanID),
		State:         "registered",
		Limitations:   []string{"Registration records package metadata and does not imply marketplace trust or endorsement."},
		SchemaVersion: domain.MarketplaceCollectorVersion,
		CreatedAt:     l.now(),
	}
	l.marketplaceCollectors[collector.ID] = collector
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
	out := []domain.MarketplaceCollector{}
	for _, collector := range l.marketplaceCollectors {
		if collector.TenantID == actor.TenantID {
			out = append(out, collector)
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
	collector, ok := l.marketplaceCollectors[strings.TrimSpace(id)]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.MarketplaceCollectorHealthReport{}, ErrNotFound
	}
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
	reportType, title := strings.TrimSpace(in.ReportType), strings.TrimSpace(in.Title)
	productID, releaseID := strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID)
	if reportType == "" || title == "" || (productID == "" && releaseID == "") {
		return domain.PDFReportPackage{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureScopeLocked(actor.TenantID, productID, "", releaseID); err != nil {
		return domain.PDFReportPackage{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, resourceRefs{ProductID: productID, ReleaseID: releaseID}); err != nil {
		return domain.PDFReportPackage{}, err
	}
	body := []byte("%PDF-1.4\n% Evydence reproducible report\n1 0 obj << /Type /Catalog >> endobj\n% " + title + "\n% compliance readiness evidence only\n%%EOF\n")
	digest := hashBytes(body)
	ref, err := l.storePayload(ctx, actor.TenantID, "pdf_report", "application/pdf", digest, body)
	if err != nil {
		return domain.PDFReportPackage{}, err
	}
	record := domain.PDFReportPackage{ID: newID("pdf"), TenantID: actor.TenantID, ReportType: reportType, ProductID: productID, ReleaseID: releaseID, Title: title, PayloadRef: ref, PayloadHash: digest, PayloadSize: int64(len(body)), Limitations: []string{"PDF output is reproducible report packaging and does not provide legal compliance or security certification."}, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: l.now()}
	l.pdfReports[record.ID] = record
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
	subjectType, subjectID := strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	if subjectType == "" || subjectID == "" {
		return domain.AnomalyReport{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	refs, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID)
	if err != nil {
		return domain.AnomalyReport{}, err
	}
	if err := l.authorizeResourceLocked(actor, ScopeReportRead, refs); err != nil {
		return domain.AnomalyReport{}, err
	}
	signals := []domain.AnomalySignal{}
	if subjectType == "release" {
		if l.checkReleaseHasPassedBuildLocked(actor.TenantID, subjectID).Result != "passed" {
			signals = append(signals, domain.AnomalySignal{Name: "missing_passed_build", Severity: "medium", Detail: "No passed build run is linked to this release."})
		}
		if l.checkReleaseHasBuildAttestationLocked(actor.TenantID, subjectID).Result != "passed" {
			signals = append(signals, domain.AnomalySignal{Name: "missing_matching_attestation", Severity: "medium", Detail: "No build attestation subject digest matches a release artifact digest."})
		}
		if len(l.unhandledCriticalFindingsLocked(actor.TenantID, subjectID)) > 0 {
			signals = append(signals, domain.AnomalySignal{Name: "unhandled_critical_finding", Severity: "high", Detail: "An open critical finding lacks a valid decision or approved exception."})
		}
	}
	result := "clear"
	if len(signals) > 0 {
		result = "attention_required"
	}
	report := domain.AnomalyReport{ID: newID("ano"), TenantID: actor.TenantID, SubjectType: subjectType, SubjectID: subjectID, Result: result, Signals: signals, Assumptions: []string{"Signals are deterministic checks over stored Evydence records."}, Limitations: []string{"This report identifies evidence anomalies only and does not infer malicious behavior or release security."}, SchemaVersion: domain.AnomalyReportVersion, CreatedAt: l.now()}
	l.anomalyReports[report.ID] = report
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
	if err := require(actor, ScopeKeysAdmin); err != nil {
		return domain.SigningOperation{}, err
	}
	providerID, subjectType, subjectID := strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	signatureValue := strings.TrimSpace(in.ExternalSignature)
	payloadHash := strings.TrimSpace(in.PayloadHash)
	if providerID == "" || subjectType == "" || subjectID == "" || !validDigest(payloadHash) || len(signatureValue) > 32768 {
		return domain.SigningOperation{}, ErrValidation
	}
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
	if signatureValue == "" {
		if l.signer == nil {
			return domain.SigningOperation{}, ErrValidation
		}
		if !providerActive {
			return domain.SigningOperation{}, ErrVerificationFailed
		}
		signed, err := l.signer.Sign(ctx, SigningRequest{
			TenantID:     actor.TenantID,
			ProviderID:   provider.ID,
			ProviderType: provider.Type,
			KeyRef:       provider.KeyRef,
			SubjectType:  subjectType,
			SubjectID:    subjectID,
			PayloadHash:  payloadHash,
		})
		if err != nil {
			return domain.SigningOperation{}, err
		}
		signatureValue = strings.TrimSpace(signed.Signature)
		if signatureValue == "" || len(signatureValue) > 32768 {
			return domain.SigningOperation{}, ErrValidation
		}
		if strings.TrimSpace(signed.Algorithm) != "" {
			signatureAlgorithm = strings.TrimSpace(signed.Algorithm)
		}
		checks = append(checks, signed.Checks...)
		checks = append(checks, domain.VerifyCheck{Name: "signing_executor_invoked", Result: "passed", Detail: strings.TrimSpace(signed.KeyID)})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "external_signature_present", Result: "passed", Detail: "Signature value was supplied by the configured provider path; local cryptographic trust verification is not implied."})
	}
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
	if _, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID); err != nil {
		return domain.SigningOperation{}, err
	}
	signature := domain.Signature{ID: newID("sig"), TenantID: actor.TenantID, SubjectType: subjectType, SubjectID: subjectID, KeyID: provider.ID, Algorithm: signatureAlgorithm, Value: signatureValue, CreatedAt: l.now()}
	l.signatures[signature.ID] = signature
	op := domain.SigningOperation{ID: newID("sop"), TenantID: actor.TenantID, ProviderID: provider.ID, SubjectType: subjectType, SubjectID: subjectID, PayloadHash: payloadHash, SignatureRef: signature.ID, Result: result, Checks: checks, SchemaVersion: domain.SigningOperationVersion, CreatedAt: l.now()}
	l.signingOperations[op.ID] = op
	_, _ = l.appendChainLocked(actor.TenantID, "signing_operation.created", "signing_operation", op.ID, actorType(actor), actorID(actor), op.PayloadHash, signature.ID)
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningOperation{}, err
	}
	if result != "passed" {
		return op, ErrVerificationFailed
	}
	return op, nil
}

func (l *Ledger) VerifyProviderIdentity(ctx context.Context, actor domain.Actor, in VerifyProviderIdentityInput) (domain.ProviderVerification, error) {
	if err := ctx.Err(); err != nil {
		return domain.ProviderVerification{}, err
	}
	if err := require(actor, ScopeIdentityAdmin); err != nil {
		return domain.ProviderVerification{}, err
	}
	providerType, providerID, subject := strings.TrimSpace(in.ProviderType), strings.TrimSpace(in.ProviderID), strings.TrimSpace(in.Subject)
	idToken := strings.TrimSpace(in.IDToken)
	samlAssertion := strings.TrimSpace(in.SAMLAssertion)
	if providerType == "" || providerID == "" || subject == "" {
		return domain.ProviderVerification{}, ErrValidation
	}
	if (providerType == "oidc" && samlAssertion != "") || (providerType == "saml" && idToken != "") {
		return domain.ProviderVerification{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	checks := []domain.VerifyCheck{}
	result := "passed"
	switch providerType {
	case "oidc", "saml":
		provider, ok := l.ssoProviders[providerID]
		if !ok || provider.TenantID != actor.TenantID || provider.Type != providerType {
			return domain.ProviderVerification{}, ErrNotFound
		}
		if idToken != "" {
			tokenChecks, err := verifyOIDCIDToken(provider, subject, idToken, l.now())
			checks = append(checks, tokenChecks...)
			if err != nil {
				result = "failed"
			}
		}
		if samlAssertion != "" {
			assertionChecks, err := verifySAMLAssertion(provider, subject, samlAssertion, l.now())
			checks = append(checks, assertionChecks...)
			if err != nil {
				result = "failed"
			}
		}
		found := false
		for _, link := range l.identityLinks {
			if link.TenantID == actor.TenantID && link.ProviderID == provider.ID && link.Subject == subject && link.Verified {
				found = true
				break
			}
		}
		if found {
			checks = append(checks, domain.VerifyCheck{Name: "verified_identity_link", Result: "passed"})
		} else {
			result = "failed"
			checks = append(checks, domain.VerifyCheck{Name: "verified_identity_link", Result: "failed"})
		}
	default:
		return domain.ProviderVerification{}, ErrValidation
	}
	limitations := []string{"Verification uses stored provider metadata and configured local token/assertion trust roots; no live provider API or discovery call is made."}
	if idToken == "" && samlAssertion == "" {
		limitations = []string{"Verification is limited to stored provider/link metadata because no provider token was supplied."}
	}
	record := domain.ProviderVerification{ID: newID("pvr"), TenantID: actor.TenantID, ProviderType: providerType, ProviderID: providerID, Subject: subject, Result: result, Checks: checks, Limitations: limitations, SchemaVersion: domain.ProviderVerificationVersion, CreatedAt: l.now()}
	l.providerVerifications[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "provider_identity.verified", "provider_identity", record.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ProviderVerification{}, err
	}
	if result != "passed" {
		return record, ErrVerificationFailed
	}
	return record, nil
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

func (l *Ledger) evidenceIDsForRefsLocked(tenantID string, refs resourceRefs, evidenceType string) []string {
	ids := []string{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID {
			continue
		}
		if evidenceType != "" && item.Type != evidenceType {
			continue
		}
		if evidenceMatchesRefs(item, refs) {
			ids = append(ids, item.ID)
		}
	}
	return sortedStrings(ids)
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

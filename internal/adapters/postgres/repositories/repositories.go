// Package repositories contains PostgreSQL implementations of the focused,
// transaction-scoped application persistence ports.
package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// New returns focused repositories bound to tx. The caller owns committing or
// rolling back tx; repositories never start independent transactions.
func New(tx pgx.Tx) app.Repositories {
	return app.Repositories{
		Identity:       identity{tx: tx},
		ReleaseCatalog: releaseCatalog{tx: tx},
		Evidence:       evidence{tx: tx},
		Decisions:      decisions{tx: tx},
		Audit:          audit{tx: tx},
		Idempotency:    idempotency{tx: tx},
		Outbox:         outbox{tx: tx},
		Packages:       packages{tx: tx},
		Signatures:     signatures{tx: tx},
		Verification:   verification{tx: tx},
	}
}

type identity struct{ tx pgx.Tx }

func (r identity) InsertTenant(ctx context.Context, tenant domain.Tenant) error {
	if tenant.ID == "" || tenant.Name == "" || tenant.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO tenants (id, name, created_at)
		VALUES ($1, $2, $3)
	`, tenant.ID, tenant.Name, tenant.CreatedAt)
	return writeError("insert tenant", err)
}

func (r identity) InsertAPIKey(ctx context.Context, key domain.APIKey) error {
	if key.ID == "" || key.TenantID == "" || key.Name == "" || key.Prefix == "" || key.Hash == "" || key.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	scopes, err := json.Marshal(key.Scopes)
	if err != nil {
		return fmt.Errorf("encode API key scopes: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO api_keys (
			id, tenant_id, name, prefix, hash, scopes, expires_at,
			revoked_at, last_used_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, key.ID, key.TenantID, key.Name, key.Prefix, key.Hash, scopes, key.ExpiresAt, key.RevokedAt, key.LastUsedAt, key.CreatedAt)
	return writeError("insert API key", err)
}

type releaseCatalog struct{ tx pgx.Tx }

func (r releaseCatalog) InsertProduct(ctx context.Context, product domain.Product) error {
	if product.ID == "" || product.TenantID == "" || product.Name == "" || product.Slug == "" || product.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, product.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO products (id, tenant_id, name, slug, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`, product.ID, product.TenantID, product.Name, product.Slug, product.CreatedAt)
	return writeError("insert product", err)
}

func (r releaseCatalog) InsertProject(ctx context.Context, project domain.Project) error {
	if project.ID == "" || project.TenantID == "" || project.ProductID == "" || project.Name == "" || project.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, project.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO projects (id, tenant_id, product_id, name, created_at)
		SELECT $1, $2, product.id, $4, $5
		FROM products product
		WHERE product.id = $3 AND product.tenant_id = $2
	`, project.ID, project.TenantID, project.ProductID, project.Name, project.CreatedAt)
	if err != nil {
		return writeError("insert project", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r releaseCatalog) InsertRelease(ctx context.Context, release domain.Release) error {
	if release.ID == "" || release.TenantID == "" || release.ProductID == "" || release.Version == "" || release.State == "" || release.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, release.TenantID); err != nil {
		return err
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO releases (id, tenant_id, product_id, version, state, frozen_at, approved_at, created_at)
		SELECT $1, $2, product.id, $4, $5, $6, $7, $8
		FROM products product
		WHERE product.id = $3 AND product.tenant_id = $2
	`, release.ID, release.TenantID, release.ProductID, release.Version, release.State, release.FrozenAt, release.ApprovedAt, release.CreatedAt)
	if err != nil {
		return writeError("insert release", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r releaseCatalog) UpdateReleaseState(ctx context.Context, release domain.Release, expectedState string) error {
	if release.ID == "" || release.TenantID == "" || release.ProductID == "" || release.State == "" || expectedState == "" {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE releases
		SET state = $4, frozen_at = $5, approved_at = $6
		WHERE id = $1 AND tenant_id = $2 AND product_id = $3 AND state = $7
	`, release.ID, release.TenantID, release.ProductID, release.State, release.FrozenAt, release.ApprovedAt, expectedState)
	if err != nil {
		return writeError("update release state", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r releaseCatalog) InsertArtifact(ctx context.Context, artifact domain.Artifact) error {
	if artifact.ID == "" || artifact.TenantID == "" || artifact.Name == "" || artifact.MediaType == "" || artifact.Digest == "" || artifact.Size < 0 || artifact.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, artifact.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO artifacts (id, tenant_id, name, media_type, size, digest, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, artifact.ID, artifact.TenantID, artifact.Name, artifact.MediaType, artifact.Size, artifact.Digest, artifact.CreatedAt)
	return writeError("insert artifact", err)
}

func (r releaseCatalog) InsertReleaseCandidate(ctx context.Context, candidate domain.ReleaseCandidate) error {
	if candidate.ID == "" || candidate.TenantID == "" || candidate.ReleaseID == "" || candidate.Name == "" || candidate.State == "" || candidate.SnapshotHash == "" || candidate.SchemaVersion == "" || candidate.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalRelease(ctx, r.tx, candidate.TenantID, candidate.ReleaseID); err != nil {
		return err
	}
	document, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode release candidate document: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO release_candidates (id, tenant_id, release_id, name, state, snapshot_hash, document, schema_version, created_at, promoted_at, rejected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, candidate.ID, candidate.TenantID, candidate.ReleaseID, candidate.Name, candidate.State, candidate.SnapshotHash, document, candidate.SchemaVersion, candidate.CreatedAt, candidate.PromotedAt, candidate.RejectedAt)
	return writeError("insert release candidate", err)
}

func (r releaseCatalog) UpdateReleaseCandidateState(ctx context.Context, candidate domain.ReleaseCandidate, expectedState string) error {
	if candidate.ID == "" || candidate.TenantID == "" || candidate.ReleaseID == "" || candidate.State == "" || expectedState == "" {
		return app.ErrValidation
	}
	document, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("encode release candidate document: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE release_candidates
		SET state = $4, document = $5, promoted_at = $6, rejected_at = $7
		WHERE id = $1 AND tenant_id = $2 AND release_id = $3 AND state = $8
	`, candidate.ID, candidate.TenantID, candidate.ReleaseID, candidate.State, document, candidate.PromotedAt, candidate.RejectedAt, expectedState)
	if err != nil {
		return writeError("update release candidate state", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type evidence struct{ tx pgx.Tx }

func (r evidence) InsertEvidence(ctx context.Context, item domain.EvidenceItem) error {
	if item.ID == "" || item.TenantID == "" || item.Type == "" || item.Title == "" || item.SourceSystem == "" || item.PayloadHash == "" || item.CanonicalHash == "" || item.Canonicalization == "" || item.TrustLevel == "" || item.VerificationStatus == "" || item.ObservedAt.IsZero() || item.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, item.TenantID); err != nil {
		return err
	}
	if err := requireOptionalProduct(ctx, r.tx, item.TenantID, item.ProductID); err != nil {
		return err
	}
	if err := requireOptionalProject(ctx, r.tx, item.TenantID, item.ProjectID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, item.TenantID, item.ReleaseID); err != nil {
		return err
	}
	sourceIdentity, err := json.Marshal(item.SourceIdentity)
	if err != nil {
		return fmt.Errorf("encode evidence source identity: %w", err)
	}
	subjectRefs, err := json.Marshal(item.SubjectRefs)
	if err != nil {
		return fmt.Errorf("encode evidence subject refs: %w", err)
	}
	relatedRefs, err := json.Marshal(item.RelatedEvidenceRefs)
	if err != nil {
		return fmt.Errorf("encode evidence related references: %w", err)
	}
	signatureRefs, err := json.Marshal(item.SignatureRefs)
	if err != nil {
		return fmt.Errorf("encode evidence signature references: %w", err)
	}
	tags, err := json.Marshal(item.Tags)
	if err != nil {
		return fmt.Errorf("encode evidence tags: %w", err)
	}
	metadata, err := json.Marshal(item.Metadata)
	if err != nil {
		return fmt.Errorf("encode evidence metadata: %w", err)
	}
	warnings, err := json.Marshal(item.Warnings)
	if err != nil {
		return fmt.Errorf("encode evidence warnings: %w", err)
	}
	limitations, err := json.Marshal(item.Limitations)
	if err != nil {
		return fmt.Errorf("encode evidence limitations: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO evidence_items (
			id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
			type, subtype, title, source_system, source_identity, collector_id,
			uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
			payload_hash, payload_media_type, payload_size, canonical_hash,
			canonicalization, subject_refs, related_evidence_refs, supersedes,
			superseded_by, trust_level, verification_status, signature_refs,
			chain_entry_id, tags, metadata, warnings, limitations, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13,
			$14, $15, $16, $17, $18,
			$19, $20, $21, $22,
			$23, $24, $25, $26,
			$27, $28, $29, $30,
			$31, $32, $33, $34, $35, $36
		)
	`, item.ID, item.TenantID, nullableString(item.ProductID), nullableString(item.ProjectID), nullableString(item.ReleaseID), nullableString(item.BuildID), nullableString(item.DeploymentID),
		item.Type, nullableString(item.Subtype), item.Title, item.SourceSystem, sourceIdentity, nullableString(item.CollectorID),
		nullableString(item.UploadedBy), item.ObservedAt, nonZeroInt(item.EvidenceVersion, 1), item.SchemaVersion, nullableString(item.PayloadRef),
		item.PayloadHash, nullableString(item.PayloadMediaType), nullableInt64(item.PayloadSize), item.CanonicalHash,
		item.Canonicalization, subjectRefs, relatedRefs, nullableString(item.Supersedes),
		nullableString(item.SupersededBy), item.TrustLevel, item.VerificationStatus, signatureRefs,
		nullableString(item.ChainEntryID), tags, metadata, warnings, limitations, item.CreatedAt)
	return writeError("insert evidence", err)
}

func (r evidence) UpdateEvidenceLinks(ctx context.Context, item domain.EvidenceItem) error {
	if item.ID == "" || item.TenantID == "" {
		return app.ErrValidation
	}
	if err := requireOptionalProduct(ctx, r.tx, item.TenantID, item.ProductID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, item.TenantID, item.ReleaseID); err != nil {
		return err
	}
	relatedRefs, err := json.Marshal(item.RelatedEvidenceRefs)
	if err != nil {
		return fmt.Errorf("encode evidence related references: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET product_id = $3, release_id = $4, related_evidence_refs = $5
		WHERE id = $1 AND tenant_id = $2
	`, item.ID, item.TenantID, nullableString(item.ProductID), nullableString(item.ReleaseID), relatedRefs)
	if err != nil {
		return writeError("update evidence links", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrNotFound
	}
	return nil
}

func (r evidence) RecordSupersession(ctx context.Context, superseded, replacement domain.EvidenceItem) error {
	if superseded.ID == "" || superseded.TenantID == "" || replacement.ID == "" || superseded.TenantID != replacement.TenantID || superseded.SupersededBy != replacement.ID || replacement.Supersedes != superseded.ID {
		return app.ErrValidation
	}
	result, err := r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET superseded_by = $3
		WHERE id = $1 AND tenant_id = $2 AND superseded_by IS NULL
	`, superseded.ID, superseded.TenantID, replacement.ID)
	if err != nil {
		return writeError("record evidence supersession", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	result, err = r.tx.Exec(ctx, `
		UPDATE evidence_items
		SET supersedes = $1
		WHERE id = $3 AND tenant_id = $2 AND supersedes IS NULL
	`, superseded.ID, superseded.TenantID, replacement.ID)
	if err != nil {
		return writeError("record replacement evidence", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

func (r evidence) AppendLifecycle(ctx context.Context, event domain.EvidenceLifecycleEvent) error {
	if event.ID == "" || event.TenantID == "" || event.EvidenceID == "" || event.Action == "" || event.Reason == "" || event.ActorID == "" || event.SchemaVersion == "" || event.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, event.TenantID, event.EvidenceID); err != nil {
		return err
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return fmt.Errorf("encode evidence lifecycle details: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO evidence_lifecycle_events (
			id, tenant_id, evidence_id, action, reason, details, replacement_id,
			actor_id, schema_version, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, event.ID, event.TenantID, event.EvidenceID, event.Action, event.Reason, details, nullableString(event.ReplacementID), event.ActorID, event.SchemaVersion, event.CreatedAt)
	return writeError("append evidence lifecycle event", err)
}

func (r evidence) InsertSBOM(ctx context.Context, sbom domain.SBOM) error {
	if sbom.ID == "" || sbom.TenantID == "" || sbom.EvidenceID == "" || sbom.Format == "" || sbom.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, sbom.TenantID, sbom.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, sbom.TenantID, sbom.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, sbom.TenantID, sbom.ArtifactID); err != nil {
		return err
	}
	components, err := json.Marshal(sbom.Components)
	if err != nil {
		return fmt.Errorf("encode SBOM components: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO sboms (id, tenant_id, evidence_id, release_id, artifact_id, format, spec_version, component_count, components, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, sbom.ID, sbom.TenantID, sbom.EvidenceID, nullableString(sbom.ReleaseID), nullableString(sbom.ArtifactID), sbom.Format, sbom.SpecVersion, sbom.ComponentCount, components, sbom.CreatedAt)
	return writeError("insert SBOM", err)
}

func (r evidence) InsertVulnerabilityScan(ctx context.Context, scan domain.VulnerabilityScan) error {
	if scan.ID == "" || scan.TenantID == "" || scan.EvidenceID == "" || scan.Scanner == "" || scan.TargetRef == "" || scan.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, scan.TenantID, scan.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, scan.TenantID, scan.ReleaseID); err != nil {
		return err
	}
	summary, err := json.Marshal(scan.Summary)
	if err != nil {
		return fmt.Errorf("encode vulnerability scan summary: %w", err)
	}
	findings, err := json.Marshal(scan.Findings)
	if err != nil {
		return fmt.Errorf("encode vulnerability scan findings: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vulnerability_scans (id, tenant_id, evidence_id, release_id, scanner, target_ref, summary, findings, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, scan.ID, scan.TenantID, scan.EvidenceID, nullableString(scan.ReleaseID), scan.Scanner, scan.TargetRef, summary, findings, scan.CreatedAt)
	return writeError("insert vulnerability scan", err)
}

func (r evidence) InsertOpenAPIContract(ctx context.Context, contract domain.OpenAPIContract) error {
	if contract.ID == "" || contract.TenantID == "" || contract.ProductID == "" || contract.EvidenceID == "" || contract.Version == "" || contract.Hash == "" || contract.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalProduct(ctx, r.tx, contract.TenantID, contract.ProductID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, contract.TenantID, contract.ReleaseID); err != nil {
		return err
	}
	if err := requireOwnedEvidence(ctx, r.tx, contract.TenantID, contract.EvidenceID); err != nil {
		return err
	}
	operations, err := json.Marshal(contract.Operations)
	if err != nil {
		return fmt.Errorf("encode OpenAPI operations: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO openapi_contracts (id, tenant_id, product_id, release_id, version, hash, path_count, operations, evidence_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, contract.ID, contract.TenantID, contract.ProductID, nullableString(contract.ReleaseID), contract.Version, contract.Hash, contract.PathCount, operations, contract.EvidenceID, contract.CreatedAt)
	return writeError("insert OpenAPI contract", err)
}

func (r evidence) InsertVEXDocument(ctx context.Context, document domain.VEXDocument) error {
	if document.ID == "" || document.TenantID == "" || document.EvidenceID == "" || document.ReleaseID == "" || document.Format == "" || document.SchemaVersion == "" || document.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedEvidence(ctx, r.tx, document.TenantID, document.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, document.TenantID, document.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, document.TenantID, document.ArtifactID); err != nil {
		return err
	}
	statusSummary, err := json.Marshal(document.StatusSummary)
	if err != nil {
		return fmt.Errorf("encode VEX status summary: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vex_documents (id, tenant_id, evidence_id, release_id, artifact_id, format, author, version, statement_count, status_summary, schema_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, document.ID, document.TenantID, document.EvidenceID, document.ReleaseID, nullableString(document.ArtifactID), document.Format, document.Author, nullableString(document.Version), document.StatementCount, statusSummary, document.SchemaVersion, document.CreatedAt)
	return writeError("insert VEX document", err)
}

func (r evidence) InsertVEXImportReport(ctx context.Context, report domain.VEXImportReport) error {
	if report.ID == "" || report.TenantID == "" || report.VEXDocumentID == "" || report.EvidenceID == "" || report.ParserVersion == "" || report.Status == "" || report.SchemaVersion == "" || report.CreatedAt.IsZero() || report.UpdatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedVEXDocument(ctx, r.tx, report.TenantID, report.VEXDocumentID); err != nil {
		return err
	}
	if err := requireOwnedEvidence(ctx, r.tx, report.TenantID, report.EvidenceID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, report.TenantID, report.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalArtifact(ctx, r.tx, report.TenantID, report.ArtifactID); err != nil {
		return err
	}
	warnings, err := json.Marshal(report.Warnings)
	if err != nil {
		return fmt.Errorf("encode VEX import warnings: %w", err)
	}
	invalidStatements, err := json.Marshal(report.InvalidStatements)
	if err != nil {
		return fmt.Errorf("encode VEX invalid statements: %w", err)
	}
	mappingFailures, err := json.Marshal(report.MappingFailures)
	if err != nil {
		return fmt.Errorf("encode VEX mapping failures: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vex_import_reports (
			id, tenant_id, vex_document_id, evidence_id, release_id, artifact_id,
			parser_version, status, statement_count, decisions_created, decisions_superseded,
			unsupported_fields, warnings, invalid_statements, mapping_failures, failure_code,
			failure_detail, schema_version, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
	`, report.ID, report.TenantID, report.VEXDocumentID, report.EvidenceID, nullableString(report.ReleaseID), nullableString(report.ArtifactID), report.ParserVersion, report.Status, report.StatementCount, report.DecisionsCreated, report.DecisionsSuperseded, textArray(report.UnsupportedFields), warnings, invalidStatements, mappingFailures, report.FailureCode, report.FailureDetail, report.SchemaVersion, report.CreatedAt, report.UpdatedAt)
	return writeError("insert VEX import report", err)
}

type decisions struct{ tx pgx.Tx }

func (r decisions) InsertVulnerabilityDecision(ctx context.Context, decision domain.VulnerabilityDecision) error {
	if decision.ID == "" || decision.TenantID == "" || decision.FindingID == "" || decision.ScanID == "" || decision.Vulnerability == "" || decision.Status == "" || decision.Justification == "" || decision.Source == "" || decision.SchemaVersion == "" || decision.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, decision.TenantID); err != nil {
		return err
	}
	if err := requireOwnedScan(ctx, r.tx, decision.TenantID, decision.ScanID); err != nil {
		return err
	}
	if err := requireOptionalRelease(ctx, r.tx, decision.TenantID, decision.ReleaseID); err != nil {
		return err
	}
	if err := requireOptionalOwnedEvidence(ctx, r.tx, decision.TenantID, decision.EvidenceID); err != nil {
		return err
	}
	supportingRefs := decision.SupportingRefs
	if supportingRefs == nil {
		supportingRefs = []domain.SubjectRef{}
	}
	supportingRefsJSON, err := json.Marshal(supportingRefs)
	if err != nil {
		return fmt.Errorf("encode vulnerability decision supporting references: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO vulnerability_decisions (
			id, tenant_id, finding_id, scan_id, release_id, vulnerability,
			component, sbom_id, sbom_component_purl, sbom_component_name,
			status, justification, impact_statement, action_statement,
			customer_visible, internal_notes, source, evidence_id, evidence_ids, supporting_refs, vex_document_id,
			supersedes, superseded_by, approved_by, reviewed_at, review_due_at, schema_version, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10,
			$11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28
		)
	`, decision.ID, decision.TenantID, decision.FindingID, decision.ScanID, nullableString(decision.ReleaseID), decision.Vulnerability,
		nullableString(decision.Component), nullableString(decision.SBOMID), nullableString(decision.SBOMComponentPURL), nullableString(decision.SBOMComponentName),
		decision.Status, decision.Justification, nullableString(decision.ImpactStatement), nullableString(decision.ActionStatement),
		decision.CustomerVisible, nullableString(decision.InternalNotes), decision.Source, nullableString(decision.EvidenceID), textArray(decision.EvidenceIDs), supportingRefsJSON, nullableString(decision.VEXDocumentID), nullableString(decision.Supersedes), nullableString(decision.SupersededBy),
		nullableString(decision.ApprovedBy), decision.ReviewedAt, decision.ReviewDueAt, decision.SchemaVersion, decision.CreatedAt)
	return writeError("insert vulnerability decision", err)
}

func (r decisions) SupersedeAndInsert(ctx context.Context, decision domain.VulnerabilityDecision, superseded []domain.VulnerabilityDecision) error {
	for _, prior := range superseded {
		if prior.ID == "" || prior.TenantID != decision.TenantID || prior.SupersededBy != decision.ID {
			return app.ErrValidation
		}
		result, err := r.tx.Exec(ctx, `
			UPDATE vulnerability_decisions
			SET superseded_by = $3
			WHERE id = $1 AND tenant_id = $2 AND superseded_by IS NULL
		`, prior.ID, prior.TenantID, decision.ID)
		if err != nil {
			return writeError("supersede vulnerability decision", err)
		}
		if result.RowsAffected() != 1 {
			return app.ErrConflict
		}
	}
	return r.InsertVulnerabilityDecision(ctx, decision)
}

type audit struct{ tx pgx.Tx }

func (r audit) Append(ctx context.Context, entry domain.AuditChainEntry) (domain.AuditChainEntry, error) {
	if entry.ID == "" || entry.TenantID == "" || entry.EntryType == "" || entry.SubjectType == "" || entry.SubjectID == "" || entry.ActorType == "" || entry.ActorID == "" || entry.OccurredAt.IsZero() {
		return domain.AuditChainEntry{}, app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, entry.TenantID); err != nil {
		return domain.AuditChainEntry{}, err
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, entry.TenantID); err != nil {
		return domain.AuditChainEntry{}, writeError("lock tenant audit chain", err)
	}
	var sequence int64
	var previous string
	err := r.tx.QueryRow(ctx, `
		SELECT sequence, entry_hash
		FROM audit_chain_entries
		WHERE tenant_id = $1
		ORDER BY sequence DESC
		LIMIT 1
		FOR UPDATE
	`, entry.TenantID).Scan(&sequence, &previous)
	if errors.Is(err, pgx.ErrNoRows) {
		sequence, previous = 0, ""
	} else if err != nil {
		return domain.AuditChainEntry{}, writeError("load audit chain head", err)
	}
	entry.Sequence = sequence + 1
	entry.PreviousEntryHash = previous
	if entry.SchemaVersion == "" {
		entry.SchemaVersion = domain.AuditChainEntrySchemaVersion
	}
	if err := app.RehashAuditChainEntry(&entry); err != nil {
		return domain.AuditChainEntry{}, err
	}
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return domain.AuditChainEntry{}, fmt.Errorf("encode audit metadata: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO audit_chain_entries (
			id, tenant_id, sequence, entry_type, subject_type, subject_id,
			actor_type, actor_id, occurred_at, request_id, idempotency_key, payload_hash,
			canonical_entry_hash, previous_entry_hash, entry_hash,
			signature_ref, metadata, schema_version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`, entry.ID, entry.TenantID, entry.Sequence, entry.EntryType, entry.SubjectType, entry.SubjectID,
		entry.ActorType, entry.ActorID, entry.OccurredAt, entry.RequestID, entry.IdempotencyKey, nullableString(entry.PayloadHash),
		entry.CanonicalEntryHash, entry.PreviousEntryHash, entry.EntryHash,
		nullableString(entry.SignatureRef), metadata, entry.SchemaVersion)
	if err != nil {
		return domain.AuditChainEntry{}, writeError("append audit chain entry", err)
	}
	return entry, nil
}

type idempotency struct{ tx pgx.Tx }

func (r idempotency) Insert(ctx context.Context, key app.IdempotencyRecordKey, record app.IdempotencyRecord) error {
	if key.TenantID == "" || key.ActorID == "" || key.Method == "" || key.Path == "" || key.IdempotencyKey == "" || record.RequestHash == "" || record.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	response, err := json.Marshal(record.Response)
	if err != nil {
		return fmt.Errorf("encode idempotency response: %w", err)
	}
	result, err := r.tx.Exec(ctx, `
		INSERT INTO idempotency_records (
			tenant_id, actor_key_id, method, path, idempotency_key,
			request_hash, status, response, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT DO NOTHING
	`, key.TenantID, key.ActorID, key.Method, key.Path, key.IdempotencyKey, record.RequestHash, record.Status, response, record.CreatedAt)
	if err != nil {
		return writeError("insert idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

type outbox struct{ tx pgx.Tx }

func (r outbox) Enqueue(ctx context.Context, job app.OutboxJob) error {
	if job.ID == "" || job.TenantID == "" || job.Kind == "" || job.SubjectType == "" || job.SubjectID == "" || job.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, job.TenantID); err != nil {
		return err
	}
	payload, err := json.Marshal(job.Payload)
	if err != nil {
		return fmt.Errorf("encode outbox payload: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO outbox_jobs (
			id, tenant_id, kind, subject_type, subject_id, payload, status,
			attempts, max_attempts, run_after, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, 'queued', 0, 5, now(), $7, now())
	`, job.ID, job.TenantID, job.Kind, job.SubjectType, job.SubjectID, payload, job.CreatedAt)
	return writeError("enqueue outbox job", err)
}

type packages struct{ tx pgx.Tx }

func (r packages) InsertReleaseBundle(ctx context.Context, bundle domain.ReleaseBundle) error {
	if bundle.ID == "" || bundle.TenantID == "" || bundle.ReleaseID == "" || bundle.State == "" || bundle.ManifestHash == "" || bundle.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOptionalRelease(ctx, r.tx, bundle.TenantID, bundle.ReleaseID); err != nil {
		return err
	}
	manifest, err := json.Marshal(bundle.Manifest)
	if err != nil {
		return fmt.Errorf("encode release bundle manifest: %w", err)
	}
	signatureRefs, err := json.Marshal(bundle.SignatureRefs)
	if err != nil {
		return fmt.Errorf("encode release bundle signatures: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO release_bundles (
			id, tenant_id, release_id, state, manifest, manifest_hash, signature_refs,
			created_at, published_at, revoked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`, bundle.ID, bundle.TenantID, bundle.ReleaseID, bundle.State, manifest, bundle.ManifestHash, signatureRefs, bundle.CreatedAt, bundle.PublishedAt, bundle.RevokedAt)
	return writeError("insert release bundle", err)
}

type signatures struct{ tx pgx.Tx }

func (r signatures) InsertSigningKey(ctx context.Context, key domain.SigningKey) error {
	if key.ID == "" || key.TenantID == "" || key.KID == "" || key.Algorithm == "" || key.Status == "" || key.PublicKey == "" || key.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, key.TenantID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO signing_keys (
			id, tenant_id, kid, algorithm, status, public_key,
			encrypted_private_key, created_at, revoked_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, key.ID, key.TenantID, key.KID, key.Algorithm, key.Status, key.PublicKey, nullableBytes(key.Private), key.CreatedAt, key.RevokedAt)
	return writeError("insert signing key", err)
}

func (r signatures) InsertSignature(ctx context.Context, signature domain.Signature) error {
	if signature.ID == "" || signature.TenantID == "" || signature.SubjectType == "" || signature.SubjectID == "" || signature.KeyID == "" || signature.Algorithm == "" || signature.Value == "" || signature.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireOwnedSigningKey(ctx, r.tx, signature.TenantID, signature.KeyID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `
		INSERT INTO signatures (id, tenant_id, subject_type, subject_id, key_id, algorithm, value, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, signature.ID, signature.TenantID, signature.SubjectType, signature.SubjectID, signature.KeyID, signature.Algorithm, signature.Value, signature.CreatedAt)
	return writeError("insert signature", err)
}

type verification struct{ tx pgx.Tx }

func (r verification) InsertVerificationResult(ctx context.Context, result domain.VerificationResult) error {
	if result.ID == "" || result.TenantID == "" || result.SubjectType == "" || result.SubjectID == "" || result.Result == "" || result.VerifiedAt.IsZero() {
		return app.ErrValidation
	}
	if err := requireTenant(ctx, r.tx, result.TenantID); err != nil {
		return err
	}
	checks, err := json.Marshal(result.Checks)
	if err != nil {
		return fmt.Errorf("encode verification checks: %w", err)
	}
	_, err = r.tx.Exec(ctx, `
		INSERT INTO verification_results (id, tenant_id, subject_type, subject_id, result, checks, verified_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, result.ID, result.TenantID, result.SubjectType, result.SubjectID, result.Result, checks, result.VerifiedAt)
	return writeError("insert verification result", err)
}

func requireTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if tenantID == "" {
		return app.ErrValidation
	}
	return requireRow(ctx, tx, `SELECT 1 FROM tenants WHERE id = $1`, tenantID)
}

func requireOptionalProduct(ctx context.Context, tx pgx.Tx, tenantID, productID string) error {
	if productID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM products WHERE id = $1 AND tenant_id = $2`, productID, tenantID)
}

func requireOptionalProject(ctx context.Context, tx pgx.Tx, tenantID, projectID string) error {
	if projectID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM projects WHERE id = $1 AND tenant_id = $2`, projectID, tenantID)
}

func requireOptionalRelease(ctx context.Context, tx pgx.Tx, tenantID, releaseID string) error {
	if releaseID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM releases WHERE id = $1 AND tenant_id = $2`, releaseID, tenantID)
}

func requireOptionalArtifact(ctx context.Context, tx pgx.Tx, tenantID, artifactID string) error {
	if artifactID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM artifacts WHERE id = $1 AND tenant_id = $2`, artifactID, tenantID)
}

func requireOwnedEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string) error {
	if evidenceID == "" {
		return app.ErrValidation
	}
	return requireOptionalOwnedEvidence(ctx, tx, tenantID, evidenceID)
}

func requireOptionalOwnedEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string) error {
	if evidenceID == "" {
		return nil
	}
	return requireRow(ctx, tx, `SELECT 1 FROM evidence_items WHERE id = $1 AND tenant_id = $2`, evidenceID, tenantID)
}

func requireOwnedScan(ctx context.Context, tx pgx.Tx, tenantID, scanID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM vulnerability_scans WHERE id = $1 AND tenant_id = $2`, scanID, tenantID)
}

func requireOwnedVEXDocument(ctx context.Context, tx pgx.Tx, tenantID, vexDocumentID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM vex_documents WHERE id = $1 AND tenant_id = $2`, vexDocumentID, tenantID)
}

func requireOwnedSigningKey(ctx context.Context, tx pgx.Tx, tenantID, keyID string) error {
	return requireRow(ctx, tx, `SELECT 1 FROM signing_keys WHERE id = $1 AND tenant_id = $2`, keyID, tenantID)
}

func requireRow(ctx context.Context, tx pgx.Tx, query string, arguments ...any) error {
	var found int
	err := tx.QueryRow(ctx, query, arguments...).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return writeError("read scoped repository row", err)
	}
	return nil
}

func writeError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505":
			return fmt.Errorf("%w: %s", app.ErrConflict, operation)
		case "23503":
			return fmt.Errorf("%w: %s", app.ErrNotFound, operation)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nonZeroInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func textArray(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

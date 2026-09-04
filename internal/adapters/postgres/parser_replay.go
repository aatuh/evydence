package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// ApplyParserReplay serializes one explicit parser replay by tenant and either
// appends its focused evidence/audit mutation or returns the already committed
// interpretation for the same source evidence and parser version.
func (s *Store) ApplyParserReplay(ctx context.Context, request app.ParserReplayRequest, mutation app.ReleaseLedgerMutation) (string, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return "", false, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	tenantID := strings.TrimSpace(request.TenantID)
	sourceEvidenceID := strings.TrimSpace(request.EvidenceID)
	parserVersion := strings.TrimSpace(request.ParserVersion)
	focusedMutation := validFocusedParserReplayMutation(tenantID, sourceEvidenceID, parserVersion, mutation)
	lookupOnly := emptyParserReplayMutation(mutation)
	if tenantID == "" || sourceEvidenceID == "" || parserVersion == "" || (!focusedMutation && !lookupOnly) {
		return "", false, app.ErrValidation
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", false, fmt.Errorf("begin parser replay transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockWorkerProjectionTenantIDs(ctx, tx, []string{tenantID}); err != nil {
		return "", false, err
	}

	existing, found, err := findParserReplayEvidence(ctx, tx, tenantID, sourceEvidenceID, parserVersion)
	if err != nil {
		return "", false, err
	}
	if found {
		source, err := loadParserReplayEvidence(ctx, tx, tenantID, sourceEvidenceID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", false, app.ErrConflict
			}
			return "", false, err
		}
		entry, err := loadParserReplayAuditEntry(ctx, tx, tenantID, existing.ChainEntryID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return "", false, app.ErrConflict
			}
			return "", false, err
		}
		if err := app.ValidateParserNormalizationRecord(tenantID, existing, source, entry); err != nil {
			return "", false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", false, fmt.Errorf("commit existing parser replay lookup: %w", err)
		}
		return existing.ID, false, nil
	}
	if lookupOnly {
		return "", false, app.ErrConflict
	}

	source, err := loadParserReplayEvidence(ctx, tx, tenantID, sourceEvidenceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, app.ErrConflict
		}
		return "", false, err
	}
	candidate := mutation.Evidence[0]
	if candidate.ProductID != source.ProductID || candidate.ProjectID != source.ProjectID || candidate.ReleaseID != source.ReleaseID || candidate.BuildID != source.BuildID || candidate.DeploymentID != source.DeploymentID {
		return "", false, app.ErrConflict
	}
	if _, err := applyReleaseLedgerMutationTx(ctx, tx, mutation); err != nil {
		return "", false, err
	}
	persisted, err := loadParserReplayEvidence(ctx, tx, tenantID, candidate.ID)
	if err != nil {
		return "", false, err
	}
	entry, err := loadParserReplayAuditEntry(ctx, tx, tenantID, persisted.ChainEntryID)
	if err != nil {
		return "", false, err
	}
	if err := app.ValidateParserNormalizationRecord(tenantID, persisted, source, entry); err != nil {
		return "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, fmt.Errorf("commit parser replay transaction: %w", err)
	}
	return mutation.Evidence[0].ID, true, nil
}

func emptyParserReplayMutation(mutation app.ReleaseLedgerMutation) bool {
	return len(mutation.Products) == 0 && len(mutation.Projects) == 0 && len(mutation.Releases) == 0 && len(mutation.Artifacts) == 0 &&
		len(mutation.Evidence) == 0 && len(mutation.EvidenceLifecycle) == 0 && len(mutation.SBOMs) == 0 && len(mutation.Scans) == 0 &&
		len(mutation.Contracts) == 0 && len(mutation.VEXDocuments) == 0 && len(mutation.VEXImportReports) == 0 && len(mutation.BuildAttestations) == 0 &&
		len(mutation.VulnerabilityDecisions) == 0 && len(mutation.AuditChainEntries) == 0 && len(mutation.OutboxJobs) == 0
}

func findParserReplayEvidence(ctx context.Context, tx pgx.Tx, tenantID, sourceEvidenceID, parserVersion string) (domain.EvidenceItem, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
		       type, subtype, title, source_system, source_identity, collector_id,
		       uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
		       payload_hash, payload_media_type, payload_size, canonical_hash,
		       canonicalization, subject_refs, related_evidence_refs, supersedes,
		       superseded_by, trust_level, verification_status, signature_refs,
		       chain_entry_id, tags, metadata, warnings, limitations, created_at
		FROM evidence_items
		WHERE tenant_id = $1
		  AND type = 'parser_normalization'
		  AND metadata ->> 'replay_of' = $2
		  AND metadata -> 'parser' ->> 'version' = $3
		ORDER BY created_at, id
		FOR UPDATE
		LIMIT 2
	`, tenantID, sourceEvidenceID, parserVersion)
	if err != nil {
		return domain.EvidenceItem{}, false, fmt.Errorf("find parser replay evidence: %w", err)
	}
	defer rows.Close()
	items := make([]domain.EvidenceItem, 0, 2)
	for rows.Next() {
		item, err := scanEvidencePageRow(rows)
		if err != nil {
			return domain.EvidenceItem{}, false, fmt.Errorf("scan parser replay evidence: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return domain.EvidenceItem{}, false, fmt.Errorf("iterate parser replay evidence: %w", err)
	}
	switch len(items) {
	case 0:
		return domain.EvidenceItem{}, false, nil
	case 1:
		return items[0], true, nil
	default:
		return domain.EvidenceItem{}, false, errors.New("multiple durable parser replay records violate idempotency")
	}
}

func loadParserReplayEvidence(ctx context.Context, tx pgx.Tx, tenantID, evidenceID string) (domain.EvidenceItem, error) {
	item, err := scanEvidencePageRow(tx.QueryRow(ctx, `
		SELECT id, tenant_id, product_id, project_id, release_id, build_id, deployment_id,
		       type, subtype, title, source_system, source_identity, collector_id,
		       uploaded_by, observed_at, evidence_version, schema_version, payload_ref,
		       payload_hash, payload_media_type, payload_size, canonical_hash,
		       canonicalization, subject_refs, related_evidence_refs, supersedes,
		       superseded_by, trust_level, verification_status, signature_refs,
		       chain_entry_id, tags, metadata, warnings, limitations, created_at
		FROM evidence_items
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, evidenceID))
	if err != nil {
		return domain.EvidenceItem{}, fmt.Errorf("load parser replay evidence: %w", err)
	}
	return item, nil
}

func loadParserReplayAuditEntry(ctx context.Context, tx pgx.Tx, tenantID, entryID string) (domain.AuditChainEntry, error) {
	var entry domain.AuditChainEntry
	var requestID, idempotencyKey, payloadHash, signatureRef sql.NullString
	var metadata []byte
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, sequence, entry_type, subject_type, subject_id,
		       actor_type, actor_id, occurred_at, request_id, idempotency_key, payload_hash,
		       canonical_entry_hash, previous_entry_hash, entry_hash,
		       signature_ref, metadata, schema_version
		FROM audit_chain_entries
		WHERE tenant_id = $1 AND id = $2
	`, tenantID, entryID).Scan(
		&entry.ID, &entry.TenantID, &entry.Sequence, &entry.EntryType, &entry.SubjectType,
		&entry.SubjectID, &entry.ActorType, &entry.ActorID, &entry.OccurredAt, &requestID,
		&idempotencyKey, &payloadHash, &entry.CanonicalEntryHash, &entry.PreviousEntryHash,
		&entry.EntryHash, &signatureRef, &metadata, &entry.SchemaVersion,
	)
	if err != nil {
		return domain.AuditChainEntry{}, fmt.Errorf("load parser replay audit entry: %w", err)
	}
	entry.RequestID = nullableSQLString(requestID)
	entry.IdempotencyKey = nullableSQLString(idempotencyKey)
	entry.PayloadHash = nullableSQLString(payloadHash)
	entry.SignatureRef = nullableSQLString(signatureRef)
	if err := decodeJSON(metadata, &entry.Metadata); err != nil {
		return domain.AuditChainEntry{}, fmt.Errorf("decode parser replay audit metadata: %w", err)
	}
	return entry, nil
}

func validFocusedParserReplayMutation(tenantID, sourceEvidenceID, parserVersion string, mutation app.ReleaseLedgerMutation) bool {
	if len(mutation.Products) != 0 || len(mutation.Projects) != 0 || len(mutation.Releases) != 0 || len(mutation.Artifacts) != 0 ||
		len(mutation.Evidence) != 1 || len(mutation.EvidenceLifecycle) != 0 || len(mutation.SBOMs) != 0 || len(mutation.Scans) != 0 ||
		len(mutation.Contracts) != 0 || len(mutation.VEXDocuments) != 0 || len(mutation.VEXImportReports) != 0 || len(mutation.BuildAttestations) != 0 ||
		len(mutation.VulnerabilityDecisions) != 0 || len(mutation.AuditChainEntries) != 1 || len(mutation.OutboxJobs) != 0 {
		return false
	}
	item := mutation.Evidence[0]
	entry := mutation.AuditChainEntries[0]
	if item.ID == "" || item.TenantID != tenantID || item.Type != "parser_normalization" || item.ChainEntryID == "" ||
		entry.ID != item.ChainEntryID || entry.TenantID != tenantID || entry.EntryType != "parser.replayed" || entry.SubjectType != "evidence_item" || entry.SubjectID != item.ID {
		return false
	}
	replayOf, _ := item.Metadata["replay_of"].(string)
	parser, _ := item.Metadata["parser"].(map[string]any)
	version, _ := parser["version"].(string)
	if replayOf != sourceEvidenceID || version != parserVersion {
		return false
	}
	for _, ref := range item.RelatedEvidenceRefs {
		if ref.Type == "evidence_item" && ref.ID == sourceEvidenceID && ref.Relationship == "replayed_from" {
			return true
		}
	}
	return false
}

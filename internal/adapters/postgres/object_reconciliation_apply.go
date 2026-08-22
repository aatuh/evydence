package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// ApplyObjectReconciliation commits every planned lifecycle transition with
// its safe receipt and append-only audit evidence in one PostgreSQL
// transaction. Object-store reads happen before this method is called, so no
// provider operation is performed while the database transaction is open.
func (s *Store) ApplyObjectReconciliation(
	ctx context.Context,
	receipt app.ObjectReconciliationReceipt,
	actions []app.ObjectPayloadReconciliationAction,
) error {
	if s == nil || s.pool == nil || receipt.DryRun ||
		!validObjectReconciliationReceipt(receipt) {
		return app.ErrValidation
	}
	for _, action := range actions {
		if action.Payload.TenantID != receipt.TenantID ||
			app.ValidateObjectPayloadForRepository(action.Payload) != nil ||
			!validObjectReconciliationAction(action) {
			return app.ErrValidation
		}
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin object reconciliation apply transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var tenantExists int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM tenants WHERE id = $1`, receipt.TenantID,
	).Scan(&tenantExists); err != nil {
		return fmt.Errorf("verify object reconciliation tenant: %w", err)
	}
	for _, action := range actions {
		if err := applyObjectReconciliationAction(ctx, tx, receipt, action); err != nil {
			return err
		}
	}
	if err := insertObjectReconciliationReceipt(ctx, tx, receipt); err != nil {
		return err
	}
	if err := appendObjectReconciliationAudit(ctx, tx, receipt); err != nil {
		return err
	}
	if err := appendObjectReconciliationActionAudits(ctx, tx, receipt, actions); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit object reconciliation apply transaction: %w", err)
	}
	return nil
}

func validObjectReconciliationAction(action app.ObjectPayloadReconciliationAction) bool {
	switch action.Status {
	case app.ObjectPayloadFinalized:
		return action.FailureCode == "" &&
			action.Payload.Status == app.ObjectPayloadStaged
	case app.ObjectPayloadOrphaned:
		return action.FailureCode == "" &&
			(action.Payload.Status == app.ObjectPayloadStaged ||
				action.Payload.Status == app.ObjectPayloadFinalized)
	case app.ObjectPayloadFailed:
		return action.FailureCode == "reconciliation_mismatch" &&
			(action.Payload.Status == app.ObjectPayloadStaged ||
				action.Payload.Status == app.ObjectPayloadFinalized)
	default:
		return false
	}
}

func applyObjectReconciliationAction(
	ctx context.Context,
	tx pgx.Tx,
	receipt app.ObjectReconciliationReceipt,
	action app.ObjectPayloadReconciliationAction,
) error {
	var (
		result pgconnCommandTag
		err    error
	)
	expectedUpdatedAt := action.Payload.UpdatedAt.UTC()
	switch action.Status {
	case app.ObjectPayloadFinalized:
		result, err = tx.Exec(ctx, `
			UPDATE object_payloads
			SET status = 'finalized', failure_code = NULL, finalized_at = $4,
				failed_at = NULL, orphaned_at = NULL, updated_at = $4
			WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
			  AND status = $5 AND updated_at = $6
		`, action.Payload.TenantID, action.Payload.Digest,
			action.Payload.FinalKey, receipt.CreatedAt.UTC(),
			string(action.Payload.Status), expectedUpdatedAt)
	case app.ObjectPayloadFailed:
		result, err = tx.Exec(ctx, `
			UPDATE object_payloads
			SET status = 'failed', failure_code = $4, failed_at = $5,
				updated_at = $5
			WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
			  AND status = $6 AND updated_at = $7
		`, action.Payload.TenantID, action.Payload.Digest,
			action.Payload.FinalKey, action.FailureCode, receipt.CreatedAt.UTC(),
			string(action.Payload.Status), expectedUpdatedAt)
	case app.ObjectPayloadOrphaned:
		result, err = tx.Exec(ctx, `
			UPDATE object_payloads
			SET status = 'orphaned', failure_code = 'object_missing',
				orphaned_at = $4, updated_at = $4
			WHERE tenant_id = $1 AND digest = $2 AND final_key = $3
			  AND status = $5 AND updated_at = $6
		`, action.Payload.TenantID, action.Payload.Digest,
			action.Payload.FinalKey, receipt.CreatedAt.UTC(),
			string(action.Payload.Status), expectedUpdatedAt)
	default:
		return app.ErrValidation
	}
	if err != nil {
		return fmt.Errorf("apply object reconciliation lifecycle action: %w", err)
	}
	if result.RowsAffected() != 1 {
		return app.ErrConflict
	}
	return nil
}

// pgconnCommandTag is the subset returned by pgx.Tx.Exec that reconciliation
// needs. Keeping the helper narrow avoids coupling this file to pgconn beyond
// pgx's transaction contract.
type pgconnCommandTag interface {
	RowsAffected() int64
}

func insertObjectReconciliationReceipt(
	ctx context.Context,
	tx pgx.Tx,
	receipt app.ObjectReconciliationReceipt,
) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO object_reconciliation_receipts (
			id, schema_version, tenant_id, dry_run, metadata_cursor,
			next_metadata_cursor, provider_cursor, next_provider_cursor,
			scanned_payloads, healthy_payloads, missing_final_objects,
			missing_staged_objects, digest_mismatches,
			recovered_finalizations, abandoned_staging, provider_orphans,
			quarantined_payloads, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
			$13, $14, $15, $16, $17, $18)
	`, receipt.ID, receipt.SchemaVersion, receipt.TenantID, receipt.DryRun,
		receipt.MetadataCursor, nullableReconciliationCursor(receipt.NextMetadataCursor),
		receipt.ProviderCursor, nullableReconciliationCursor(receipt.NextProviderCursor),
		receipt.ScannedPayloads, receipt.HealthyPayloads,
		receipt.MissingFinalObjects, receipt.MissingStagedObjects,
		receipt.DigestMismatches, receipt.RecoveredFinalizations,
		receipt.AbandonedStaging, receipt.ProviderOrphans,
		receipt.QuarantinedPayloads, receipt.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert object reconciliation receipt: %w", err)
	}
	return nil
}

func appendObjectReconciliationAudit(
	ctx context.Context,
	tx pgx.Tx,
	receipt app.ObjectReconciliationReceipt,
) error {
	_, err := repositories.New(tx).Audit.Append(ctx, domain.AuditChainEntry{
		ID:          "ace_" + receipt.ID,
		TenantID:    receipt.TenantID,
		EntryType:   "object_payload.reconciled",
		SubjectType: "object_reconciliation",
		SubjectID:   receipt.ID,
		ActorType:   "worker",
		ActorID:     "evydence-worker",
		OccurredAt:  receipt.CreatedAt.UTC(),
		Metadata: map[string]any{
			"dry_run":                 receipt.DryRun,
			"scanned_payloads":        receipt.ScannedPayloads,
			"missing_final_objects":   receipt.MissingFinalObjects,
			"missing_staged_objects":  receipt.MissingStagedObjects,
			"digest_mismatches":       receipt.DigestMismatches,
			"recovered_finalizations": receipt.RecoveredFinalizations,
			"abandoned_staging":       receipt.AbandonedStaging,
			"provider_orphans":        receipt.ProviderOrphans,
			"quarantined_payloads":    receipt.QuarantinedPayloads,
		},
	})
	if err != nil {
		return fmt.Errorf("append object reconciliation audit entry: %w", err)
	}
	return nil
}

// appendObjectReconciliationActionAudits links every apply-mode mutation to
// its run receipt without persisting object keys, raw payload bytes, media
// contents, or provider error text. The digest is the existing tenant-scoped
// payload identity already stored in PostgreSQL and is sufficient to attribute
// the lifecycle transition.
func appendObjectReconciliationActionAudits(
	ctx context.Context,
	tx pgx.Tx,
	receipt app.ObjectReconciliationReceipt,
	actions []app.ObjectPayloadReconciliationAction,
) error {
	auditRepository := repositories.New(tx).Audit
	for index, action := range actions {
		metadata := map[string]any{
			"receipt_id":    receipt.ID,
			"source_status": string(action.Payload.Status),
			"target_status": string(action.Status),
		}
		if action.FailureCode != "" {
			metadata["failure_code"] = action.FailureCode
		}
		_, err := auditRepository.Append(ctx, domain.AuditChainEntry{
			ID:          fmt.Sprintf("ace_%s_action_%d", receipt.ID, index+1),
			TenantID:    receipt.TenantID,
			EntryType:   "object_payload.reconciliation_action",
			SubjectType: "object_payload",
			SubjectID:   action.Payload.Digest,
			ActorType:   "worker",
			ActorID:     "evydence-worker",
			OccurredAt:  receipt.CreatedAt.UTC(),
			Metadata:    metadata,
		})
		if err != nil {
			return fmt.Errorf("append object reconciliation action audit: %w", err)
		}
	}
	return nil
}

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.AuditLogReader = (*Store)(nil)

const maxAuditMetadataBytes = 1 << 20

// PageAuditLog applies tenant, filters, keyset, and limit in one SQL statement.
// It never reconstructs the audit chain or changes append-only rows.
func (s *Store) PageAuditLog(ctx context.Context, request verificationquery.AuditPageRequest) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(request.TenantID) == "" {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, verificationquery.ErrValidation
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	where := []string{"tenant_id = $1"}
	args := []any{request.TenantID}
	if request.Filter.SubjectType != "" {
		args = append(args, request.Filter.SubjectType)
		where = append(where, fmt.Sprintf("subject_type = $%d", len(args)))
	}
	if request.Filter.SubjectID != "" {
		args = append(args, request.Filter.SubjectID)
		where = append(where, fmt.Sprintf("subject_id = $%d", len(args)))
	}
	if request.Filter.Since != nil {
		args = append(args, request.Filter.Since.UTC())
		where = append(where, fmt.Sprintf("occurred_at >= $%d", len(args)))
	}
	operator, direction := ">", "ASC"
	if request.Page.Direction == appquery.Descending {
		operator, direction = "<", "DESC"
	}
	order := "occurred_at " + direction + ", id " + direction
	switch request.Page.Sort {
	case appquery.SortCreatedAt:
		if request.After != nil {
			occurredAt, err := time.Parse(time.RFC3339Nano, request.After.Value)
			if err != nil || occurredAt.UTC().Format(time.RFC3339Nano) != request.After.Value {
				return appquery.Result[verificationdomain.AuditChainEntry]{}, appquery.ErrInvalidCursor
			}
			args = append(args, occurredAt, request.After.ID)
			where = append(where, fmt.Sprintf("(occurred_at %s $%d OR (occurred_at = $%d AND id %s $%d))", operator, len(args)-1, len(args)-1, operator, len(args)))
		}
	case appquery.SortID:
		order = "id " + direction
		if request.After != nil {
			if request.After.Value != request.After.ID {
				return appquery.Result[verificationdomain.AuditChainEntry]{}, appquery.ErrInvalidCursor
			}
			args = append(args, request.After.ID)
			where = append(where, fmt.Sprintf("id %s $%d", operator, len(args)))
		}
	default:
		return appquery.Result[verificationdomain.AuditChainEntry]{}, appquery.ErrInvalidPage
	}
	args = append(args, request.Page.PageSize+1)
	statement := fmt.Sprintf(`
		SELECT id, tenant_id, sequence, entry_type, subject_type, subject_id,
		       actor_type, actor_id, occurred_at, request_id, idempotency_key,
		       payload_hash, canonical_entry_hash, previous_entry_hash, entry_hash,
		       signature_ref, metadata, schema_version
		FROM audit_chain_entries
		WHERE %s
		ORDER BY %s LIMIT $%d`, strings.Join(where, " AND "), order, len(args))
	rows, err := s.pool.Query(ctx, statement, args...)
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, fmt.Errorf("page audit log: %w", err)
	}
	defer rows.Close()
	items := make([]verificationdomain.AuditChainEntry, 0, request.Page.PageSize+1)
	for rows.Next() {
		var entry verificationdomain.AuditChainEntry
		var requestID, idempotencyKey, payloadHash, signatureRef sql.NullString
		var metadata []byte
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.Sequence, &entry.EntryType,
			&entry.SubjectType, &entry.SubjectID, &entry.ActorType, &entry.ActorID,
			&entry.OccurredAt, &requestID, &idempotencyKey, &payloadHash,
			&entry.CanonicalEntryHash, &entry.PreviousEntryHash, &entry.EntryHash,
			&signatureRef, &metadata, &entry.SchemaVersion); err != nil {
			return appquery.Result[verificationdomain.AuditChainEntry]{}, fmt.Errorf("scan audit log: %w", err)
		}
		if len(metadata) > maxAuditMetadataBytes {
			return appquery.Result[verificationdomain.AuditChainEntry]{}, errors.New("oversized stored audit metadata")
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &entry.Metadata); err != nil {
				return appquery.Result[verificationdomain.AuditChainEntry]{}, errors.New("invalid stored audit metadata")
			}
		}
		entry.RequestID = nullableSQLString(requestID)
		entry.IdempotencyKey = nullableSQLString(idempotencyKey)
		entry.PayloadHash = nullableSQLString(payloadHash)
		entry.SignatureRef = nullableSQLString(signatureRef)
		items = append(items, entry)
	}
	if err := rows.Err(); err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, fmt.Errorf("page audit log: %w", err)
	}
	result := appquery.Result[verificationdomain.AuditChainEntry]{Items: items}
	if len(items) > request.Page.PageSize {
		result.Items = items[:request.Page.PageSize]
		last := result.Items[len(result.Items)-1]
		key := appquery.RecordSortKey(last.ID, last.OccurredAt, request.Page.Sort)
		result.Next = &key
	}
	return result, nil
}

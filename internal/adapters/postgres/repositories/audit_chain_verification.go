package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// LockAuditChainVerification follows the audit writer's projection-then-chain
// fence order. Exclusive fences are required because this command appends its
// own receipt audit entry; a shared-to-exclusive upgrade can deadlock.
func (r verification) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	view := verificationapp.AuditChainVerificationView{TenantID: tenant}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return view, err
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return view, fmt.Errorf("lock verification projection view: %w", err)
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenant); err != nil {
		return view, fmt.Errorf("lock verification audit view: %w", err)
	}
	return readAuditChainView(ctx, r.tx, tenant, true)
}

// ReadAuditChainSnapshotView takes no mutation fence or row lock. The caller
// supplies one read-only repeatable-read transaction shared by all pages.
func ReadAuditChainSnapshotView(ctx context.Context, tx pgx.Tx, tenant string) (verificationapp.AuditChainVerificationView, error) {
	var empty verificationapp.AuditChainVerificationView
	if ctx == nil || tx == nil || !customerCreationID(tenant, false) {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := requireRow(ctx, tx, `SELECT 1 FROM tenants WHERE id=$1`, tenant); err != nil {
		return empty, err
	}
	view, err := readAuditChainView(ctx, tx, tenant, false)
	if err != nil {
		return empty, err
	}
	return view, nil
}

func readAuditChainView(ctx context.Context, tx pgx.Tx, tenant string, lock bool) (verificationapp.AuditChainVerificationView, error) {
	view := verificationapp.AuditChainVerificationView{TenantID: tenant}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id=$1`, tenant).Scan(&view.EntryCount); err != nil {
		return view, err
	}
	if view.EntryCount == 0 {
		return view, nil
	}
	var oversized bool
	rowLock := ""
	if lock {
		rowLock = " FOR SHARE"
	}
	err := tx.QueryRow(ctx, `SELECT sequence,left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1`+rowLock, tenant).Scan(&view.HeadSequence, &view.HeadHash, &oversized)
	if err != nil {
		return view, err
	}
	if oversized {
		return view, app.ErrConflict
	}
	return view, nil
}

func (r verification) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	return r.readAuditChainPage(ctx, view, after, budget, true)
}

// ReadAuditChainSnapshotPage has no write capability. Private canonical audit
// details stay inside verification; signing-key ciphertext is never selected.
func ReadAuditChainSnapshotPage(ctx context.Context, tx pgx.Tx, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	var empty verificationapp.AuditChainVerificationPage
	if ctx == nil || tx == nil || !customerCreationID(view.TenantID, false) {
		return empty, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	page, err := (verification{tx: tx}).readAuditChainPage(ctx, view, after, budget, false)
	if err != nil {
		return empty, err
	}
	return page, nil
}

func (r verification) readAuditChainPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int, lock bool) (verificationapp.AuditChainVerificationPage, error) {
	page := verificationapp.AuditChainVerificationPage{Bindings: map[string]verificationapp.AuditSignatureBinding{}}
	if budget < 0 || budget > verificationapp.MaxAuditChainVerificationBytes {
		return page, app.ErrValidation
	}
	remaining := budget
	rowLock := ""
	if lock {
		rowLock = " FOR SHARE"
	}
	rows, err := r.tx.Query(ctx, `WITH selected AS MATERIALIZED (
		SELECT sequence,jsonb_build_object('id',id,'tenant_id',tenant_id,'sequence',sequence,'entry_type',entry_type,
		'subject_type',subject_type,'subject_id',subject_id,'actor_type',actor_type,'actor_id',actor_id,
		'occurred_at',to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
		'request_id',request_id,'idempotency_key',idempotency_key,'payload_hash',payload_hash,'canonical_entry_hash',canonical_entry_hash,
		'previous_entry_hash',previous_entry_hash,'entry_hash',entry_hash,'signature_ref',signature_ref,'metadata',metadata,'schema_version',schema_version) body
		FROM audit_chain_entries WHERE tenant_id=$1 AND ($2::bigint IS NULL OR sequence>$2) AND sequence<=$3 ORDER BY sequence LIMIT $5`+rowLock+`
	), bounds AS (SELECT coalesce(sum(octet_length(body::text)),0)>$4 AS rejected FROM selected)
	SELECT CASE WHEN bounds.rejected THEN NULL ELSE selected.body END FROM selected CROSS JOIN bounds ORDER BY selected.sequence`, view.TenantID, after, view.HeadSequence, budget, verificationapp.MaxAuditChainVerificationPageEntries)
	if err != nil {
		return page, fmt.Errorf("read verification audit page: %w", err)
	}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return page, err
		}
		if !consumeVerificationBytes(raw, &remaining) {
			rows.Close()
			return page, app.ErrConflict
		}
		var entry domain.AuditChainEntry
		if jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: 4096, MaxStringBytes: verificationapp.MaxAuditChainVerificationBytes}) != nil || json.Unmarshal(raw, &entry) != nil {
			rows.Close()
			return page, app.ErrConflict
		}
		page.Entries = append(page.Entries, verificationdomain.AuditChainEntry(entry))
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	refs := []string{}
	seen := map[string]bool{}
	for _, entry := range page.Entries {
		if entry.SignatureRef == "" {
			continue
		}
		if len(entry.SignatureRef) > 1024 || len(entry.SubjectID) > 1024 {
			return page, app.ErrConflict
		}
		if !seen[entry.SignatureRef] {
			refs = append(refs, entry.SignatureRef)
			seen[entry.SignatureRef] = true
		}
		binding, err := r.readAuditSignatureBinding(ctx, entry, &remaining, lock)
		if errors.Is(err, app.ErrNotFound) {
			continue
		}
		if err != nil {
			return page, err
		}
		page.Bindings[entry.ID] = binding
	}
	material, err := r.readVerificationSigningMaterialWithLocks(ctx, verificationapp.SubjectReference{TenantID: view.TenantID}, refs, verificationapp.MaxBundleVerificationBytes-remaining, lock)
	if err != nil {
		return page, err
	}
	page.Signatures, page.Keys = material.Signatures, material.Keys
	if len(refs) > 0 {
		raw, err := json.Marshal(struct {
			Signatures []verificationdomain.Signature
			Keys       []verificationdomain.SigningKey
		}{page.Signatures, page.Keys})
		if err != nil || !consumeVerificationBytes(raw, &remaining) {
			return page, app.ErrConflict
		}
	}
	page.BytesRead = budget - remaining
	return page, nil
}

func (r verification) readAuditSignatureBinding(ctx context.Context, e verificationdomain.AuditChainEntry, budget *int, lock bool) (verificationapp.AuditSignatureBinding, error) {
	// Fixed allowlisted statements, never request-derived SQL identifiers.
	var statement string
	switch e.SubjectType {
	case "release_bundle":
		statement = `SELECT jsonb_build_object('payload',manifest_hash,'subject_type','release_bundle','subject_id',id) FROM release_bundles WHERE tenant_id=$1 AND id=$2`
	case "evidence_bundle":
		statement = `SELECT jsonb_build_object('payload',manifest_hash,'subject_type','evidence_bundle','subject_id',id) FROM evidence_bundles WHERE tenant_id=$1 AND id=$2`
	case "merkle_batch":
		statement = `SELECT jsonb_build_object('payload',root_hash,'subject_type','merkle_batch','subject_id',id) FROM merkle_batches WHERE tenant_id=$1 AND id=$2`
	case "signing_operation":
		statement = `SELECT jsonb_build_object('payload',payload_hash,'subject_type',subject_type,'subject_id',subject_id) FROM signing_operations WHERE tenant_id=$1 AND id=$2`
	default:
		return verificationapp.AuditSignatureBinding{}, app.ErrNotFound
	}
	if lock {
		statement += " FOR SHARE"
	}
	var raw []byte
	err := r.tx.QueryRow(ctx, `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (`+statement+`) selected(body)`, e.TenantID, e.SubjectID, *budget).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return verificationapp.AuditSignatureBinding{}, app.ErrNotFound
	}
	if err != nil {
		return verificationapp.AuditSignatureBinding{}, err
	}
	if !consumeVerificationBytes(raw, budget) {
		return verificationapp.AuditSignatureBinding{}, app.ErrConflict
	}
	var selected struct {
		Payload     string `json:"payload"`
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	if json.Unmarshal(raw, &selected) != nil || len(selected.Payload) > 1024 || len(selected.SubjectType) > 64 || len(selected.SubjectID) > 1024 {
		return verificationapp.AuditSignatureBinding{}, app.ErrConflict
	}
	return verificationapp.AuditSignatureBinding{Subject: verificationapp.SubjectReference{TenantID: e.TenantID, Type: selected.SubjectType, ID: selected.SubjectID}, Payload: selected.Payload}, nil
}

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
	if err := r.tx.QueryRow(ctx, `SELECT count(*) FROM audit_chain_entries WHERE tenant_id=$1`, tenant).Scan(&view.EntryCount); err != nil {
		return view, err
	}
	if view.EntryCount == 0 {
		return view, nil
	}
	var oversized bool
	err := r.tx.QueryRow(ctx, `SELECT sequence,left(entry_hash,1025),octet_length(entry_hash)>1024 FROM audit_chain_entries WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1 FOR SHARE`, tenant).Scan(&view.HeadSequence, &view.HeadHash, &oversized)
	if err != nil {
		return view, err
	}
	if oversized {
		return view, app.ErrConflict
	}
	return view, nil
}

func (r verification) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, budget int) (verificationapp.AuditChainVerificationPage, error) {
	page := verificationapp.AuditChainVerificationPage{Bindings: map[string]verificationapp.AuditSignatureBinding{}}
	if budget < 0 || budget > verificationapp.MaxAuditChainVerificationBytes {
		return page, app.ErrValidation
	}
	remaining := budget
	rows, err := r.tx.Query(ctx, `SELECT CASE WHEN octet_length(body::text)<=$4 THEN body ELSE NULL END FROM (
		SELECT to_jsonb(a)||jsonb_build_object('occurred_at',to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body
		FROM audit_chain_entries a WHERE tenant_id=$1 AND ($2::bigint IS NULL OR sequence>$2) AND sequence<=$3 ORDER BY sequence LIMIT $5 FOR SHARE
	) selected`, view.TenantID, after, view.HeadSequence, budget, verificationapp.MaxAuditChainVerificationPageEntries)
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
		if json.Unmarshal(raw, &entry) != nil {
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
		binding, err := r.readAuditSignatureBinding(ctx, entry, &remaining)
		if errors.Is(err, app.ErrNotFound) {
			continue
		}
		if err != nil {
			return page, err
		}
		page.Bindings[entry.ID] = binding
	}
	material, err := r.readVerificationSigningMaterial(ctx, verificationapp.SubjectReference{TenantID: view.TenantID}, refs, verificationapp.MaxBundleVerificationBytes-remaining)
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

func (r verification) readAuditSignatureBinding(ctx context.Context, e verificationdomain.AuditChainEntry, budget *int) (verificationapp.AuditSignatureBinding, error) {
	// Fixed allowlisted statements, never request-derived SQL identifiers.
	var statement string
	switch e.SubjectType {
	case "release_bundle":
		statement = `SELECT jsonb_build_object('payload',manifest_hash,'subject_type','release_bundle','subject_id',id) FROM release_bundles WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "evidence_bundle":
		statement = `SELECT jsonb_build_object('payload',manifest_hash,'subject_type','evidence_bundle','subject_id',id) FROM evidence_bundles WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "merkle_batch":
		statement = `SELECT jsonb_build_object('payload',root_hash,'subject_type','merkle_batch','subject_id',id) FROM merkle_batches WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	case "signing_operation":
		statement = `SELECT jsonb_build_object('payload',payload_hash,'subject_type',subject_type,'subject_id',subject_id) FROM signing_operations WHERE tenant_id=$1 AND id=$2 FOR SHARE`
	default:
		return verificationapp.AuditSignatureBinding{}, app.ErrNotFound
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

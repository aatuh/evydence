package repositories

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r verification) ResolveEvidenceVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	refs, err := evidence(r).LockEvidenceBundleEvidence(ctx, tenant, id)
	return verificationapp.SubjectReference{TenantID: tenant, Type: "evidence_item", ID: id, Resources: refs}, err
}

// Only the selected item, its canonical origins and its owning parser facts
// cross this boundary. No tenant aggregate or uploaded object is loaded.
func (r verification) ReadEvidenceVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.EvidenceVerificationSnapshot, error) {
	snapshot := verificationapp.EvidenceVerificationSnapshot{Subject: subject}
	if subject.Type != "evidence_item" {
		return snapshot, app.ErrValidation
	}
	budget := verificationapp.MaxEvidenceVerificationBytes
	item, err := r.readEvidenceWithProvenance(ctx, subject.TenantID, subject.ID, &budget)
	if err != nil {
		return snapshot, err
	}
	snapshot.Item = domain.EvidenceToContextModel(item)
	if item.Canonicalization != evidencedomain.LegacyEvidenceCanonicalizationProfileVersion {
		return snapshot, nil
	}
	rows, err := r.tx.Query(ctx, `SELECT CASE WHEN octet_length((details->$3)::text)<=$4 THEN details->$3 ELSE NULL END
		FROM evidence_lifecycle_events WHERE tenant_id=$1 AND evidence_id=$2 AND schema_version=$5 AND details ? $3
		ORDER BY id LIMIT $6 FOR SHARE`, subject.TenantID, subject.ID, evidencedomain.LegacyCanonicalOriginDetailKey, verificationapp.MaxEvidenceVerificationBytes, evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, verificationapp.MaxEvidenceVerificationOrigins+1)
	if err != nil {
		return snapshot, fmt.Errorf("read evidence canonical origins: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return snapshot, err
		}
		if !consumeVerificationBytes(raw, &budget) || len(snapshot.Lifecycle) == verificationapp.MaxEvidenceVerificationOrigins {
			return snapshot, app.ErrConflict
		}
		var origin any
		if err := json.Unmarshal(raw, &origin); err != nil {
			return snapshot, app.ErrConflict
		}
		snapshot.Lifecycle = append(snapshot.Lifecycle, evidencedomain.EvidenceLifecycleEvent{TenantID: subject.TenantID, EvidenceID: subject.ID, SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: origin}})
	}
	if err := rows.Err(); err != nil {
		return snapshot, fmt.Errorf("iterate canonical origins: %w", err)
	}
	return snapshot, nil
}

// ReadEvidenceWithWorkerProvenance shares the selected-item/provenance read
// with point and lifecycle queries. Callers resolve and authorize coordinates
// first, in this same transaction. No canonical-origin history is needed just
// to return the evidence item; verification loads that history separately.
func ReadEvidenceWithWorkerProvenance(ctx context.Context, tx pgx.Tx, tenant, id string) (evidencedomain.EvidenceItem, error) {
	budget := verificationapp.MaxEvidenceVerificationBytes
	item, err := (verification{tx}).readEvidenceWithProvenance(ctx, tenant, id, &budget)
	if err != nil {
		return evidencedomain.EvidenceItem{}, err
	}
	return domain.EvidenceToContextModel(item), nil
}
func (r verification) readEvidenceWithProvenance(ctx context.Context, tenant, id string, budget *int) (domain.EvidenceItem, error) {
	item, err := r.readVerificationEvidence(ctx, tenant, id, budget)
	if err != nil {
		return domain.EvidenceItem{}, err
	}
	if err := r.validateSelectedWorkerEvidence(ctx, item, budget); err != nil {
		return domain.EvidenceItem{}, err
	}
	return item, nil
}

// Explicit columns preserve the canonical wire format even if the table grows.
// PostgreSQL timestamptz is rendered in UTC, independent of session timezone.
const verificationEvidenceJSON = `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (
	SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'product_id',product_id,'project_id',project_id,'release_id',release_id,'build_id',build_id,'deployment_id',deployment_id,
	'type',type,'subtype',subtype,'title',title,'source_system',source_system,'source_identity',source_identity,'collector_id',collector_id,'uploaded_by',uploaded_by,
	'observed_at',to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'evidence_version',evidence_version,'schema_version',schema_version,
	'payload_ref',payload_ref,'payload_hash',payload_hash,'payload_media_type',payload_media_type,'payload_size',payload_size,'canonical_hash',canonical_hash,'canonicalization',canonicalization,
	'subject_refs',subject_refs,'related_evidence_refs',related_evidence_refs,'supersedes',supersedes,'superseded_by',superseded_by,'trust_level',trust_level,'verification_status',verification_status,
	'signature_refs',signature_refs,'chain_entry_id',chain_entry_id,'tags',tags,'metadata',metadata,'warnings',warnings,'limitations',limitations,
	'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) AS body
	FROM evidence_items WHERE tenant_id=$1 AND id=$2 FOR SHARE) selected`

func (r verification) readVerificationEvidence(ctx context.Context, tenant, id string, budget *int) (domain.EvidenceItem, error) {
	var item domain.EvidenceItem
	err := r.readVerificationJSON(ctx, verificationEvidenceJSON, &item, budget, tenant, id, *budget)
	return item, err
}

func consumeVerificationBytes(raw []byte, budget *int) bool {
	if len(raw) == 0 || len(raw) > *budget {
		return false
	}
	*budget -= len(raw)
	return true
}
func (r verification) readVerificationJSON(ctx context.Context, statement string, target any, budget *int, args ...any) error {
	var raw []byte
	err := r.tx.QueryRow(ctx, statement, args...).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read verification fact: %w", err)
	}
	if !consumeVerificationBytes(raw, budget) {
		return app.ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return app.ErrConflict
	}
	return nil
}

func (r verification) validateSelectedWorkerEvidence(ctx context.Context, item domain.EvidenceItem, budget *int) error {
	if item.Type == "parser_normalization" {
		return r.validateNormalizationVerification(ctx, item, budget)
	}
	// Statements are fixed, not influenced by the request or stored type text.
	var statement string
	switch item.Type {
	case "sbom":
		statement = `SELECT CASE WHEN octet_length(to_jsonb(s)::text)<=$3 THEN to_jsonb(s) ELSE NULL END FROM sboms s WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY id LIMIT $4 FOR SHARE`
	case "vulnerability_scan":
		statement = `SELECT CASE WHEN octet_length(to_jsonb(s)::text)<=$3 THEN to_jsonb(s) ELSE NULL END FROM vulnerability_scans s WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY id LIMIT $4 FOR SHARE`
	case "openapi_contract":
		statement = `SELECT CASE WHEN octet_length(to_jsonb(s)::text)<=$3 THEN to_jsonb(s) ELSE NULL END FROM openapi_contracts s WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY id LIMIT $4 FOR SHARE`
	case "vex":
		statement = `SELECT CASE WHEN octet_length(to_jsonb(s)::text)<=$3 THEN to_jsonb(s) ELSE NULL END FROM vex_documents s WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY id LIMIT $4 FOR SHARE`
	case "build_attestation":
		statement = `SELECT CASE WHEN octet_length(to_jsonb(s)::text)<=$3 THEN to_jsonb(s) ELSE NULL END FROM build_attestations s WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY id LIMIT $4 FOR SHARE`
	default:
		return nil
	}
	rows, err := r.tx.Query(ctx, statement, item.TenantID, item.ID, *budget, verificationapp.MaxEvidenceVerificationOrigins+1)
	if err != nil {
		return fmt.Errorf("read selected worker facts: %w", err)
	}
	// Close rows before any parent query on the same transaction connection.
	var facts []any
	var artifacts []string
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if !consumeVerificationBytes(raw, budget) || len(facts) == verificationapp.MaxEvidenceVerificationOrigins {
			rows.Close()
			return app.ErrConflict
		}
		var fact any
		switch item.Type {
		case "sbom":
			var value domain.SBOM
			err = json.Unmarshal(raw, &value)
			fact = value
			artifacts = append(artifacts, value.ArtifactID)
		case "vulnerability_scan":
			var value domain.VulnerabilityScan
			err = json.Unmarshal(raw, &value)
			fact = value
		case "openapi_contract":
			var value domain.OpenAPIContract
			err = json.Unmarshal(raw, &value)
			fact = value
		case "vex":
			var value domain.VEXDocument
			err = json.Unmarshal(raw, &value)
			fact = value
			artifacts = append(artifacts, value.ArtifactID)
		case "build_attestation":
			var value domain.BuildAttestation
			err = json.Unmarshal(raw, &value)
			fact = value
		}
		if err != nil {
			rows.Close()
			return app.ErrConflict
		}
		facts = append(facts, fact)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fmt.Errorf("iterate selected worker facts: %w", err)
	}
	for _, fact := range facts {
		if err := app.ValidateWorkerEvidenceRecord(item, fact); err != nil {
			return err
		}
	}
	for _, id := range artifacts {
		if id != "" {
			if err := requireRow(ctx, r.tx, `SELECT 1 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, item.TenantID, id); err != nil {
				if errors.Is(err, app.ErrNotFound) {
					return app.ErrConflict
				}
				return err
			}
		}
	}
	return nil
}

func (r verification) validateNormalizationVerification(ctx context.Context, item domain.EvidenceItem, budget *int) error {
	sourceID, _ := item.Metadata["replay_of"].(string)
	if sourceID == "" || len(sourceID) > 1024 || item.ChainEntryID == "" || len(item.ChainEntryID) > 1024 {
		return app.ErrConflict
	}
	if _, err := evidence(r).LockEvidenceBundleEvidence(ctx, item.TenantID, sourceID); err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return app.ErrConflict
		}
		return err
	}
	source, err := r.readVerificationEvidence(ctx, item.TenantID, sourceID, budget)
	if err != nil {
		return err
	}
	switch source.Type {
	case "sbom", "vulnerability_scan", "vex", "openapi_contract":
	default:
		return app.ErrConflict
	}
	if err := r.validateSelectedWorkerEvidence(ctx, source, budget); err != nil {
		return err
	}
	var entry domain.AuditChainEntry
	err = r.readVerificationJSON(ctx, `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (
		SELECT to_jsonb(a)||jsonb_build_object('occurred_at',to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body
		FROM audit_chain_entries a WHERE tenant_id=$1 AND id=$2 FOR SHARE) selected`, &entry, budget, item.TenantID, item.ChainEntryID, *budget)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return app.ErrConflict
		}
		return err
	}
	if err := app.ValidateParserNormalizationRecord(item.TenantID, item, source, entry); err != nil {
		return err
	}
	if entry.Sequence < 1 {
		return app.ErrConflict
	}
	if entry.Sequence == 1 {
		if entry.PreviousEntryHash != "" {
			return app.ErrConflict
		}
		return nil
	}
	var previous domain.AuditChainEntry
	err = r.readVerificationJSON(ctx, `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (
		SELECT to_jsonb(a)||jsonb_build_object('occurred_at',to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body
		FROM audit_chain_entries a WHERE tenant_id=$1 AND sequence=$2 FOR SHARE) selected`, &previous, budget, item.TenantID, entry.Sequence-1, *budget)
	if err != nil {
		if errors.Is(err, app.ErrNotFound) {
			return app.ErrConflict
		}
		return err
	}
	if !app.VerifyAuditChainEntryHash(previous) || entry.PreviousEntryHash != previous.EntryHash {
		return app.ErrConflict
	}
	return nil
}

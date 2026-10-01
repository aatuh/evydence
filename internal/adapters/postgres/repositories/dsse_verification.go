package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r verification) dsseCoordinates(ctx context.Context, tenant, id string, lock bool) (string, string, error) {
	query := `SELECT left(build_id,1025),left(evidence_id,1025),octet_length(build_id)>1024 OR octet_length(evidence_id)>1024 FROM build_attestations WHERE tenant_id=$1 AND id=$2`
	if lock {
		query += ` FOR SHARE`
	}
	var build, evidence string
	var large bool
	err := r.tx.QueryRow(ctx, query, tenant, id).Scan(&build, &evidence, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", app.ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("read attestation coordinates: %w", err)
	}
	if large || build == "" || evidence == "" {
		return "", "", app.ErrConflict
	}
	return build, evidence, nil
}
func (r verification) ResolveDSSEVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	subject := verificationapp.SubjectReference{TenantID: tenant, Type: "build_attestation", ID: id}
	build, evidenceID, err := r.dsseCoordinates(ctx, tenant, id, false)
	if err != nil {
		return subject, err
	}
	// Worker publication locks evidence before parsed records. Use the same
	// ordering, then recheck attestation coordinates under its row lock.
	refs, err := evidence(r).LockEvidenceBundleEvidence(ctx, tenant, evidenceID)
	if err != nil {
		return subject, err
	}
	lockedBuild, lockedEvidence, err := r.dsseCoordinates(ctx, tenant, id, true)
	if err != nil {
		return subject, err
	}
	if build != lockedBuild || evidenceID != lockedEvidence || refs.BuildID != build || refs.ProjectID == "" || refs.ReleaseID == "" {
		return subject, app.ErrConflict
	}
	subject.Resources = refs
	return subject, nil
}
func (r verification) ReadDSSEVerification(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.DSSEVerificationSnapshot, error) {
	snapshot := verificationapp.DSSEVerificationSnapshot{Subject: subject}
	if subject.Type != "build_attestation" {
		return snapshot, app.ErrValidation
	}
	budget := verificationapp.MaxDSSEVerificationBytes
	records := verificationapp.MaxDSSEVerificationRecords
	var attestation domain.BuildAttestation
	err := r.readVerificationJSON(ctx, `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (SELECT to_jsonb(a)||jsonb_build_object('created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body FROM build_attestations a WHERE tenant_id=$1 AND id=$2 FOR SHARE) selected`, &attestation, &budget, subject.TenantID, subject.ID, budget)
	if err != nil {
		return snapshot, err
	}
	item, err := r.readVerificationEvidence(ctx, subject.TenantID, attestation.EvidenceID, &budget)
	if err != nil {
		return snapshot, err
	}
	if attestation.BuildID != subject.Resources.BuildID || app.ValidateWorkerEvidenceRecord(item, attestation) != nil || attestation.PayloadRef != item.PayloadRef || attestation.PayloadHash != item.PayloadHash || attestation.PayloadSize != item.PayloadSize {
		return snapshot, app.ErrConflict
	}
	if !consumeDSSERecords(2+len(attestation.SubjectDigests)+len(item.SubjectRefs), &records) {
		return snapshot, app.ErrConflict
	}
	var payload app.ObjectPayload
	err = r.readVerificationJSON(ctx, `SELECT CASE WHEN octet_length(body::text)<=$3 THEN body ELSE NULL END FROM (
	 SELECT jsonb_build_object('tenant_id',tenant_id,'digest',digest,'size',size,'media_type',media_type,'staging_key',staging_key,'final_key',final_key,'status',status,
	 'created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'updated_at',to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body
	 FROM object_payloads WHERE tenant_id=$1 AND digest=$2 AND status<>'orphaned' FOR SHARE) selected`, &payload, &budget, subject.TenantID, attestation.PayloadHash, budget)
	if err != nil {
		return snapshot, err
	}
	if app.ValidateObjectPayloadForRepository(payload) != nil || payload.Status != app.ObjectPayloadFinalized || payload.Size != attestation.PayloadSize || attestation.PayloadRef != "object://"+payload.FinalKey || !app.ObjectMediaTypesMatch(payload.MediaType, item.PayloadMediaType) {
		return snapshot, app.ErrConflict
	}
	snapshot.EvidenceID, snapshot.PayloadRef, snapshot.PayloadHash, snapshot.PayloadSize = attestation.EvidenceID, attestation.PayloadRef, attestation.PayloadHash, attestation.PayloadSize
	snapshot.PayloadMediaType, snapshot.PayloadFinalized = payload.MediaType, true
	if err := r.readDSSEExpectedSubjects(ctx, subject, &snapshot, &budget, &records); err != nil {
		return snapshot, err
	}
	rows, err := r.tx.Query(ctx, `SELECT CASE WHEN octet_length(body::text)<=$2 THEN body ELSE NULL END FROM (
	 SELECT to_jsonb(d)||jsonb_build_object('created_at',to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) body
	 FROM dsse_trust_roots d WHERE tenant_id=$1 AND status='active' ORDER BY id LIMIT $3 FOR SHARE) selected`, subject.TenantID, budget, records+1)
	if err != nil {
		return snapshot, fmt.Errorf("read attestation trust policies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return snapshot, err
		}
		var root domain.DSSETrustRoot
		if !consumeVerificationBytes(raw, &budget) || json.Unmarshal(raw, &root) != nil || !consumeDSSERecords(1+len(root.AllowedPredicateTypes)+len(root.ExpectedBuilderIDs)+len(root.RequiredClaims), &records) {
			return snapshot, app.ErrConflict
		}
		// Preserve the legacy conservative treatment of unusable roots.
		owned := domain.DSSETrustRootToContextModel(root)
		if verificationapp.ValidDSSETrustRoot(owned) {
			snapshot.Roots = append(snapshot.Roots, owned)
		}
	}
	return snapshot, rows.Err()
}
func consumeDSSERecords(n int, remaining *int) bool {
	if n < 0 || n > *remaining {
		return false
	}
	*remaining -= n
	return true
}

func (r verification) readDSSEExpectedSubjects(ctx context.Context, subject verificationapp.SubjectReference, snapshot *verificationapp.DSSEVerificationSnapshot, budget, records *int) error {
	var outputs []domain.BuildOutput
	if err := r.readVerificationJSON(ctx, `SELECT CASE WHEN octet_length(outputs::text)<=$3 THEN outputs ELSE NULL END FROM build_runs WHERE tenant_id=$1 AND id=$2 FOR SHARE`, &outputs, budget, subject.TenantID, subject.Resources.BuildID, *budget); err != nil {
		return err
	}
	if !consumeDSSERecords(len(outputs), records) {
		return app.ErrConflict
	}
	ids := make([]string, 0, len(outputs))
	seen := map[string]bool{}
	for _, output := range outputs {
		if output.ArtifactID == "" || len(output.ArtifactID) > 1024 || strings.TrimSpace(output.ArtifactID) != output.ArtifactID || app.ValidateCanonicalObjectDigest(output.Digest) != nil {
			return app.ErrConflict
		}
		if !seen[output.ArtifactID] {
			ids = append(ids, output.ArtifactID)
			seen[output.ArtifactID] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := r.tx.Query(ctx, `SELECT left(id,1025),left(digest,1025),octet_length(id)>1024 OR octet_length(digest)>1024 FROM artifacts WHERE tenant_id=$1 AND id=ANY($2) ORDER BY id LIMIT $3 FOR SHARE`, subject.TenantID, ids, *records+1)
	if err != nil {
		return fmt.Errorf("read registered build artifacts: %w", err)
	}
	artifacts := map[string]string{}
	for rows.Next() {
		var id, digest string
		var oversized bool
		if err := rows.Scan(&id, &digest, &oversized); err != nil {
			rows.Close()
			return err
		}
		if oversized || !consumeDSSERecords(1, records) || len(id)+len(digest) > *budget {
			rows.Close()
			return app.ErrConflict
		}
		*budget -= len(id) + len(digest)
		artifacts[id] = digest
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	matching := []domain.BuildOutput{}
	for _, output := range outputs {
		if artifacts[output.ArtifactID] == output.Digest {
			matching = append(matching, output)
		}
	}
	if len(matching) == 0 {
		return nil
	}
	wanted, err := json.Marshal(matching)
	if err != nil {
		return err
	}
	rows, err = r.tx.Query(ctx, `SELECT CASE WHEN octet_length(subject_refs::text)<=$4 THEN subject_refs ELSE NULL END
	 FROM evidence_items e WHERE tenant_id=$1 AND release_id=$2 AND EXISTS (
	 SELECT 1 FROM jsonb_array_elements($3::jsonb) wanted WHERE e.subject_refs @> jsonb_build_array(jsonb_build_object('type','artifact','id',wanted->>'artifact_id')))
	 ORDER BY id LIMIT $5 FOR SHARE`, subject.TenantID, subject.Resources.ReleaseID, wanted, *budget, *records+1)
	if err != nil {
		return fmt.Errorf("read registered release artifact links: %w", err)
	}
	defer rows.Close()
	linked := map[string]bool{}
	for rows.Next() {
		var raw []byte
		var refs []domain.SubjectRef
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if !consumeVerificationBytes(raw, budget) || json.Unmarshal(raw, &refs) != nil || !consumeDSSERecords(1+len(refs), records) {
			return app.ErrConflict
		}
		for _, ref := range refs {
			if ref.Type == "artifact" && artifacts[ref.ID] != "" {
				linked[ref.ID] = true
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, output := range matching {
		if linked[output.ArtifactID] {
			snapshot.ExpectedSubjectDigests = append(snapshot.ExpectedSubjectDigests, output.Digest)
		}
	}
	sort.Strings(snapshot.ExpectedSubjectDigests)
	return nil
}

package repositories

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func (r verification) ResolveArtifactSignatureVerificationSubject(ctx context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	s, err := r.lockArtifactSignatureSubject(ctx, tenant, id)
	return verificationapp.SubjectReference{TenantID: tenant, Type: "artifact_signature", ID: id, Resources: s.Resources}, err
}
func (r verification) ReadArtifactSignatureVerification(ctx context.Context, s verificationapp.SubjectReference) (verificationapp.ArtifactSignatureVerificationSnapshot, error) {
	snapshot := verificationapp.ArtifactSignatureVerificationSnapshot{Subject: s}
	if s.Type != "artifact_signature" {
		return snapshot, app.ErrValidation
	}
	var artifact string
	var large bool
	err := r.tx.QueryRow(ctx, `SELECT left(artifact_id,1025),left(subject_digest,1025),algorithm<>'',signature<>'',octet_length(artifact_id)>1024 OR octet_length(subject_digest)>1024
 FROM artifact_signatures WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, s.ID).Scan(&artifact, &snapshot.SignatureDigest, &snapshot.AlgorithmPresent, &snapshot.SignaturePresent, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read artifact signature metadata: %w", err)
	}
	if large || artifact != s.Resources.ArtifactID {
		return snapshot, app.ErrConflict
	}
	err = r.tx.QueryRow(ctx, `SELECT left(digest,1025),octet_length(digest)>1024 FROM artifacts WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, artifact).Scan(&snapshot.ArtifactDigest, &large)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot, app.ErrNotFound
	}
	if err != nil {
		return snapshot, fmt.Errorf("read signature artifact digest: %w", err)
	}
	if large {
		return snapshot, app.ErrConflict
	}
	return snapshot, nil
}

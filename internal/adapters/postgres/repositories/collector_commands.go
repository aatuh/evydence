package repositories

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

var _ integrationapp.CollectorWriteReader = builds{}

func (r builds) LockCollectorWrites(ctx context.Context, tenant string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return err
	}
	// Match worker and audit ordering; serialize names and pin updates even
	// before the first matching collector or release exists.
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return err
	}
	return requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant)
}

func (r builds) validCollectorKey(ctx context.Context, tenant string, parts ...string) error {
	if err := validBuildIdentityRead(ctx, r.tx, tenant, tenant); err != nil {
		return err
	}
	size := len(tenant)
	for _, v := range parts {
		if v == "" || !utf8.ValidString(v) || strings.ContainsRune(v, 0) || strings.TrimSpace(v) != v {
			return app.ErrValidation
		}
		size += len(v)
	}
	if size > integrationapp.MaxCollectorKeyBytes {
		return app.ErrValidation
	}
	return nil
}
func (r builds) CollectorNameExists(ctx context.Context, tenant, name string) (bool, error) {
	if err := r.validCollectorKey(ctx, tenant, name); err != nil {
		return false, err
	}
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collectors WHERE tenant_id=$1 AND name=$2)`, tenant, name).Scan(&exists)
	return exists, err
}
func (r builds) CommercialCollectorIdentityExists(ctx context.Context, tenant, provider, name, version string) (bool, error) {
	if err := r.validCollectorKey(ctx, tenant, provider, name, version); err != nil {
		return false, err
	}
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM commercial_collectors WHERE tenant_id=$1 AND provider=$2 AND name=$3 AND version=$4)`, tenant, provider, name, version).Scan(&exists)
	return exists, err
}

// Transfer only bounded identities/digests, never signature bytes, SBOM
// components, findings, or unrelated inventories. Lock current parents too.
func (r builds) ReadCollectorReleaseReference(ctx context.Context, tenant, kind, id string) (integrationapp.CollectorReference, error) {
	var empty integrationapp.CollectorReference
	if err := validBuildIdentityRead(ctx, r.tx, tenant, id); err != nil {
		return empty, err
	}
	if strings.TrimSpace(tenant) != tenant || strings.TrimSpace(id) != id {
		return empty, app.ErrValidation
	}
	switch kind {
	case "collector", "signature", "sbom", "scan":
	default:
		return empty, app.ErrValidation
	}
	if err := coordination.LockWorkerProjection(ctx, r.tx, tenant); err != nil {
		return empty, err
	}
	v := integrationapp.CollectorReference{ID: id, TenantID: tenant, Type: kind}
	var err error
	switch kind {
	case "collector":
		err = requireRow(ctx, r.tx, `SELECT 1 FROM collectors WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id)
	case "signature":
		var artifact string
		var large bool
		err = r.tx.QueryRow(ctx, `SELECT left(artifact_id,1025),left(subject_digest,72),octet_length(artifact_id)>1024 OR octet_length(subject_digest)>71 FROM artifact_signatures WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, id).Scan(&artifact, &v.Digest, &large)
		if err = buildIdentityReadError(err, large); err != nil {
			return empty, err
		}
		a, e := ReadBuildArtifact(ctx, r.tx, tenant, artifact, true)
		if e != nil {
			return empty, e
		}
		if a.Digest != v.Digest {
			return empty, app.ErrNotFound
		}
	case "sbom":
		_, err = evidence(r).ReadSBOMDiffSubject(ctx, tenant, id)
	case "scan":
		var refs application.ResourceReferences
		var large bool
		err = r.tx.QueryRow(ctx, `SELECT left(COALESCE(e.product_id,''),1025),left(COALESCE(e.project_id,''),1025),left(COALESCE(e.release_id,''),1025),left(COALESCE(e.build_id,''),1025),left(COALESCE(e.deployment_id,''),1025),
 EXISTS(SELECT 1 FROM unnest(ARRAY[e.product_id,e.project_id,e.release_id,e.build_id,e.deployment_id]) x(id) WHERE octet_length(x.id)>1024)
 FROM vulnerability_scans s JOIN evidence_items e ON e.id=s.evidence_id AND e.tenant_id=s.tenant_id AND e.type='vulnerability_scan'
 WHERE s.tenant_id=$1 AND s.id=$2 AND s.release_id IS NOT DISTINCT FROM e.release_id FOR SHARE OF s,e`, tenant, id).Scan(&refs.ProductID, &refs.ProjectID, &refs.ReleaseID, &refs.BuildID, &refs.DeploymentID, &large)
		if err = buildIdentityReadError(err, large); err != nil {
			return empty, err
		}
		_, err = evidence(r).ResolveEvidenceCreationScope(ctx, tenant, refs)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		err = app.ErrNotFound
	}
	if err != nil {
		return empty, err
	}
	return v, nil
}

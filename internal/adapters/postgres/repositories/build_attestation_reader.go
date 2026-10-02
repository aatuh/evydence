package repositories

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/adapters/postgres/coordination"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

var _ releaseapp.BuildAttestationSnapshotReader = builds{}

// ReadBuildAttestationBuild selects one full build, never tenant state or
// unrelated parent metadata. The CASE prevents oversized JSON/text reaching
// the application; no value is truncated into a plausible snapshot.
func ReadBuildAttestationBuild(ctx context.Context, q buildIdentityQueryer, tenant, id string, lock bool) (releasedomain.BuildRun, error) {
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	if id == "" && ctx != nil && ctx.Err() == nil {
		return releasedomain.BuildRun{}, app.ErrNotFound
	}
	if err := validBuildIdentityRead(ctx, q, tenant, id); err != nil {
		return releasedomain.BuildRun{}, err
	}
	sql := `SELECT CASE WHEN
 octet_length(b.id)<=1024 AND octet_length(b.tenant_id)<=1024 AND octet_length(b.project_id)<=1024 AND octet_length(b.release_id)<=1024 AND octet_length(p.id)<=1024
 AND COALESCE(octet_length(b.collector_id),0)<=1024 AND octet_length(b.provider)<=1024 AND octet_length(b.commit_sha)<=1024 AND octet_length(b.status)<=1024 AND octet_length(b.schema_version)<=1024
 AND COALESCE(octet_length(b.repository),0)<=65536 AND COALESCE(octet_length(b.workflow_ref),0)<=65536 AND COALESCE(octet_length(b.run_id),0)<=65536 AND COALESCE(octet_length(b.job_id),0)<=65536 AND COALESCE(octet_length(b.actor),0)<=65536
 AND COALESCE(octet_length(b.ref),0)<=65536 AND COALESCE(octet_length(b.oidc_subject),0)<=65536 AND COALESCE(octet_length(b.parameters_hash),0)<=65536 AND COALESCE(octet_length(b.environment_hash),0)<=65536
 AND COALESCE(octet_length(b.source_identity::text),0)<=1048576 AND octet_length(b.outputs::text)<=1048576
 AND (b.source_identity IS NULL OR jsonb_typeof(b.source_identity) IN('object','null')) AND jsonb_typeof(b.outputs)='array'
 THEN jsonb_build_object(
 'id',b.id,'tenant_id',b.tenant_id,'project_id',b.project_id,'release_id',b.release_id,'collector_id',b.collector_id,
 'provider',b.provider,'commit_sha',b.commit_sha,'repository',b.repository,'workflow_ref',b.workflow_ref,
 'run_id',b.run_id,'run_attempt',b.run_attempt,'job_id',b.job_id,'actor',b.actor,'ref',b.ref,'oidc_subject',b.oidc_subject,
 'status',b.status,'started_at',b.started_at,'finished_at',b.finished_at,'parameters_hash',b.parameters_hash,
 'environment_hash',b.environment_hash,'source_identity',b.source_identity,'outputs',b.outputs,
 'schema_version',b.schema_version,'created_at',b.created_at) ELSE NULL END
 FROM build_runs b
 JOIN projects j ON j.id=b.project_id AND j.tenant_id=b.tenant_id
 JOIN releases r ON r.id=b.release_id AND r.tenant_id=b.tenant_id AND r.product_id=j.product_id
 JOIN products p ON p.id=j.product_id AND p.tenant_id=b.tenant_id
 WHERE b.tenant_id=$1 AND b.id=$2`
	if lock {
		sql += ` FOR SHARE OF b,j,r,p`
	}
	var raw []byte
	err := q.QueryRow(ctx, sql, tenant, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasedomain.BuildRun{}, app.ErrNotFound
	}
	if err != nil {
		return releasedomain.BuildRun{}, fmt.Errorf("read build attestation snapshot: %w", err)
	}
	// JSON escaping can expand the nine 64 KiB text fields up to sixfold;
	// their fixed limits plus the two 1 MiB JSON fields still fit in 8 MiB.
	if len(raw) == 0 || len(raw) > 8<<20 {
		return releasedomain.BuildRun{}, app.ErrConflict
	}
	var b domain.BuildRun
	if err := json.Unmarshal(raw, &b); err != nil {
		return releasedomain.BuildRun{}, app.ErrConflict
	}
	outputs := make([]releasedomain.BuildOutput, 0, len(b.Outputs))
	for _, output := range b.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	if b.FinishedAt != nil {
		utc := b.FinishedAt.UTC()
		b.FinishedAt = &utc
	}
	return releasedomain.BuildRun{
		ID: b.ID, TenantID: b.TenantID, ProjectID: b.ProjectID, ReleaseID: b.ReleaseID, CollectorID: b.CollectorID,
		Provider: b.Provider, CommitSHA: b.CommitSHA, Repository: b.Repository, WorkflowRef: b.WorkflowRef,
		RunID: b.RunID, RunAttempt: b.RunAttempt, JobID: b.JobID, Actor: b.Actor, Ref: b.Ref, OIDCSubject: b.OIDCSubject,
		Status: b.Status, StartedAt: b.StartedAt.UTC(), FinishedAt: b.FinishedAt, ParametersHash: b.ParametersHash,
		EnvironmentHash: b.EnvironmentHash, SourceIdentity: b.SourceIdentity, Outputs: outputs,
		SchemaVersion: b.SchemaVersion, CreatedAt: b.CreatedAt.UTC(),
	}, nil
}

func (r builds) ReadBuildAttestationBuild(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	if err := validBuildIdentityRead(ctx, r.tx, strings.TrimSpace(tenant), strings.TrimSpace(id)); err != nil {
		return releasedomain.BuildRun{}, err
	}
	// Preserve the projection/audit lock order before acquiring relational locks.
	if err := coordination.LockWorkerProjection(ctx, r.tx, strings.TrimSpace(tenant)); err != nil {
		return releasedomain.BuildRun{}, err
	}
	return ReadBuildAttestationBuild(ctx, r.tx, tenant, id, true)
}

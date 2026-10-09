package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	app "github.com/aatuh/evydence/internal/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.BuildPointReader = (*Store)(nil)

const maxBuildPointJSONBytes = 1 << 20

// GetBuildPoint resolves the build and its project/release/product coordinates
// in one tenant-filtered statement, preventing mixed-time or cross-product
// authorization projections.
func (s *Store) GetBuildPoint(ctx context.Context, tenantID, id string) (releasequery.BuildPoint, error) {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(tenantID) == "" {
		return releasequery.BuildPoint{}, app.ErrValidation
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasequery.BuildPoint{}, releasequery.ErrNotFound
	}
	var point releasequery.BuildPoint
	var collectorID, repository, workflowRef, runID, jobID, actor, ref, oidcSubject sql.NullString
	var parametersHash, environmentHash sql.NullString
	var runAttempt sql.NullInt64
	var finishedAt sql.NullTime
	var sourceIdentity, outputs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT b.id, b.tenant_id, b.project_id, b.release_id, p.id,
		       b.collector_id, b.provider, b.commit_sha, b.repository,
		       b.workflow_ref, b.run_id, b.run_attempt, b.job_id, b.actor,
		       b.ref, b.oidc_subject, b.status, b.started_at, b.finished_at,
		       b.parameters_hash, b.environment_hash, b.source_identity,
		       b.outputs, b.schema_version, b.created_at
		FROM build_runs AS b
		JOIN projects AS j ON j.id = b.project_id AND j.tenant_id = b.tenant_id
		JOIN releases AS r ON r.id = b.release_id AND r.tenant_id = b.tenant_id
		    AND r.product_id = j.product_id
		JOIN products AS p ON p.id = j.product_id AND p.tenant_id = b.tenant_id
		WHERE b.tenant_id = $1 AND b.id = $2`, tenantID, id).Scan(
		&point.Build.ID, &point.Build.TenantID, &point.Build.ProjectID,
		&point.Build.ReleaseID, &point.ProductID, &collectorID,
		&point.Build.Provider, &point.Build.CommitSHA, &repository, &workflowRef,
		&runID, &runAttempt, &jobID, &actor, &ref, &oidcSubject,
		&point.Build.Status, &point.Build.StartedAt, &finishedAt,
		&parametersHash, &environmentHash, &sourceIdentity, &outputs,
		&point.Build.SchemaVersion, &point.Build.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return releasequery.BuildPoint{}, releasequery.ErrNotFound
	}
	if err != nil {
		return releasequery.BuildPoint{}, fmt.Errorf("get build point: %w", err)
	}
	if len(sourceIdentity) > maxBuildPointJSONBytes || len(outputs) > maxBuildPointJSONBytes {
		return releasequery.BuildPoint{}, errors.New("oversized stored build metadata")
	}
	point.Build.CollectorID = nullableSQLString(collectorID)
	point.Build.Repository = nullableSQLString(repository)
	point.Build.WorkflowRef = nullableSQLString(workflowRef)
	point.Build.RunID = nullableSQLString(runID)
	point.Build.RunAttempt = int(runAttempt.Int64)
	point.Build.JobID = nullableSQLString(jobID)
	point.Build.Actor = nullableSQLString(actor)
	point.Build.Ref = nullableSQLString(ref)
	point.Build.OIDCSubject = nullableSQLString(oidcSubject)
	point.Build.FinishedAt = nullableSQLTime(finishedAt)
	point.Build.ParametersHash = nullableSQLString(parametersHash)
	point.Build.EnvironmentHash = nullableSQLString(environmentHash)
	if len(sourceIdentity) > 0 {
		if err := json.Unmarshal(sourceIdentity, &point.Build.SourceIdentity); err != nil {
			return releasequery.BuildPoint{}, errors.New("invalid stored build source identity")
		}
	}
	var storedOutputs []struct {
		ArtifactID string `json:"artifact_id"`
		Digest     string `json:"digest"`
	}
	if err := json.Unmarshal(outputs, &storedOutputs); err != nil {
		return releasequery.BuildPoint{}, errors.New("invalid stored build outputs")
	}
	point.Build.Outputs = make([]releasedomain.BuildOutput, 0, len(storedOutputs))
	for _, output := range storedOutputs {
		point.Build.Outputs = append(point.Build.Outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return point, nil
}

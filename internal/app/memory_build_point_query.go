package app

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

var _ releasequery.BuildPointReader = memoryBuildRepository{}

// A focused test-backend point reads current coherent coordinates and selected
// metadata only. Its byte checks do not prove SQL transfer or allocation bounds.
func (r memoryBuildRepository) GetBuildPoint(ctx context.Context, tenant, id string) (releasequery.BuildPoint, error) {
	var out releasequery.BuildPoint
	err := memoryReleaseCatalogRepository(r).catalogQueryRead(ctx, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: id})
		if err != nil {
			return err
		}
		v, ok := s.BuildRuns[id]
		if !ok || v.ID != id || v.TenantID != tenant || refs.ProductID == "" || refs.ProjectID == "" || refs.ReleaseID == "" {
			return releasequery.ErrNotFound
		}
		build, err := memoryBuildPointMetadata(v)
		if err != nil {
			return err
		}
		out = releasequery.BuildPoint{Build: build, ProductID: refs.ProductID}
		return nil
	})
	if err != nil {
		return releasequery.BuildPoint{}, err
	}
	return out, nil
}

func memoryBuildPointMetadata(v domain.BuildRun) (releasedomain.BuildRun, error) {
	for _, text := range []string{v.CollectorID, v.Provider, v.CommitSHA, v.Repository, v.WorkflowRef, v.RunID, v.JobID, v.Actor, v.Ref, v.OIDCSubject, v.Status, v.ParametersHash, v.EnvironmentHash, v.SchemaVersion} {
		if !memoryMembershipText(text, 65536) {
			return releasedomain.BuildRun{}, releasequery.ErrInvalidProjection
		}
	}
	if v.CreatedAt.IsZero() || v.StartedAt.IsZero() {
		return releasedomain.BuildRun{}, releasequery.ErrInvalidProjection
	}
	identity, err := json.Marshal(v.SourceIdentity)
	if err != nil || len(identity) > 1<<20 {
		return releasedomain.BuildRun{}, releasequery.ErrInvalidProjection
	}
	outputs, err := json.Marshal(v.Outputs)
	if err != nil || len(outputs) > 1<<20 {
		return releasedomain.BuildRun{}, releasequery.ErrInvalidProjection
	}
	// Decode the selected generic JSON with exact numbers and no retained
	// caller-owned pointers, including nested maps and arrays.
	var detached map[string]any
	decoder := json.NewDecoder(bytes.NewReader(identity))
	decoder.UseNumber()
	if err := decoder.Decode(&detached); err != nil {
		return releasedomain.BuildRun{}, releasequery.ErrInvalidProjection
	}
	v.SourceIdentity = detached
	return buildRunToReleaseContext(v), nil
}

package app

import (
	"context"
	"encoding/json"

	"github.com/aatuh/evydence/internal/application"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func (r memoryBuildRepository) ReadBuildAttestationCreationScope(ctx context.Context, tenant, id string) (releaseapp.BuildAttestationCreationCoordinates, error) {
	var out releaseapp.BuildAttestationCreationCoordinates
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: id})
		if err != nil {
			return err
		}
		b := s.BuildRuns[id]
		if len(b.Outputs) > 4096 {
			return ErrConflict
		}
		ids := make([]string, 0, len(b.Outputs))
		for _, output := range b.Outputs {
			if output.ArtifactID == "" {
				continue
			}
			if !memoryMembershipQueryText(output.ArtifactID, 1024) {
				return ErrConflict
			}
			ids = append(ids, output.ArtifactID)
		}
		raw, err := json.Marshal(ids)
		if err != nil || len(raw) > 1<<20 {
			return ErrConflict
		}
		out = releaseapp.BuildAttestationCreationCoordinates{BuildCreationCoordinates: releaseapp.BuildCreationCoordinates{TenantID: tenant, ProjectID: refs.ProjectID, ProductID: refs.ProductID, ReleaseID: refs.ReleaseID, ReleaseProductID: refs.ProductID}, BuildID: id, ArtifactIDs: ids}
		return nil
	})
	if err != nil {
		return releaseapp.BuildAttestationCreationCoordinates{}, err
	}
	return out, nil
}
func (r memoryBuildRepository) ReadBuildAttestationBuild(ctx context.Context, tenant, id string) (releasedomain.BuildRun, error) {
	var out releasedomain.BuildRun
	err := memoryGovernanceRead(ctx, r.uow, tenant, id, func(s *MemoryUnitOfWorkSnapshot) error {
		if _, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{BuildID: id}); err != nil {
			return err
		}
		b := s.BuildRuns[id]
		for _, text := range []string{b.CollectorID, b.Provider, b.CommitSHA, b.Status, b.SchemaVersion} {
			if !memoryMembershipText(text, 1024) {
				return ErrConflict
			}
		}
		var err error
		out, err = memoryBuildPointMetadata(b)
		if err != nil {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return releasedomain.BuildRun{}, err
	}
	return out, nil
}

var (
	_ releaseapp.BuildAttestationCreationGuardReader = memoryBuildRepository{}
	_ releaseapp.BuildAttestationSnapshotReader      = memoryBuildRepository{}
)

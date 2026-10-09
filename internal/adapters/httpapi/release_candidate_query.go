package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

func releaseCandidateFromQuery(value releasedomain.ReleaseCandidate) domain.ReleaseCandidate {
	return domain.ReleaseCandidate{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID,
		Name: value.Name, Revision: value.Revision, State: value.State.String(),
		BuildIDs: value.BuildIDs, ArtifactIDs: value.ArtifactIDs, SBOMIDs: value.SBOMIDs,
		ScanIDs: value.ScanIDs, VEXIDs: value.VEXIDs, ContractIDs: value.ContractIDs,
		BundleIDs: value.BundleIDs, SnapshotHash: value.SnapshotHash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
		PromotedAt: value.PromotedAt, RejectedAt: value.RejectedAt,
	}
}

func mapReleaseCandidateQueryError(err error) error {
	switch {
	case errors.Is(err, releasequery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, releasequery.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, releasequery.ErrInvalidProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}

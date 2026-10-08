package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

// Current typed rows model the selected evidence/provenance snapshot. JSON
// budgets here are not PostgreSQL JSON shape, transfer, work or locking proof.
func readMemoryEvidencePoint(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, id string, guard evidencequery.EvidenceReadGuard) (evidencequery.EvidencePoint, error) {
	var empty evidencequery.EvidencePoint
	e, ok := s.Evidence[id]
	if !ok || e.ID != id || e.TenantID != tenant {
		return empty, evidencequery.ErrNotFound
	}
	refs, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	if errors.Is(err, ErrNotFound) {
		return empty, evidencequery.ErrNotFound
	}
	if err != nil {
		return empty, evidencequery.ErrConflict
	}
	if err := guard(refs); err != nil {
		return empty, err
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	remaining := verificationapp.MaxEvidenceVerificationBytes
	raw, err := memorySelectedEvidenceJSON(e, &remaining)
	if err != nil {
		return empty, err
	}
	if err := validateMemoryWorkerEvidence(ctx, s, e, &remaining); err != nil {
		return empty, err
	}
	// Decode schema-free JSON without rounding recorded numbers or sharing maps.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var detached domain.EvidenceItem
	if err := decoder.Decode(&detached); err != nil {
		return empty, evidencequery.ErrConflict
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return evidencequery.EvidencePoint{Item: domain.EvidenceToContextModel(detached), ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID, WorkerProjectionValidated: evidencedomain.RequiresWorkerProjection(detached.Type)}, nil
}

func memorySelectedEvidenceJSON(value any, remaining *int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > *remaining {
		return nil, evidencequery.ErrConflict
	}
	*remaining -= len(raw)
	return raw, nil
}

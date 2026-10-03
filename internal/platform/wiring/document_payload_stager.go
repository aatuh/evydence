package wiring

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

type evidenceDocumentStager struct {
	objects app.ObjectStore
	clock   application.Clock
}

func (s evidenceDocumentStager) StagePayloadSource(ctx context.Context, tenant, media string, source evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	if s.objects == nil {
		return evidenceapp.StagedPayload{}, nil
	}
	objects, ok := s.objects.(app.PayloadObjectStore)
	if !ok {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrConflict
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, media, app.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open}, s.clock.Now())
	if err != nil {
		return evidenceapp.StagedPayload{}, mapEvidenceCreationError(err)
	}
	return evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}

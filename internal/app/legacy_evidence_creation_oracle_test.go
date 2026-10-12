package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

// Historical aggregate creation characterization only. HTTP fixtures use the
// focused creator and current transaction repository scope instead.
func (l *Ledger) CreateEvidence(ctx context.Context, actor domain.Actor, in CreateEvidenceInput) (domain.EvidenceItem, error) {
	subjects := make([]evidencedomain.SubjectRef, 0, len(in.SubjectRefs))
	for _, subject := range in.SubjectRefs {
		subjects = append(subjects, evidencedomain.SubjectRef{Type: subject.Type, ID: subject.ID, Digest: subject.Digest})
	}
	value, err := l.legacyEvidenceCommands().CreateEvidence(ctx, actor, evidenceapp.CreateEvidenceInput{
		ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID,
		Type: in.Type, Subtype: in.Subtype, Title: in.Title, SourceSystem: in.SourceSystem, SourceIdentity: cloneMap(in.SourceIdentity),
		CollectorID: in.CollectorID, ObservedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash,
		PayloadMediaType: in.PayloadMediaType, PayloadSize: in.PayloadSize, StagedPayload: objectPayloadToEvidenceContext(in.StagedPayload),
		SubjectRefs: subjects, Metadata: cloneMap(in.Metadata), Tags: append([]string(nil), in.Tags...), Limitations: append([]string(nil), in.Limitations...),
	})
	return evidenceFromContext(value), fromEvidenceContextError(err)
}

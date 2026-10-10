package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical uploads retained only for characterization tests.

func (l *Ledger) UploadVulnerabilityScan(ctx context.Context, actor domain.Actor, raw []byte) (domain.VulnerabilityScan, error) {
	value, err := l.legacyEvidenceCommands().UploadVulnerabilityScan(ctx, actor, raw)
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

// UploadVulnerabilityScanPayload accepts a repeatable pre-hashed payload
// source for streaming HTTP ingestion.
func (l *Ledger) UploadVulnerabilityScanPayload(ctx context.Context, actor domain.Actor, source PayloadSource) (domain.VulnerabilityScan, error) {
	value, err := l.legacyEvidenceCommands().UploadVulnerabilityScanPayload(ctx, actor, payloadSourceToEvidenceContext(source))
	return vulnerabilityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

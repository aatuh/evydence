package app

import (
	"context"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
)

func validateMemoryNormalizationEvidence(ctx context.Context, s *MemoryUnitOfWorkSnapshot, item domain.EvidenceItem, remaining *int) error {
	sourceID, _ := item.Metadata["replay_of"].(string)
	if sourceID == "" || len(sourceID) > 1024 || item.ChainEntryID == "" || len(item.ChainEntryID) > 1024 {
		return evidencequery.ErrConflict
	}
	source, ok := s.Evidence[sourceID]
	if !ok || source.ID != sourceID || source.TenantID != item.TenantID || !replayableEvidenceType(source.Type) {
		return evidencequery.ErrConflict
	}
	if _, err := memoryOperationsCoordinates(s, item.TenantID, application.ResourceReferences{ProductID: source.ProductID, ProjectID: source.ProjectID, ReleaseID: source.ReleaseID, BuildID: source.BuildID, DeploymentID: source.DeploymentID}); err != nil {
		return evidencequery.ErrConflict
	}
	if _, err := memorySelectedEvidenceJSON(source, remaining); err != nil {
		return err
	}
	if err := validateMemoryWorkerEvidence(ctx, s, source, remaining); err != nil {
		return err
	}
	var entry domain.AuditChainEntry
	found := false
	for _, candidate := range s.AuditEntries[item.TenantID] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if candidate.ID == item.ChainEntryID && candidate.TenantID == item.TenantID {
			if found {
				return evidencequery.ErrConflict
			}
			entry, found = candidate, true
		}
	}
	if !found || entry.Sequence < 1 {
		return evidencequery.ErrConflict
	}
	if _, err := memorySelectedEvidenceJSON(entry, remaining); err != nil {
		return err
	}
	if err := ValidateParserNormalizationRecord(item.TenantID, item, source, entry); err != nil {
		return evidencequery.ErrConflict
	}
	if entry.Sequence == 1 {
		if entry.PreviousEntryHash != "" {
			return evidencequery.ErrConflict
		}
		return nil
	}
	var previous domain.AuditChainEntry
	found = false
	for _, candidate := range s.AuditEntries[item.TenantID] {
		if err := ctx.Err(); err != nil {
			return err
		}
		if candidate.Sequence == entry.Sequence-1 && candidate.TenantID == item.TenantID {
			if found {
				return evidencequery.ErrConflict
			}
			previous, found = candidate, true
		}
	}
	if !found || !VerifyAuditChainEntryHash(previous) || entry.PreviousEntryHash != previous.EntryHash {
		return evidencequery.ErrConflict
	}
	_, err := memorySelectedEvidenceJSON(previous, remaining)
	return err
}

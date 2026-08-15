package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func (s releaseEvidenceService) uploadValidatedSPDXSBOMPayload(ctx context.Context, actor domain.Actor, releaseID, artifactID string, source PayloadSource) (domain.SBOM, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.SBOM{}, err
	}
	releaseID, artifactID = strings.TrimSpace(releaseID), strings.TrimSpace(artifactID)
	l.mu.Lock()
	if err := l.ensureScopeLocked(actor.TenantID, "", "", releaseID); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	if artifactID != "" {
		artifact, ok := l.artifacts[artifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			l.mu.Unlock()
			return domain.SBOM{}, ErrNotFound
		}
	}
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: releaseID, ArtifactID: artifactID}); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	l.mu.Unlock()

	normalized, err := validateAndNormalizeSPDXSource(source)
	if err != nil {
		return domain.SBOM{}, err
	}
	staged, err := l.stagePayloadSource(ctx, actor.TenantID, "application/spdx+json", source)
	if err != nil {
		return domain.SBOM{}, err
	}
	payloadRef, payloadHash := staged.Reference(), source.Digest
	evidenceInput := CreateEvidenceInput{ReleaseID: releaseID, Type: "sbom", Subtype: "spdx", Title: "SPDX SBOM", SourceSystem: "api", ObservedAt: l.now(), PayloadRef: payloadRef, PayloadHash: payloadHash, PayloadMediaType: "application/spdx+json", PayloadSize: source.Size, SubjectRefs: subjectForArtifact(artifactID), Metadata: normalized.evidenceMetadata(), Limitations: normalized.limitations()}
	newSBOM := func(evidenceID string) domain.SBOM {
		return domain.SBOM{ID: newID("sbom"), TenantID: actor.TenantID, EvidenceID: evidenceID, ReleaseID: releaseID, ArtifactID: artifactID, Format: "spdx", SpecVersion: normalized.SpecVersion, ComponentCount: len(normalized.Components), Components: append([]domain.SBOMComponent(nil), normalized.Components...), CreatedAt: l.now()}
	}
	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := s.newEvidenceItemLocked(actor, evidenceInput)
		if err != nil {
			return domain.SBOM{}, err
		}
		sbom := newSBOM(item.ID)
		persisted, chainAction := parserOwnedSBOM(sbom, l.workerOwnedParsers)
		job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, addPayloadLifecycle(map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": normalized.ParserVersion}, staged))
		var evidenceEntry, sbomEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := l.persistStagedObjectPayload(ctx, repos, staged); err != nil {
				return err
			}
			var err error
			evidenceEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(item.CreatedAt, actor.TenantID, "evidence.created", "evidence_item", item.ID, "api_key", actor.KeyID, item.PayloadHash, ""))
			if err != nil {
				return err
			}
			item.ChainEntryID = evidenceEntry.ID
			if err := repos.Evidence.InsertEvidence(ctx, item); err != nil {
				return err
			}
			sbomEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(sbom.CreatedAt, actor.TenantID, chainAction, "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, ""))
			if err != nil {
				return err
			}
			if err := repos.Evidence.InsertSBOM(ctx, persisted); err != nil {
				return err
			}
			return repos.Outbox.Enqueue(ctx, job)
		}); err != nil {
			return domain.SBOM{}, err
		}
		l.evidence[item.ID], l.sboms[sbom.ID] = item, persisted
		l.publishCommittedAuditEntryLocked(evidenceEntry)
		l.publishCommittedAuditEntryLocked(sbomEntry)
		return sbom, nil
	}
	item, err := l.CreateEvidence(ctx, actor, evidenceInput)
	if err != nil {
		return domain.SBOM{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sbom := newSBOM(item.ID)
	persisted, chainAction := parserOwnedSBOM(sbom, l.workerOwnedParsers)
	l.sboms[sbom.ID] = persisted
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, "")
	job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, addPayloadLifecycle(map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash, "parser_version": normalized.ParserVersion}, staged))
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

package app

import (
	"context"
	"strings"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	"github.com/aatuh/evydence/internal/domain"
)

// uploadValidatedCycloneDXSBOMPayload is the conformant CycloneDX transaction
// path. The public Ledger facade switches to this method only after the pinned
// official schema resources are embedded and verified.
func (s releaseEvidenceService) uploadValidatedCycloneDXSBOMPayload(
	ctx context.Context,
	actor domain.Actor,
	releaseID, artifactID string,
	source PayloadSource,
	validator *cyclonedxparser.SchemaValidator,
) (domain.SBOM, error) {
	l := s.ledger
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	if err := require(actor, ScopeEvidenceWrite); err != nil {
		return domain.SBOM{}, err
	}

	releaseID = strings.TrimSpace(releaseID)
	artifactID = strings.TrimSpace(artifactID)
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
	if err := l.authorizeResourceLocked(actor, ScopeEvidenceWrite, resourceRefs{ReleaseID: releaseID}); err != nil {
		l.mu.Unlock()
		return domain.SBOM{}, err
	}
	l.mu.Unlock()

	// Authorize the target before opening or parsing attacker-controlled payload
	// bytes. The validator still binds normalization to the declared source
	// digest, and object staging independently verifies those bytes again.
	normalized, err := validateAndNormalizeCycloneDXSource(source, validator)
	if err != nil {
		return domain.SBOM{}, err
	}

	payloadHash := source.Digest
	stagedPayload, err := l.stagePayloadSource(ctx, actor.TenantID, "application/vnd.cyclonedx+json", source)
	if err != nil {
		return domain.SBOM{}, err
	}
	payloadRef := stagedPayload.Reference()
	evidenceInput := CreateEvidenceInput{
		ReleaseID:        releaseID,
		Type:             "sbom",
		Subtype:          "cyclonedx",
		Title:            "CycloneDX SBOM",
		SourceSystem:     "api",
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/vnd.cyclonedx+json",
		PayloadSize:      source.Size,
		SubjectRefs:      subjectForArtifact(artifactID),
		Metadata:         normalized.evidenceMetadata(),
		Limitations:      normalized.limitations(),
	}
	newSBOM := func(evidenceID string) domain.SBOM {
		return domain.SBOM{
			ID:             newID("sbom"),
			TenantID:       actor.TenantID,
			EvidenceID:     evidenceID,
			ReleaseID:      releaseID,
			ArtifactID:     artifactID,
			Format:         "cyclonedx",
			SpecVersion:    normalized.SpecVersion,
			ComponentCount: len(normalized.Components),
			Components:     append([]domain.SBOMComponent(nil), normalized.Components...),
			CreatedAt:      l.now(),
		}
	}

	if l.unitOfWork != nil {
		l.mu.Lock()
		defer l.mu.Unlock()
		item, err := s.newEvidenceItemLocked(actor, evidenceInput)
		if err != nil {
			return domain.SBOM{}, err
		}
		sbom := newSBOM(item.ID)
		persistedSBOM, chainAction := parserOwnedSBOM(sbom, l.workerOwnedParsers)
		job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, addPayloadLifecycle(map[string]any{
			"payload_ref":    payloadRef,
			"payload_hash":   payloadHash,
			"parser_version": normalized.ParserVersion,
		}, stagedPayload))
		var evidenceEntry, sbomEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := l.persistStagedObjectPayload(ctx, repos, stagedPayload); err != nil {
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
			if err := repos.Evidence.InsertSBOM(ctx, persistedSBOM); err != nil {
				return err
			}
			return repos.Outbox.Enqueue(ctx, job)
		}); err != nil {
			return domain.SBOM{}, err
		}
		l.evidence[item.ID] = item
		l.sboms[sbom.ID] = persistedSBOM
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
	persistedSBOM, chainAction := parserOwnedSBOM(sbom, l.workerOwnedParsers)
	l.sboms[sbom.ID] = persistedSBOM
	_, _ = l.appendChainLocked(actor.TenantID, chainAction, "sbom", sbom.ID, "api_key", actor.KeyID, payloadHash, "")
	job := l.newOutboxJob(actor.TenantID, "parse_sbom", "sbom", sbom.ID, addPayloadLifecycle(map[string]any{
		"payload_ref":    payloadRef,
		"payload_hash":   payloadHash,
		"parser_version": normalized.ParserVersion,
	}, stagedPayload))
	if err := l.persistReleaseLedgerWithOutboxLocked(ctx, job); err != nil {
		return domain.SBOM{}, err
	}
	return sbom, nil
}

func parserOwnedSBOM(sbom domain.SBOM, workerOwned bool) (domain.SBOM, string) {
	if !workerOwned {
		return sbom, "sbom.parsed"
	}
	persisted := sbom
	persisted.SpecVersion = ""
	persisted.ComponentCount = 0
	persisted.Components = nil
	return persisted, "sbom.accepted"
}

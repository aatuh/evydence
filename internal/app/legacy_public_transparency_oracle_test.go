package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

// Historical declarations retained unchanged for package-local regressions.
// Native HTTP fixtures use transaction repositories, not these caches.
// These oracles do not establish SQL durability or external public-log trust.

type CreatePublicTransparencyLogInput struct {
	Name      string
	Endpoint  string
	PublicKey string
}

type PublishPublicTransparencyLogEntryInput struct {
	LogID        string
	CheckpointID string
	ExternalID   string
}

type VerifyPublicTransparencyLogEntryInput struct {
	LeafHash       string
	RootHash       string
	LeafIndex      int
	TreeSize       int
	InclusionProof []string
	Source         string
}

func (l *Ledger) CreatePublicTransparencyLog(ctx context.Context, actor domain.Actor, in CreatePublicTransparencyLogInput) (domain.PublicTransparencyLog, error) {
	if err := ctx.Err(); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	if err := l.AuthorizeCreatePublicTransparencyLog(ctx, actor, in); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[actor.TenantID]; !ok {
		return domain.PublicTransparencyLog{}, ErrNotFound
	}
	projection, err := experimentalapp.BuildPublicTransparencyLog(newID("ptl"), actor.TenantID, publicTransparencyLogInput(in), l.now())
	if err != nil {
		return domain.PublicTransparencyLog{}, fromExperimentalCommandError(err)
	}
	record := PublicTransparencyLogLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertPublicTransparencyLog(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "public_transparency_log.created", "public_transparency_log", record.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLog{}, err
		}
		l.publicLogs[record.ID] = record
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	l.publicLogs[record.ID] = record
	_, _ = l.appendChainLocked(actor.TenantID, "public_transparency_log.created", "public_transparency_log", record.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLog{}, err
	}
	return record, nil
}

func (l *Ledger) PublishPublicTransparencyLogEntry(ctx context.Context, actor domain.Actor, in PublishPublicTransparencyLogEntryInput) (domain.PublicTransparencyLogEntry, error) {
	if err := ctx.Err(); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	if err := l.AuthorizePublishPublicTransparencyLogEntry(ctx, actor, in); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	normalized, err := experimentalapp.NormalizePublicTransparencyPublicationInput(publicTransparencyPublicationInput(in))
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	source, err := l.publicTransparencyPublicationSourceLocked(ctx, actor.TenantID, normalized)
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	projection, err := experimentalapp.BuildPublicTransparencyPublication(newID("pte"), actor.TenantID, normalized, source, l.now())
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	entry := PublicTransparencyPublicationLegacyRecord(projection)
	entryHash := entry.EntryHash
	if l.unitOfWork != nil {
		var auditEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertPublicTransparencyLogEntry(ctx, entry); err != nil {
				return err
			}
			var err error
			auditEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(entry.CreatedAt, actor.TenantID, "public_transparency_log_entry.published", "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entryHash, ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLogEntry{}, err
		}
		l.publicLogEntries[entry.ID] = entry
		l.publishCommittedAuditEntryLocked(auditEntry)
		return entry, nil
	}
	l.publicLogEntries[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, "public_transparency_log_entry.published", "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entryHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return entry, nil
}

func (l *Ledger) VerifyPublicTransparencyLogEntry(ctx context.Context, actor domain.Actor, id string, in VerifyPublicTransparencyLogEntryInput) (domain.PublicTransparencyLogEntry, error) {
	if err := l.AuthorizeVerifyPublicTransparencyLogEntry(ctx, actor, id, in); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	current, err := l.publicTransparencyVerificationSourceLocked(ctx, actor.TenantID, strings.TrimSpace(id))
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return l.verifyPublicTransparencyEntryLocked(ctx, actor, in, current)
}

func (l *Ledger) verifyPublicTransparencyEntryLocked(ctx context.Context, actor domain.Actor, in VerifyPublicTransparencyLogEntryInput, current experimentaldomain.PublicTransparencyLogEntry) (domain.PublicTransparencyLogEntry, error) {
	now := l.now()
	verified, err := experimentalapp.BuildPublicTransparencyVerification(current, publicTransparencyProofInput(in), strings.TrimSpace(in.Source), now)
	if err != nil {
		return domain.PublicTransparencyLogEntry{}, fromExperimentalCommandError(err)
	}
	entry := PublicTransparencyVerificationLegacyRecord(verified)
	eventType := "public_transparency_log_entry." + entry.State
	if l.unitOfWork != nil {
		var auditEntry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.UpdatePublicTransparencyLogEntry(ctx, entry, current.State); err != nil {
				return err
			}
			var err error
			auditEntry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(now, actor.TenantID, eventType, "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entry.InclusionProofHash, ""))
			return err
		}); err != nil {
			return domain.PublicTransparencyLogEntry{}, err
		}
		l.publicLogEntries[entry.ID] = entry
		l.publishCommittedAuditEntryLocked(auditEntry)
		return PublicTransparencyVerificationLegacyRecord(verified), nil
	}
	l.publicLogEntries[entry.ID] = entry
	_, _ = l.appendChainLocked(actor.TenantID, eventType, "public_transparency_log_entry", entry.ID, actorType(actor), actorID(actor), entry.InclusionProofHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PublicTransparencyLogEntry{}, err
	}
	return PublicTransparencyVerificationLegacyRecord(verified), nil
}

func verifyRFC6962StyleProof(leafHash, rootHash string, leafIndex, treeSize int, proof []string) bool {
	return experimentalapp.VerifyPublicTransparencyProof(leafHash, rootHash, leafIndex, treeSize, proof)
}

func transparencyParentHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func decodeSHA256Digest(value string) ([]byte, error) {
	if !validSHA256Digest(value) {
		return nil, ErrValidation
	}
	return hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

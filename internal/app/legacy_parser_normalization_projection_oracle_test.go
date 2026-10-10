package app

import (
	"reflect"

	"github.com/aatuh/evydence/internal/domain"
)

// mergeParserNormalizations publishes only the append-only evidence records
// produced by explicit parser replay. The source evidence and complete audit
// chain must already be present in the same authoritative worker snapshot.
func (l *Ledger) mergeParserNormalizations(tenantID string, incoming []domain.EvidenceItem, target map[string]domain.EvidenceItem, chain map[string][]domain.AuditChainEntry) error {
	seen := make(map[string]struct{}, len(incoming))
	auditByID := make(map[string]domain.AuditChainEntry, len(chain[tenantID]))
	for _, entry := range chain[tenantID] {
		auditByID[entry.ID] = entry
	}

	for _, item := range incoming {
		if err := validProjectionIdentity(tenantID, item.ID, item.TenantID, seen, "parser normalization"); err != nil {
			return err
		}
		if err := l.validateParserNormalizationProjection(tenantID, item, target, auditByID); err != nil {
			return err
		}
		if existing, ok := target[item.ID]; ok {
			if existing.Type != "parser_normalization" || !sameParserNormalizationEvidence(existing, item) {
				return projectionConflict("parser normalization divergence")
			}
			continue
		}
		target[item.ID] = cloneParserNormalizationEvidence(item)
	}

	if err := requireAuthoritativeProjectionRows(tenantID, "parser normalization", seen, target, func(value domain.EvidenceItem) string {
		if value.Type != "parser_normalization" {
			return ""
		}
		return value.TenantID
	}); err != nil {
		return err
	}
	for _, entry := range chain[tenantID] {
		if entry.EntryType != "parser.replayed" {
			continue
		}
		item, ok := target[entry.SubjectID]
		if !ok || item.Type != "parser_normalization" || item.TenantID != tenantID || item.ChainEntryID != entry.ID {
			return projectionConflict("parser normalization audit subject")
		}
	}
	return nil
}

func (l *Ledger) validateParserNormalizationProjection(tenantID string, item domain.EvidenceItem, target map[string]domain.EvidenceItem, auditByID map[string]domain.AuditChainEntry) error {
	sourceID := parserReplayOf(item.Metadata)
	source, sourceOK := target[sourceID]
	entry, entryOK := auditByID[item.ChainEntryID]
	if !sourceOK || !entryOK {
		return projectionConflict("parser normalization relationships")
	}
	return ValidateParserNormalizationRecord(tenantID, item, source, entry)
}

func sameParserNormalizationEvidence(left, right domain.EvidenceItem) bool {
	left = normalizedParserNormalizationEvidence(left)
	right = normalizedParserNormalizationEvidence(right)
	return reflect.DeepEqual(left, right)
}

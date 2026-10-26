package app

import (
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// ValidateParserNormalizationRecord verifies that a durable replay marker is
// the immutable projection of its tenant-owned source and linked audit fact.
// Storage adapters use it before treating an existing marker as idempotent.
func ValidateParserNormalizationRecord(tenantID string, item, source domain.EvidenceItem, entry domain.AuditChainEntry) error {
	if item.Type != "parser_normalization" || item.Subtype == "" || item.Title != "Parser normalization replay" || item.SourceSystem != "operator" || item.UploadedBy == "" || item.EvidenceVersion != 1 || item.SchemaVersion != domain.EvidenceItemSchemaVersion || item.Canonicalization != domain.CanonicalizationProfileVersion || item.VerificationStatus != "derived" || item.TrustLevel == "" || item.ObservedAt.IsZero() || item.CreatedAt.IsZero() || !sameParserProjectionTime(item.ObservedAt, item.CreatedAt) || item.ChainEntryID == "" || !validDigest(item.PayloadHash) || !validDigest(item.CanonicalHash) {
		return projectionConflict("parser normalization value")
	}
	if item.CollectorID != "" || item.Supersedes != "" || item.SupersededBy != "" || len(item.SourceIdentity) != 0 || len(item.SignatureRefs) != 0 || len(item.Tags) != 0 || len(item.Warnings) != 0 || len(item.RelatedEvidenceRefs) != 1 {
		return projectionConflict("parser normalization immutable shape")
	}
	if strings.TrimSpace(item.ID) != item.ID || strings.TrimSpace(item.Subtype) != item.Subtype || strings.TrimSpace(item.UploadedBy) != item.UploadedBy || strings.TrimSpace(item.ChainEntryID) != item.ChainEntryID {
		return projectionConflict("parser normalization value")
	}
	parser, ok := parserNormalizationProvenance(item.Metadata)
	if !ok || parser.Name != item.Subtype || parser.ReplayStatus != ParserReplayStatusReplayed {
		return projectionConflict("parser normalization provenance")
	}
	sourceID := parserReplayOf(item.Metadata)
	ref := item.RelatedEvidenceRefs[0]
	if sourceID == "" || sourceID == item.ID || ref.Type != "evidence_item" || ref.ID != sourceID || ref.Relationship != "replayed_from" {
		return projectionConflict("parser normalization source link")
	}
	if item.TenantID != tenantID || source.ID != sourceID || source.TenantID != tenantID || !replayableEvidenceType(source.Type) || item.PayloadRef != source.PayloadRef || item.PayloadHash != source.PayloadHash || item.PayloadMediaType != source.PayloadMediaType || item.PayloadSize != source.PayloadSize || item.TrustLevel != source.TrustLevel {
		return projectionConflict("parser normalization source relationship")
	}
	// Product/release/build/deployment columns on ordinary evidence are audited,
	// mutable relationship projections. Bind the replay to the source's
	// immutable subjects plus the replay-time scope recorded on the derived row,
	// so a later legitimate LinkEvidence operation cannot invalidate history.
	expectedSubjects := withEvidenceCanonicalOriginRefs(domain.EvidenceItem{
		ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
		BuildID: item.BuildID, DeploymentID: item.DeploymentID,
		SubjectRefs: append([]domain.SubjectRef(nil), source.SubjectRefs...),
	}).SubjectRefs
	if !reflect.DeepEqual(item.SubjectRefs, expectedSubjects) {
		return projectionConflict("parser normalization subject relationships")
	}
	canonical, err := canonicalHash(normalizedParserNormalizationEvidence(item))
	if err != nil || canonical != item.CanonicalHash {
		return projectionConflict("parser normalization canonical hash")
	}
	if entry.ID != item.ChainEntryID || entry.TenantID != tenantID || entry.EntryType != "parser.replayed" || entry.SubjectType != "evidence_item" || entry.SubjectID != item.ID || entry.ActorType != "operator" || entry.ActorID != item.UploadedBy || entry.PayloadHash != item.PayloadHash || !sameParserProjectionTime(entry.OccurredAt, item.CreatedAt) || entry.RequestID != "" || entry.IdempotencyKey != "" || entry.SignatureRef != "" || len(entry.Metadata) != 0 {
		return projectionConflict("parser normalization audit relationship")
	}
	verifiedEntry := entry
	if err := RehashAuditChainEntry(&verifiedEntry); err != nil || verifiedEntry.CanonicalEntryHash != entry.CanonicalEntryHash || verifiedEntry.EntryHash != entry.EntryHash {
		return projectionConflict("parser normalization audit integrity")
	}
	return nil
}

func parserNormalizationProvenance(metadata map[string]any) (ParserProvenance, bool) {
	value, ok := metadata["parser"].(map[string]any)
	if !ok {
		return ParserProvenance{}, false
	}
	parser := ParserProvenance{}
	parser.Name, _ = value["name"].(string)
	parser.Version, _ = value["version"].(string)
	parser.SourceSchema, _ = value["source_schema"].(string)
	parser.NormalizedSchema, _ = value["normalized_schema"].(string)
	parser.ReplayStatus, _ = value["replay_status"].(string)
	return parser, parser.Valid() && parserReplayVersion(metadata) == parser.Version
}

func replayableEvidenceType(value string) bool {
	switch value {
	case "sbom", "vulnerability_scan", "vex", "openapi_contract":
		return true
	default:
		return false
	}
}

func normalizedParserNormalizationEvidence(value domain.EvidenceItem) domain.EvidenceItem {
	value = cloneParserNormalizationEvidence(value)
	value.ObservedAt = value.ObservedAt.UTC().Truncate(time.Microsecond)
	value.CreatedAt = value.CreatedAt.UTC().Truncate(time.Microsecond)
	if len(value.SourceIdentity) == 0 {
		value.SourceIdentity = nil
	}
	if len(value.SubjectRefs) == 0 {
		value.SubjectRefs = nil
	}
	if len(value.SignatureRefs) == 0 {
		value.SignatureRefs = nil
	}
	if len(value.Tags) == 0 {
		value.Tags = nil
	}
	if len(value.Warnings) == 0 {
		value.Warnings = nil
	}
	return value
}

func cloneParserNormalizationEvidence(value domain.EvidenceItem) domain.EvidenceItem {
	return evidenceFromContext(evidenceToContext(value))
}

func sameParserProjectionTime(left, right time.Time) bool {
	return left.UTC().Truncate(time.Microsecond).Equal(right.UTC().Truncate(time.Microsecond))
}

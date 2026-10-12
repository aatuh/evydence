package app

import (
	"encoding/json"
	"maps"
	"net/mail"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// An authorized VEX upload publishes its author as evidence metadata. Preserve
// only a plain mailbox in this closed, versioned DTO on replay. Free-form author
// text, unknown fields, logs, and customer packages retain generic redaction.
func publicVEXAuthorReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	for field := range root {
		switch field {
		case "id", "tenant_id", "evidence_id", "release_id", "artifact_id", "format", "author", "version", "statement_count", "status_summary", "schema_version", "created_at":
		default:
			return nil, false
		}
	}
	encoded, err := json.Marshal(root)
	if err != nil || len(encoded) > 2<<20 {
		return nil, false
	}
	var v domain.VEXDocument
	if json.Unmarshal(encoded, &v) != nil || v.SchemaVersion != domain.VEXDocumentSchemaVersion || v.CreatedAt.IsZero() || (v.Format != "openvex" && v.Format != "cyclonedx") || v.StatementCount <= 0 || v.StatementCount > evidenceapp.VEXIngestionStatementLimit {
		return nil, false
	}
	for _, id := range []string{v.ID, v.TenantID, v.EvidenceID} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	for _, id := range []string{v.ReleaseID, v.ArtifactID} {
		if !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if !validPublicMembershipText(v.Version, evidenceapp.VEXIngestionStringByteLimit) || len(v.Author) > 254 || strings.TrimSpace(v.Author) != v.Author || redaction.RedactString(v.Author) != redaction.Redacted {
		return nil, false
	}
	address, err := mail.ParseAddress(v.Author)
	if err != nil || address.Name != "" || address.Address != v.Author {
		return nil, false
	}
	remaining := v.StatementCount
	for status, count := range v.StatusSummary {
		switch status {
		case "affected", "not_affected", "fixed", "under_investigation":
		default:
			return nil, false
		}
		if count < 0 || count > remaining {
			return nil, false
		}
		remaining -= count
	}
	safe, _ := redaction.RemoveSensitive(root)
	result := maps.Clone(safe.(map[string]any))
	result["author"] = v.Author
	return result, true
}

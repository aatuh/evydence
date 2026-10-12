package app

import (
	"context"
	"errors"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

func TestEvidenceVEXParserIndependentlyRejectsDigestMismatch(t *testing.T) {
	raw := []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"security@example.test","timestamp":"2026-08-22T11:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:generic/api@1"}],"status":"fixed"}]}`)
	source := evidenceapp.BytesPayloadSource(raw)
	source.Digest = sampleDigest("different-payload")

	_, err := (ledgerEvidencePayloadParser{}).ParseVEX(context.Background(), "openvex", source)
	if !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatalf("ParseVEX error = %v, want validation", err)
	}
}

func TestEvidenceVEXParserRetainsCycloneDXInvalidStatementIndexes(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"id":"CVE-2026-0001","analysis":{"state":"resolved"}},{"analysis":{"state":"resolved"}},{"id":"CVE-2026-0003","analysis":{"state":"unknown"}}]}`)

	parsed, err := (ledgerEvidencePayloadParser{}).ParseVEX(context.Background(), "cyclonedx", evidenceapp.BytesPayloadSource(raw))
	if err != nil {
		t.Fatalf("ParseVEX: %v", err)
	}
	if parsed.Format != "cyclonedx" || parsed.ParserVersion != ParserVersionCycloneDXVEXJSON || parsed.StatementCount != 3 || parsed.ValidStatementCount != 1 || parsed.StatusSummary["fixed"] != 1 {
		t.Fatalf("parsed VEX = %#v", parsed)
	}
	if len(parsed.InvalidStatements) != 2 || parsed.InvalidStatements[0].StatementIndex != 2 || parsed.InvalidStatements[0].Code != "missing_vulnerability" || parsed.InvalidStatements[1].StatementIndex != 3 || parsed.InvalidStatements[1].Code != "unsupported_analysis_state" {
		t.Fatalf("invalid statements = %#v", parsed.InvalidStatements)
	}
}

func TestEvidenceVEXParserRejectsAllInvalidCycloneDXBeforeStaging(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{"analysis":{"state":"resolved"}},{"id":"CVE-2026-0002","analysis":{"state":"unknown"}}]}`)

	_, err := (ledgerEvidencePayloadParser{}).ParseVEX(context.Background(), "cyclonedx", evidenceapp.BytesPayloadSource(raw))
	if !errors.Is(err, evidenceapp.ErrValidation) {
		t.Fatalf("ParseVEX error = %v, want validation", err)
	}
}

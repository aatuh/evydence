package query

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxVEXPreviewFindings = 4096
const MaxVEXPreviewScans = 4096
const MaxVEXPreviewTextBytes = 8 << 20

type VEXPreviewInput struct {
	ReleaseID, ArtifactID, Format string
	Payload                       []byte
}
type VEXPreviewFinding struct {
	ID, ScanID, TenantID, ReleaseID, Vulnerability, Component string
	HasActiveDecision                                         bool
}
type VEXPreviewSnapshot struct {
	TenantID, ProductID, ReleaseID, ArtifactID string
	Findings                                   []VEXPreviewFinding
}

// Preparation runs within the reader's snapshot, before candidate selection.
// Artifact authorization must read associations in that same snapshot.
type VEXPreviewPreparation func(application.ResourceReferences, application.Authorizer) ([]string, error)
type VEXPreviewReader interface {
	ReadVEXPreviewSnapshot(context.Context, string, string, string, VEXPreviewPreparation) (VEXPreviewSnapshot, error)
}
type VEXPreviewEffects struct {
	WouldCreate, WouldSupersede int
	Warnings                    []string
	Failures                    []evidencedomain.VEXImportIssue
}
type VEXPreviewMapper func(string, evidenceapp.ParsedVEX, VEXPreviewSnapshot) (VEXPreviewEffects, error)
type VEXPreviews struct {
	reader VEXPreviewReader
	parser evidenceapp.VEXIngestionParser
	mapper VEXPreviewMapper
	now    func() time.Time
}

func NewVEXPreviews(reader VEXPreviewReader, parser evidenceapp.VEXIngestionParser, mapper VEXPreviewMapper, now func() time.Time) (*VEXPreviews, error) {
	if reader == nil || parser == nil || mapper == nil || now == nil {
		return nil, ErrValidation
	}
	return &VEXPreviews{reader, parser, mapper, now}, nil
}

func (s *VEXPreviews) PreviewVEXImport(ctx context.Context, a identitydomain.Actor, in VEXPreviewInput) (evidencedomain.VEXImportPreview, error) {
	if s == nil || ctx == nil {
		return evidencedomain.VEXImportPreview{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	if err := authorizeEvidenceRead(a, EvidencePoint{}, true); err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	if !validEvidenceReadID(a.TenantID) || !validEvidenceReadID(in.ReleaseID) || in.ArtifactID != "" && !validEvidenceReadID(in.ArtifactID) || len(in.Payload) == 0 || int64(len(in.Payload)) > evidenceapp.EvidenceDocumentLimit {
		return evidencedomain.VEXImportPreview{}, ErrValidation
	}
	in.ReleaseID, in.ArtifactID, in.Format = strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.ArtifactID), strings.ToLower(strings.TrimSpace(in.Format))
	if in.ReleaseID == "" || (in.Format != "openvex" && in.Format != "cyclonedx") {
		return evidencedomain.VEXImportPreview{}, ErrValidation
	}
	var parsed evidenceapp.ParsedVEX
	var prepared application.ResourceReferences
	called := false
	snapshot, err := s.reader.ReadVEXPreviewSnapshot(ctx, a.TenantID, in.ReleaseID, in.ArtifactID, func(refs application.ResourceReferences, artifacts application.Authorizer) ([]string, error) {
		if called || refs.ReleaseID != in.ReleaseID || !validEvidenceReadID(refs.ProductID) || refs != (application.ResourceReferences{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}) {
			return nil, ErrConflict
		}
		called, prepared = true, refs
		if err := authorizeEvidenceRead(a, EvidencePoint{ProductID: refs.ProductID, ReleaseID: refs.ReleaseID}, false); err != nil {
			return nil, err
		}
		if in.ArtifactID != "" {
			if artifacts == nil {
				return nil, ErrConflict
			}
			if err := artifacts.Authorize(ctx, a, application.AuthorizationRequest{Scope: scopeEvidenceRead, Resources: application.ResourceReferences{ArtifactID: in.ArtifactID}}); err != nil {
				return nil, err
			}
		}
		var err error
		parsed, err = s.parser.ParseVEX(ctx, in.Format, evidenceapp.BytesPayloadSource(in.Payload))
		if errors.Is(err, evidenceapp.ErrValidation) {
			return nil, ErrValidation
		}
		if err != nil {
			return nil, err
		}
		if !evidenceapp.ValidVEXIngestionProjection(parsed, in.Format) {
			return nil, ErrValidation
		}
		ids, seen := []string{}, map[string]bool{}
		for _, statement := range parsed.Statements {
			if !seen[statement.Vulnerability] {
				seen[statement.Vulnerability] = true
				ids = append(ids, statement.Vulnerability)
			}
		}
		return ids, nil
	})
	if err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	if !called || snapshot.TenantID != a.TenantID || snapshot.ProductID != prepared.ProductID || snapshot.ReleaseID != in.ReleaseID || snapshot.ArtifactID != in.ArtifactID || len(snapshot.Findings) > MaxVEXPreviewFindings {
		return evidencedomain.VEXImportPreview{}, ErrConflict
	}
	budget, seen := MaxVEXPreviewTextBytes, map[string]bool{}
	for _, f := range snapshot.Findings {
		if f.TenantID != a.TenantID || f.ReleaseID != in.ReleaseID || seen[f.ID] || !validEvidenceReadID(f.ID) || !validEvidenceReadID(f.ScanID) {
			return evidencedomain.VEXImportPreview{}, ErrConflict
		}
		seen[f.ID] = true
		for i, text := range []string{f.ID, f.ScanID, f.TenantID, f.ReleaseID, f.Vulnerability, f.Component} {
			if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(text) > evidenceapp.VEXIngestionStringByteLimit || len(text) > budget || i == 4 && strings.TrimSpace(text) == "" {
				return evidencedomain.VEXImportPreview{}, ErrConflict
			}
			budget -= len(text)
		}
	}
	if err := ctx.Err(); err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	effects, err := s.mapper(in.Format, parsed, snapshot)
	if err != nil {
		return evidencedomain.VEXImportPreview{}, err
	}
	if effects.WouldCreate < 0 || effects.WouldCreate > len(snapshot.Findings) || effects.WouldSupersede < 0 || effects.WouldSupersede > effects.WouldCreate {
		return evidencedomain.VEXImportPreview{}, ErrConflict
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
		return evidencedomain.VEXImportPreview{}, ErrConflict
	}
	summary := map[string]int{}
	for status, count := range parsed.StatusSummary {
		summary[status] = count
	}
	return evidencedomain.VEXImportPreview{TenantID: a.TenantID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Format: in.Format, ParserVersion: parsed.ParserVersion, Advisory: true, StatementCount: parsed.StatementCount, StatusSummary: summary, DecisionsWouldCreate: effects.WouldCreate, DecisionsWouldSupersede: effects.WouldSupersede, Warnings: append(append([]string{}, parsed.Warnings...), effects.Warnings...), InvalidStatements: append([]evidencedomain.VEXImportIssue(nil), parsed.InvalidStatements...), MappingFailures: append([]evidencedomain.VEXImportIssue{}, effects.Failures...), Assumptions: evidencedomain.VEXPreviewAssumptions(), Limitations: evidencedomain.VEXPreviewLimitations(), SchemaVersion: evidencedomain.VEXImportPreviewSchemaVersion, GeneratedAt: now}, nil
}

package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	scannerparser "github.com/aatuh/evydence/internal/app/parsers/scanners"
	spdxparser "github.com/aatuh/evydence/internal/app/parsers/spdx"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
)

type ParserReplayRequest struct {
	TenantID, EvidenceID, ParserVersion, ActorID string
	Now                                          time.Time
}
type ParserReplayResult struct {
	EvidenceID string
	Created    bool
	Parser     ParserProvenance
	Summary    map[string]any
}

// ParserReplayPayloadKey verifies the requested tenant scope and returns the
// provider key for the immutable source payload. It never exposes the key to
// operator command output.
func ParserReplayPayloadKey(state *PersistedState, request ParserReplayRequest) (string, error) {
	if state == nil || strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.EvidenceID) == "" {
		return "", ErrValidation
	}
	original, ok := state.Evidence[request.EvidenceID]
	if !ok || original.TenantID != request.TenantID {
		return "", ErrNotFound
	}
	key := strings.TrimPrefix(original.PayloadRef, "object://")
	if key == original.PayloadRef || !strings.HasPrefix(key, "tenants/"+request.TenantID+"/") {
		return "", ErrValidation
	}
	return key, nil
}

// ReplayStoredParserEvidence verifies immutable payload identity before
// appending a replay projection. It intentionally accepts an already-read
// object so storage adapters remain outside the application boundary.
func ReplayStoredParserEvidence(state *PersistedState, object Object, request ParserReplayRequest) (ParserReplayResult, error) {
	key, err := ParserReplayPayloadKey(state, request)
	if err != nil {
		return ParserReplayResult{}, err
	}
	original := state.Evidence[request.EvidenceID]
	if object.Key != key || object.TenantID != request.TenantID || object.Digest != original.PayloadHash || hashBytes(object.Bytes) != original.PayloadHash {
		return ParserReplayResult{}, ErrValidation
	}
	return ReplayParserEvidence(state, object.Bytes, request)
}

// ReplayParserEvidence appends a derived normalization record. It never edits
// the source evidence or payload, and repeating the same replay returns the
// original derived record.
func ReplayParserEvidence(state *PersistedState, raw []byte, request ParserReplayRequest) (ParserReplayResult, error) {
	if state == nil || strings.TrimSpace(request.TenantID) == "" || strings.TrimSpace(request.EvidenceID) == "" || strings.TrimSpace(request.ParserVersion) == "" || strings.TrimSpace(request.ActorID) == "" || request.Now.IsZero() {
		return ParserReplayResult{}, ErrValidation
	}
	original, ok := state.Evidence[request.EvidenceID]
	if !ok || original.TenantID != request.TenantID {
		return ParserReplayResult{}, ErrNotFound
	}
	provenance, summary, err := replayParserProjection(original, raw, request.ParserVersion)
	if err != nil {
		return ParserReplayResult{}, err
	}
	for _, item := range state.Evidence {
		if item.TenantID == request.TenantID && item.Type == "parser_normalization" && parserReplayOf(item.Metadata) == original.ID && parserReplayVersion(item.Metadata) == provenance.Version {
			return ParserReplayResult{EvidenceID: item.ID, Parser: provenance, Summary: summary}, nil
		}
	}
	if state.Evidence == nil {
		state.Evidence = map[string]domain.EvidenceItem{}
	}
	derived := domain.EvidenceItem{ID: newID("ev"), TenantID: original.TenantID, ProductID: original.ProductID, ProjectID: original.ProjectID, ReleaseID: original.ReleaseID, Type: "parser_normalization", Subtype: provenance.Name, Title: "Parser normalization replay", SourceSystem: "operator", UploadedBy: request.ActorID, ObservedAt: request.Now.UTC(), EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion, PayloadRef: original.PayloadRef, PayloadHash: original.PayloadHash, PayloadMediaType: original.PayloadMediaType, PayloadSize: original.PayloadSize, Canonicalization: domain.CanonicalizationProfileVersion, TrustLevel: original.TrustLevel, VerificationStatus: "derived", RelatedEvidenceRefs: []domain.EvidenceRef{{Type: "evidence_item", ID: original.ID, Relationship: "replayed_from"}}, Metadata: map[string]any{"parser": provenance.Metadata(), "replay_of": original.ID, "normalized_summary": summary}, Limitations: []string{"Derived normalization records do not replace or mutate the immutable source evidence."}, CreatedAt: request.Now.UTC()}
	var hashErr error
	derived.CanonicalHash, hashErr = canonicalHash(derived)
	if hashErr != nil {
		return ParserReplayResult{}, hashErr
	}
	entry, err := AppendPersistedChainEntry(state, request.Now, request.TenantID, "parser.replayed", "evidence_item", derived.ID, "operator", request.ActorID, derived.PayloadHash, "")
	if err != nil {
		return ParserReplayResult{}, err
	}
	derived.ChainEntryID = entry.ID
	state.Evidence[derived.ID] = derived
	return ParserReplayResult{EvidenceID: derived.ID, Created: true, Parser: provenance, Summary: summary}, nil
}

func parserReplayOf(metadata map[string]any) string {
	value, _ := metadata["replay_of"].(string)
	return value
}
func parserReplayVersion(metadata map[string]any) string {
	parser, _ := metadata["parser"].(map[string]any)
	value, _ := parser["version"].(string)
	return value
}

func replayParserProjection(item domain.EvidenceItem, raw []byte, requestedVersion string) (ParserProvenance, map[string]any, error) {
	if len(raw) == 0 {
		return ParserProvenance{}, nil, ErrValidation
	}
	switch item.Type {
	case "sbom":
		if item.Subtype == "spdx" {
			if requestedVersion != ParserVersionSPDXJSON {
				return ParserProvenance{}, nil, ErrValidation
			}
			parsed, err := spdxparser.ParseBounded(raw, spdxparser.DefaultLimits(EvidenceDocumentLimit))
			if err != nil {
				return ParserProvenance{}, nil, ErrValidation
			}
			return ParserProvenance{Name: "spdx", Version: requestedVersion, SourceSchema: strings.ToLower(parsed.SpecVersion), NormalizedSchema: "evydence-sbom.v1", Warnings: parsed.Warnings, ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"component_count": len(parsed.Packages), "spec_version": parsed.SpecVersion}, nil
		}
		if requestedVersion != ParserVersionCycloneDXJSON {
			return ParserProvenance{}, nil, ErrValidation
		}
		parsed, err := cyclonedxparser.ParseBounded(raw, cyclonedxparser.DefaultLimits(EvidenceDocumentLimit))
		if err != nil {
			return ParserProvenance{}, nil, ErrValidation
		}
		return ParserProvenance{Name: "cyclonedx", Version: requestedVersion, SourceSchema: "cyclonedx-" + parsed.SpecVersion, NormalizedSchema: "evydence-sbom.v1", Warnings: parsed.Warnings, ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"component_count": len(parsed.Components), "spec_version": parsed.SpecVersion}, nil
	case "vulnerability_scan":
		if requestedVersion != ParserVersionScannerAdaptersJSON && requestedVersion != ParserVersionGenericVulnerabilityJSON {
			return ParserProvenance{}, nil, ErrValidation
		}
		parsed, err := scannerparser.ParseBounded(raw, scannerparser.DefaultLimits(EvidenceDocumentLimit))
		if err != nil {
			return ParserProvenance{}, nil, ErrValidation
		}
		return ParserProvenance{Name: parsed.Adapter, Version: requestedVersion, SourceSchema: parsed.SourceSchema, NormalizedSchema: "evydence-vulnerability-finding.v1", ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"finding_count": len(parsed.Findings)}, nil
	case "vex":
		if item.Subtype == "cyclonedx" {
			if requestedVersion != ParserVersionCycloneDXVEXJSON {
				return ParserProvenance{}, nil, ErrValidation
			}
			parsed, err := vexparser.ParseCycloneDX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
			if err != nil {
				return ParserProvenance{}, nil, ErrValidation
			}
			return ParserProvenance{Name: "cyclonedx-vex", Version: requestedVersion, SourceSchema: "cyclonedx-vex-" + parsed.Version, NormalizedSchema: "evydence-vex.v1", Warnings: parsed.Warnings, ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"statement_count": len(parsed.Statements)}, nil
		}
		if requestedVersion != ParserVersionOpenVEXJSON {
			return ParserProvenance{}, nil, ErrValidation
		}
		parsed, err := vexparser.ParseOpenVEX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
		if err != nil {
			return ParserProvenance{}, nil, ErrValidation
		}
		return ParserProvenance{Name: "openvex", Version: requestedVersion, SourceSchema: "openvex-" + parsed.Version, NormalizedSchema: "evydence-vex.v1", Warnings: parsed.Warnings, ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"statement_count": len(parsed.Statements)}, nil
	case "openapi_contract":
		if requestedVersion != ParserVersionOpenAPIJSON {
			return ParserProvenance{}, nil, ErrValidation
		}
		doc, err := openapi3.NewLoader().LoadFromData(raw)
		if err != nil || doc.Validate(context.Background()) != nil {
			return ParserProvenance{}, nil, ErrValidation
		}
		return ParserProvenance{Name: "openapi", Version: requestedVersion, SourceSchema: "openapi-" + doc.OpenAPI, NormalizedSchema: "evydence-openapi-contract.v1", ReplayStatus: ParserReplayStatusReplayed}, map[string]any{"path_count": len(doc.Paths.Map())}, nil
	default:
		return ParserProvenance{}, nil, fmt.Errorf("%w: evidence type is not replayable", ErrValidation)
	}
}

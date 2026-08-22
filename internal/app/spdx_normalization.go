package app

import (
	"errors"
	"io"
	"strings"

	spdxparser "github.com/aatuh/evydence/internal/app/parsers/spdx"
	"github.com/aatuh/evydence/internal/domain"
)

type spdxNormalization struct {
	SpecVersion                                                            string
	Components                                                             []domain.SBOMComponent
	RelationshipCount, ChecksumCount, LicenseCount, ExternalReferenceCount int
	ParserVersion                                                          string
	Warnings, UnsupportedPaths                                             []string
}

func parseSPDXReader(reader io.Reader, maxBytes int64) (spdxNormalization, error) {
	parsed, err := spdxparser.ParseBoundedReader(reader, spdxparser.DefaultLimits(maxBytes))
	if err != nil {
		if errors.Is(err, spdxparser.ErrInvalid) {
			return spdxNormalization{}, ErrValidation
		}
		return spdxNormalization{}, err
	}
	return normalizeSPDXResult(parsed), nil
}

func normalizeSPDXResult(parsed spdxparser.Result) spdxNormalization {
	components := make([]domain.SBOMComponent, 0, len(parsed.Packages))
	for _, pkg := range parsed.Packages {
		components = append(components, domain.SBOMComponent{Identity: strings.TrimSpace(pkg.Identity), Name: strings.TrimSpace(pkg.Name), Version: strings.TrimSpace(pkg.Version), PURL: strings.TrimSpace(pkg.PURL)})
	}
	return spdxNormalization{
		SpecVersion: parsed.SpecVersion, Components: components, RelationshipCount: len(parsed.Relationships), ChecksumCount: parsed.ChecksumCount,
		LicenseCount: parsed.LicenseCount, ExternalReferenceCount: parsed.ExternalReferenceCount, ParserVersion: spdxparser.ParserVersion,
		Warnings: append([]string(nil), parsed.Warnings...), UnsupportedPaths: append([]string(nil), parsed.UnsupportedPaths...),
	}
}

func (n spdxNormalization) evidenceMetadata() map[string]any {
	warnings, unsupported := append([]string(nil), n.Warnings...), append([]string(nil), n.UnsupportedPaths...)
	return WithParserProvenance(map[string]any{
		"sbom_format": "spdx", "sbom_spec_version": n.SpecVersion, "component_count": len(n.Components), "relationship_count": n.RelationshipCount,
		"checksum_count": n.ChecksumCount, "license_count": n.LicenseCount, "external_reference_count": n.ExternalReferenceCount,
		"parser_version": n.ParserVersion, "normalization_warnings": warnings, "unsupported_normalization": unsupported,
		"import_report": map[string]any{"parser_version": n.ParserVersion, "warnings": append([]string(nil), warnings...), "unsupported_constructs": append([]string(nil), unsupported...)},
	}, ParserProvenance{Name: "spdx", Version: n.ParserVersion, SourceSchema: strings.ToLower(n.SpecVersion), NormalizedSchema: "evydence-sbom.v1", Warnings: warnings, ReplayStatus: ParserReplayStatusOriginal})
}

func (n spdxNormalization) limitations() []string {
	if len(n.UnsupportedPaths) == 0 {
		return []string{"SPDX ingestion preserves package, relationship, checksum, license, and external-reference source data, but does not prove SBOM completeness."}
	}
	return []string{"SPDX fields outside the normalized Evydence subset remain preserved only in the immutable raw payload; review evidence metadata for exact parser warnings.", "SPDX ingestion does not prove SBOM completeness."}
}

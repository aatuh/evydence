package app

import (
	"errors"
	"io"
	"strings"

	cyclonedxparser "github.com/aatuh/evydence/internal/app/parsers/cyclonedx"
	"github.com/aatuh/evydence/internal/domain"
)

type cyclonedxNormalization struct {
	SpecVersion      string
	Components       []domain.SBOMComponent
	DependencyCount  int
	ParserVersion    string
	Warnings         []string
	UnsupportedPaths []string
}

func parseCycloneDXReader(reader io.Reader, maxBytes int64) (cyclonedxNormalization, error) {
	parsed, err := cyclonedxparser.ParseBoundedReader(reader, cyclonedxparser.DefaultLimits(maxBytes))
	if err != nil {
		if errors.Is(err, cyclonedxparser.ErrInvalid) {
			return cyclonedxNormalization{}, ErrValidation
		}
		return cyclonedxNormalization{}, err
	}
	return normalizeCycloneDXResult(parsed), nil
}

func normalizeCycloneDXResult(parsed cyclonedxparser.Result) cyclonedxNormalization {
	components := make([]domain.SBOMComponent, 0, len(parsed.Components))
	for _, component := range parsed.Components {
		purl := strings.TrimSpace(component.PURL)
		identity := strings.TrimSpace(component.Identity)
		if purl != "" {
			identity = "purl:" + purl
		}
		components = append(components, domain.SBOMComponent{
			Identity: identity,
			Name:     strings.TrimSpace(component.Name),
			Version:  strings.TrimSpace(component.Version),
			PURL:     purl,
		})
	}
	return cyclonedxNormalization{
		SpecVersion:      parsed.SpecVersion,
		Components:       components,
		DependencyCount:  len(parsed.Dependencies),
		ParserVersion:    cyclonedxparser.ParserVersion,
		Warnings:         append([]string(nil), parsed.Warnings...),
		UnsupportedPaths: append([]string(nil), parsed.UnsupportedPaths...),
	}
}

func (n cyclonedxNormalization) evidenceMetadata() map[string]any {
	warnings := append([]string(nil), n.Warnings...)
	unsupported := append([]string(nil), n.UnsupportedPaths...)
	return map[string]any{
		"sbom_format":               "cyclonedx",
		"sbom_spec_version":         n.SpecVersion,
		"component_count":           len(n.Components),
		"dependency_count":          n.DependencyCount,
		"parser_version":            n.ParserVersion,
		"normalization_warnings":    warnings,
		"unsupported_normalization": unsupported,
		"import_report": map[string]any{
			"parser_version":         n.ParserVersion,
			"warnings":               append([]string(nil), warnings...),
			"unsupported_constructs": append([]string(nil), unsupported...),
		},
	}
}

func (n cyclonedxNormalization) limitations() []string {
	if len(n.UnsupportedPaths) == 0 {
		return nil
	}
	return []string{
		"CycloneDX fields outside the normalized Evydence component/dependency subset remain preserved only in the immutable raw payload; review evidence metadata for the exact parser warnings.",
	}
}

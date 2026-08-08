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
	components := make([]domain.SBOMComponent, 0, len(parsed.Components))
	for _, component := range parsed.Components {
		components = append(components, domain.SBOMComponent{
			Name:    strings.TrimSpace(component.Name),
			Version: strings.TrimSpace(component.Version),
			PURL:    strings.TrimSpace(component.PURL),
		})
	}
	return cyclonedxNormalization{
		SpecVersion:      parsed.SpecVersion,
		Components:       components,
		DependencyCount:  len(parsed.Dependencies),
		ParserVersion:    cyclonedxparser.ParserVersion,
		Warnings:         append([]string(nil), parsed.Warnings...),
		UnsupportedPaths: append([]string(nil), parsed.UnsupportedPaths...),
	}, nil
}

func (n cyclonedxNormalization) evidenceMetadata() map[string]any {
	return map[string]any{
		"sbom_format":               "cyclonedx",
		"sbom_spec_version":         n.SpecVersion,
		"component_count":           len(n.Components),
		"dependency_count":          n.DependencyCount,
		"parser_version":            n.ParserVersion,
		"normalization_warnings":    append([]string(nil), n.Warnings...),
		"unsupported_normalization": append([]string(nil), n.UnsupportedPaths...),
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

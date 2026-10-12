package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type MarketplaceCollectorCommands interface {
	AuthorizeCreateMarketplaceCollector(context.Context, identitydomain.Actor, experimentalapp.MarketplaceCollectorInput) error
	CreateMarketplaceCollector(context.Context, identitydomain.Actor, experimentalapp.MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error)
}

func decodeMarketplaceCollectorRequest(body []byte) (experimentalapp.MarketplaceCollectorInput, error) {
	var req struct {
		Name         string `json:"name"`
		Provider     string `json:"provider"`
		Version      string `json:"version"`
		Publisher    string `json:"publisher"`
		ManifestHash string `json:"manifest_hash"`
		SignatureID  string `json:"signature_id"`
		SBOMID       string `json:"sbom_id"`
		ScanID       string `json:"scan_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return experimentalapp.MarketplaceCollectorInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "provider", "version", "publisher", "manifest_hash", "signature_id", "sbom_id", "scan_id"); err != nil {
		return experimentalapp.MarketplaceCollectorInput{}, err
	}
	in, err := experimentalapp.NormalizeMarketplaceCollectorInput(experimentalapp.MarketplaceCollectorInput{Name: req.Name, Provider: req.Provider, Version: req.Version, Publisher: req.Publisher, ManifestHash: req.ManifestHash, SignatureID: req.SignatureID, SBOMID: req.SBOMID, ScanID: req.ScanID})
	return in, mapAnomalyReportError(err)
}
func (s *Server) createDurableMarketplaceCollector(w http.ResponseWriter, r *http.Request) {
	var in experimentalapp.MarketplaceCollectorInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeMarketplaceCollectorRequest(body)
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.marketplaceCollectorCommands.AuthorizeCreateMarketplaceCollector(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.marketplaceCollectorCommands.CreateMarketplaceCollector(ctx, a, in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := experimentalapp.EncodeMarketplaceCollector(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}

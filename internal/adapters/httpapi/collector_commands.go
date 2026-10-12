package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type CollectorCommands interface {
	AuthorizeCreateCollector(context.Context, identitydomain.Actor, integrationapp.CreateCollectorInput) error
	AuthorizeRecordCollectorRelease(context.Context, identitydomain.Actor, integrationapp.RecordCollectorReleaseInput) error
	AuthorizeCreateCommercialCollectorDefinition(context.Context, identitydomain.Actor, integrationapp.CreateCommercialCollectorInput) error
	CreateCollector(context.Context, identitydomain.Actor, integrationapp.CreateCollectorInput) (integrationdomain.Collector, identitydomain.APIKey, string, error)
	RecordCollectorRelease(context.Context, identitydomain.Actor, integrationapp.RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error)
	CreateCommercialCollectorDefinition(context.Context, identitydomain.Actor, integrationapp.CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error)
}

func (s *Server) createDurableCollector(w http.ResponseWriter, r *http.Request) {
	var in integrationapp.CreateCollectorInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Version string   `json:"version"`
			Scopes  []string `json:"scopes"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "type", "version", "scopes"); err != nil {
			return err
		}
		if err := validateNonNullableArrayItems(body, "scopes"); err != nil {
			return err
		}
		in = integrationapp.CreateCollectorInput{Name: req.Name, Type: req.Type, Version: req.Version, Scopes: req.Scopes}
		return mapSourceRepositoryCommandError(s.collectorCommands.AuthorizeCreateCollector(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, key, secret, err := s.collectorCommands.CreateCollector(ctx, a, in)
		return http.StatusCreated, map[string]any{"collector": domain.CollectorFromContextModel(v), "api_key": domain.APIKey(key), "secret": secret}, mapSourceRepositoryCommandError(err)
	})
}
func (s *Server) recordDurableCollectorRelease(w http.ResponseWriter, r *http.Request) {
	var in integrationapp.RecordCollectorReleaseInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Version        string `json:"version"`
			ArtifactDigest string `json:"artifact_digest"`
			SignatureID    string `json:"signature_id"`
			SBOMID         string `json:"sbom_id"`
			ScanID         string `json:"scan_id"`
			Pinned         bool   `json:"pinned"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "version", "artifact_digest", "signature_id", "sbom_id", "scan_id", "pinned"); err != nil {
			return err
		}
		in = integrationapp.RecordCollectorReleaseInput{CollectorID: r.PathValue("id"), Version: req.Version, ArtifactDigest: req.ArtifactDigest, SignatureID: req.SignatureID, SBOMID: req.SBOMID, ScanID: req.ScanID, Pinned: req.Pinned}
		return mapSourceRepositoryCommandError(s.collectorCommands.AuthorizeRecordCollectorRelease(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.collectorCommands.RecordCollectorRelease(ctx, a, in)
		return http.StatusCreated, domain.CollectorRelease(v), mapSourceRepositoryCommandError(err)
	})
}
func (s *Server) createDurableCommercialCollector(w http.ResponseWriter, r *http.Request) {
	var in integrationapp.CreateCommercialCollectorInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			Name          string   `json:"name"`
			Provider      string   `json:"provider"`
			Version       string   `json:"version"`
			ManifestHash  string   `json:"manifest_hash"`
			AllowedScopes []string `json:"allowed_scopes"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "name", "provider", "version", "manifest_hash", "allowed_scopes"); err != nil {
			return err
		}
		if err := validateNonNullableArrayItems(body, "allowed_scopes"); err != nil {
			return err
		}
		in = integrationapp.CreateCommercialCollectorInput{Name: req.Name, Provider: req.Provider, Version: req.Version, ManifestHash: req.ManifestHash, AllowedScopes: req.AllowedScopes}
		return mapSourceRepositoryCommandError(s.collectorCommands.AuthorizeCreateCommercialCollectorDefinition(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.collectorCommands.CreateCommercialCollectorDefinition(ctx, a, in)
		return http.StatusCreated, domain.CommercialCollectorDefinition(v), mapSourceRepositoryCommandError(err)
	})
}

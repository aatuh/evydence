package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SBOMIngestionCommands interface {
	AuthorizeUploadSBOM(context.Context, identitydomain.Actor, evidenceapp.SBOMIngestionInput) error
	UploadSBOMPayload(context.Context, identitydomain.Actor, evidenceapp.SBOMIngestionInput, evidenceapp.PayloadSource) (evidencedomain.SBOM, error)
}

func (s *Server) uploadDurableSBOM(w http.ResponseWriter, r *http.Request, format string) {
	media := evidenceapp.CycloneDXMediaType
	if format == "spdx" {
		media = evidenceapp.SPDXMediaType
	}
	if requestMediaType(r) == media {
		s.uploadDurableNativeSBOM(w, r, format)
		return
	}
	var in evidenceapp.SBOMIngestionInput
	var source evidenceapp.PayloadSource
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			ReleaseID  string          `json:"release_id"`
			ArtifactID string          `json:"artifact_id"`
			Payload    json.RawMessage `json:"payload"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "release_id", "artifact_id", "payload"); err != nil {
			return err
		}
		in = evidenceapp.SBOMIngestionInput{ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: format}
		source = evidenceapp.BytesPayloadSource(req.Payload)
		return mapEvidenceCreationCommandError(s.sbomIngestionCommands.AuthorizeUploadSBOM(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.sbomIngestionCommands.UploadSBOMPayload(ctx, a, in, source)
		return http.StatusCreated, domain.SBOMFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
func (s *Server) uploadDurableNativeSBOM(w http.ResponseWriter, r *http.Request, format string) {
	a, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	release, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	artifact, err := optionalSingleHeader(r, "X-Evydence-Artifact-ID")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	source, cleanup, err := streamRequestPayload(r, evidenceapp.EvidenceDocumentLimit)
	if err != nil {
		writeProblem(w, r, app.ErrValidation)
		return
	}
	defer cleanup()
	in := evidenceapp.SBOMIngestionInput{ReleaseID: release, ArtifactID: artifact, Format: format}
	guard := func(ctx context.Context) error {
		return mapEvidenceCreationCommandError(s.sbomIngestionCommands.AuthorizeUploadSBOM(ctx, a, in))
	}
	s.executeDurableNativeDocument(w, r, a, source.Digest, map[string]string{"artifact_id": artifact, "media_type": requestMediaType(r), "release_id": release}, guard, func(ctx context.Context) (int, any, error) {
		v, err := s.sbomIngestionCommands.UploadSBOMPayload(ctx, a, in, evidenceapp.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open})
		return http.StatusCreated, domain.SBOMFromContext(v), mapEvidenceCreationCommandError(err)
	}, func(response any) bool { return sbomReplayMatches(response, a, in) })
}
func sbomReplayMatches(response any, a domain.Actor, in evidenceapp.SBOMIngestionInput) bool {
	var tenant, release, artifact, format string
	switch v := response.(type) {
	case domain.SBOM:
		tenant, release, artifact, format = v.TenantID, v.ReleaseID, v.ArtifactID, v.Format
	case map[string]any:
		tenant, _ = v["tenant_id"].(string)
		release, _ = v["release_id"].(string)
		artifact, _ = v["artifact_id"].(string)
		format, _ = v["format"].(string)
	default:
		return false
	}
	return tenant == a.TenantID && release == strings.TrimSpace(in.ReleaseID) && artifact == strings.TrimSpace(in.ArtifactID) && format == in.Format
}

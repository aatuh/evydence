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

type VEXIngestionCommands interface {
	AuthorizeUploadVEX(context.Context, identitydomain.Actor, evidenceapp.VEXIngestionInput) error
	UploadVEXPayload(context.Context, identitydomain.Actor, evidenceapp.VEXIngestionInput, evidenceapp.PayloadSource) (evidencedomain.VEXDocument, error)
}

func (s *Server) uploadDurableVEX(w http.ResponseWriter, r *http.Request, format string) {
	if format == "openvex" && requestMediaType(r) == evidenceapp.OpenVEXMediaType {
		s.uploadDurableNativeVEX(w, r)
		return
	}
	var in evidenceapp.VEXIngestionInput
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
		in = evidenceapp.VEXIngestionInput{ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: format}
		source = evidenceapp.BytesPayloadSource(req.Payload)
		return mapEvidenceCreationCommandError(s.vexIngestionCommands.AuthorizeUploadVEX(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.vexIngestionCommands.UploadVEXPayload(ctx, a, in, source)
		return http.StatusCreated, domain.VEXDocumentFromContext(v), mapEvidenceCreationCommandError(err)
	})
}

func (s *Server) uploadDurableNativeVEX(w http.ResponseWriter, r *http.Request) {
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
	in := evidenceapp.VEXIngestionInput{ReleaseID: release, ArtifactID: artifact, Format: "openvex"}
	guard := func(ctx context.Context) error {
		return mapEvidenceCreationCommandError(s.vexIngestionCommands.AuthorizeUploadVEX(ctx, a, in))
	}
	s.executeDurableNativeDocument(w, r, a, source.Digest, map[string]string{"artifact_id": artifact, "media_type": requestMediaType(r), "release_id": release}, guard, func(ctx context.Context) (int, any, error) {
		v, err := s.vexIngestionCommands.UploadVEXPayload(ctx, a, in, evidenceapp.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open})
		return http.StatusCreated, domain.VEXDocumentFromContext(v), mapEvidenceCreationCommandError(err)
	}, func(response any) bool { return vexReplayMatches(response, a, in) })
}
func vexReplayMatches(response any, a domain.Actor, in evidenceapp.VEXIngestionInput) bool {
	var tenant, release, artifact, format string
	switch v := response.(type) {
	case domain.VEXDocument:
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

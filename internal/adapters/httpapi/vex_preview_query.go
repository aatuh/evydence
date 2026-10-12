package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type VEXPreviewQuery interface {
	PreviewVEXImport(context.Context, identitydomain.Actor, evidencequery.VEXPreviewInput) (evidencedomain.VEXImportPreview, error)
}

func (s *Server) previewDurableVEX(w http.ResponseWriter, r *http.Request, format string) {
	a, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var req struct {
		ReleaseID  string          `json:"release_id"`
		ArtifactID string          `json:"artifact_id"`
		Payload    json.RawMessage `json:"payload"`
	}
	if err := decodeJSON(body, &req); err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := validateNonNullableObjectFields(body, "release_id", "artifact_id", "payload"); err != nil {
		writeProblem(w, r, err)
		return
	}
	out, err := s.vexPreviewQuery.PreviewVEXImport(r.Context(), a, evidencequery.VEXPreviewInput{ReleaseID: req.ReleaseID, ArtifactID: req.ArtifactID, Format: format, Payload: req.Payload})
	if err != nil {
		writeProblem(w, r, mapEvidencePointQueryError(err))
		return
	}
	writeData(w, http.StatusOK, domain.VEXImportPreviewFromContext(out))
}

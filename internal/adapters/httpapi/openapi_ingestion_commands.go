package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type OpenAPIIngestionCommands interface {
	AuthorizeUploadOpenAPIContract(context.Context, identitydomain.Actor, evidenceapp.OpenAPIIngestionInput) error
	UploadOpenAPIContractPayload(context.Context, identitydomain.Actor, evidenceapp.OpenAPIIngestionInput, evidenceapp.PayloadSource) (evidencedomain.OpenAPIContract, error)
}
type DurableStreamedCommandExecutor interface {
	WithBodyDigest(context.Context, domain.Actor, string, string, string, string, func(context.Context) error, func(context.Context) (int, any, error)) (int, any, error)
}

func (s *Server) uploadDurableOpenAPIContract(w http.ResponseWriter, r *http.Request) {
	if requestMediaType(r) == evidenceapp.OpenAPIMediaType {
		s.uploadDurableNativeOpenAPI(w, r)
		return
	}
	var in evidenceapp.OpenAPIIngestionInput
	var source evidenceapp.PayloadSource
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			ProductID string          `json:"product_id"`
			ReleaseID string          `json:"release_id"`
			Version   string          `json:"version"`
			Spec      json.RawMessage `json:"spec"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "product_id", "release_id", "version", "spec"); err != nil {
			return err
		}
		in = evidenceapp.OpenAPIIngestionInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, Version: req.Version}
		source = evidenceapp.BytesPayloadSource(req.Spec)
		return mapEvidenceCreationCommandError(s.openAPIIngestionCommands.AuthorizeUploadOpenAPIContract(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.openAPIIngestionCommands.UploadOpenAPIContractPayload(ctx, a, in, source)
		return http.StatusCreated, domain.OpenAPIContractFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
func (s *Server) uploadDurableNativeOpenAPI(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	product, err := requiredSingleHeader(r, "X-Evydence-Product-ID")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	release, err := requiredSingleHeader(r, "X-Evydence-Release-ID")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	version, err := requiredSingleHeader(r, "X-Evydence-Version")
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
	in := evidenceapp.OpenAPIIngestionInput{ProductID: product, ReleaseID: release, Version: version}
	executor := s.durableStreamedCommandExecutor
	guard := func(ctx context.Context) error {
		return mapEvidenceCreationCommandError(s.openAPIIngestionCommands.AuthorizeUploadOpenAPIContract(ctx, a, in))
	}
	fingerprint := streamedRequestFingerprint(source.Digest, map[string]string{"media_type": requestMediaType(r), "product_id": product, "release_id": release, "version": version})
	status, response, err := executor.WithBodyDigest(r.Context(), a, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), fingerprint, guard, func(ctx context.Context) (int, any, error) {
		v, err := s.openAPIIngestionCommands.UploadOpenAPIContractPayload(ctx, a, in, evidenceapp.PayloadSource{Digest: source.Digest, Size: source.Size, Open: source.Open})
		return http.StatusCreated, domain.OpenAPIContractFromContext(v), mapEvidenceCreationCommandError(err)
	})
	if errors.Is(err, app.ErrIdempotencyConflict) && fingerprint != source.Digest {
		// Compatibility is replay-only. Never run a new upload with the older,
		// weaker body-only fingerprint or expose another resource's saved result.
		status, response, err = executor.WithBodyDigest(r.Context(), a, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), source.Digest, guard, func(context.Context) (int, any, error) { return 0, nil, app.ErrIdempotencyConflict })
	}
	if err == nil && !openAPIReplayMatches(response, a, in, source.Digest) {
		err = app.ErrIdempotencyConflict
	}
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	writeData(w, status, response)
}
func openAPIReplayMatches(response any, a domain.Actor, in evidenceapp.OpenAPIIngestionInput, digest string) bool {
	var tenant, product, release, version, hash string
	switch v := response.(type) {
	case domain.OpenAPIContract:
		tenant, product, release, version, hash = v.TenantID, v.ProductID, v.ReleaseID, v.Version, v.Hash
	case map[string]any:
		tenant, _ = v["tenant_id"].(string)
		product, _ = v["product_id"].(string)
		release, _ = v["release_id"].(string)
		version, _ = v["version"].(string)
		hash, _ = v["hash"].(string)
	default:
		return false
	}
	return tenant == a.TenantID && product == strings.TrimSpace(in.ProductID) && release == strings.TrimSpace(in.ReleaseID) && version == strings.TrimSpace(in.Version) && hash == digest
}

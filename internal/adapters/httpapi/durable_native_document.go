package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) executeDurableNativeDocument(w http.ResponseWriter, r *http.Request, a domain.Actor, digest string, metadata map[string]string, guard func(context.Context) error, run func(context.Context) (int, any, error), matches func(any) bool) {
	fingerprint := streamedRequestFingerprint(digest, metadata)
	status, response, err := s.durableStreamedCommandExecutor.WithBodyDigest(r.Context(), a, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), fingerprint, guard, run)
	if errors.Is(err, app.ErrIdempotencyConflict) && fingerprint != digest {
		// Retained body-only keys are replay-only: never execute a new command
		// under their weaker fingerprint or expose different resource coordinates.
		status, response, err = s.durableStreamedCommandExecutor.WithBodyDigest(r.Context(), a, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), digest, guard, func(context.Context) (int, any, error) { return 0, nil, app.ErrIdempotencyConflict })
	}
	if err == nil && !matches(response) {
		err = app.ErrIdempotencyConflict
	}
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	writeData(w, status, response)
}

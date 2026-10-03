package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// DurableCommandExecutor gives a focused command the same transaction as its
// replay record. Current authorization must run before reservation/replay; it
// cannot be substituted by a saved success. Neither callback can bind a Ledger.
type DurableCommandExecutor interface {
	WithBody(context.Context, domain.Actor, string, string, string, []byte, func(context.Context) error, func(context.Context) (int, any, error)) (int, any, error)
}

func (s *Server) createDurable(w http.ResponseWriter, r *http.Request, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error)) {
	s.createDurableAfterCommit(w, r, authorize, run, nil)
}

func (s *Server) createDurableAfterCommit(w http.ResponseWriter, r *http.Request, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error), afterCommit func()) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBodyLimit(r, app.SmallJSONRequestLimit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	status, response, err := s.durableCommandExecutor.WithBody(r.Context(), actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), body, func(ctx context.Context) error { return authorize(ctx, actor, body) }, func(ctx context.Context) (int, any, error) { return run(ctx, actor, body) })
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if afterCommit != nil {
		afterCommit()
	}
	w.Header().Set("Idempotency-Key", r.Header.Get("Idempotency-Key"))
	writeData(w, status, response)
}

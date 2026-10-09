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

// DurableReplayCommandExecutor can authorize a historical server-selected
// scope without rerunning a command or reconstructing a current snapshot.
type DurableReplayCommandExecutor interface {
	WithBodyReplayAuthorization(context.Context, domain.Actor, string, string, string, []byte, func(context.Context) error, func(context.Context, any) error, func(context.Context) (int, any, error)) (int, any, error)
}

func (s *Server) createDurable(w http.ResponseWriter, r *http.Request, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error)) {
	s.createDurableAfterCommit(w, r, authorize, run, nil)
}

func (s *Server) createDurableWithLimit(w http.ResponseWriter, r *http.Request, limit int64, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error)) {
	s.createDurableWithLimitAndFingerprint(w, r, limit, authorize, run, nil, nil)
}

func (s *Server) createDurableAfterCommit(w http.ResponseWriter, r *http.Request, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error), afterCommit func()) {
	s.createDurableWithFingerprint(w, r, authorize, run, afterCommit, nil)
}

// Fingerprints may bind security-relevant request context while callbacks still
// receive the original bytes. Current authorization always precedes replay.
func (s *Server) createDurableWithFingerprint(w http.ResponseWriter, r *http.Request, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error), afterCommit func(), fingerprint func(domain.Actor, []byte) ([]byte, error)) {
	s.createDurableWithLimitAndFingerprint(w, r, app.SmallJSONRequestLimit, authorize, run, afterCommit, fingerprint)
}

func (s *Server) createDurableWithLimitAndFingerprint(w http.ResponseWriter, r *http.Request, limit int64, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error), afterCommit func(), fingerprint func(domain.Actor, []byte) ([]byte, error)) {
	s.executeDurableCreate(w, r, limit, authorize, run, afterCommit, fingerprint, nil)
}

func (s *Server) executeDurableCreate(w http.ResponseWriter, r *http.Request, limit int64, authorize func(context.Context, domain.Actor, []byte) error, run func(context.Context, domain.Actor, []byte) (int, any, error), afterCommit func(), fingerprint func(domain.Actor, []byte) ([]byte, error), authorizeReplay func(context.Context, domain.Actor, any) error) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBodyLimit(r, limit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	input := body
	if fingerprint != nil {
		input, err = fingerprint(actor, body)
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	guard := func(ctx context.Context) error { return authorize(ctx, actor, body) }
	command := func(ctx context.Context) (int, any, error) { return run(ctx, actor, body) }
	var status int
	var response any
	if authorizeReplay != nil {
		executor, ok := s.durableCommandExecutor.(DurableReplayCommandExecutor)
		if !ok {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		status, response, err = executor.WithBodyReplayAuthorization(r.Context(), actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), input, guard, func(ctx context.Context, v any) error { return authorizeReplay(ctx, actor, v) }, command)
	} else {
		status, response, err = s.durableCommandExecutor.WithBody(r.Context(), actor, r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"), input, guard, command)
	}
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

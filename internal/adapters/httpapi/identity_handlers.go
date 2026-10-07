package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityquery "github.com/aatuh/evydence/internal/identity/query"
)

const ssoSessionCookieName = "evydence_session"

func (s *Server) instanceAdminSnapshot(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	snapshot, err := s.instanceAdminQuery.Snapshot(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, mapInstanceAdminQueryError(err))
		return
	}
	writeData(w, http.StatusOK, instanceAdminSnapshotFromQuery(snapshot))
}

func (s *Server) outboxOperatorDiagnostics(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	diagnostics, err := s.outboxDiagnosticsQuery.Diagnostics(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, mapInstanceAdminQueryError(err))
		return
	}
	writeData(w, http.StatusOK, app.OutboxDiagnostics{
		PendingJobs: diagnostics.PendingJobs, RunningJobs: diagnostics.RunningJobs,
		TerminalJobs: diagnostics.TerminalJobs, OldestPendingCreatedAt: diagnostics.OldestPendingCreatedAt,
	})
}

func (s *Server) replayTerminalOutboxJob(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	body, err := readBodyLimit(r, app.SmallJSONRequestLimit)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	status, replay, err := s.outboxReplayCommand.ReplayIdempotent(r.Context(), actor, r.Method, r.URL.Path, key, body, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if key != "" {
		w.Header().Set("Idempotency-Key", key)
	}
	writeData(w, status, replay)
}

func (s *Server) createOrganization(w http.ResponseWriter, r *http.Request) {
	s.createDurableOrganization(w, r)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	s.createDurableUser(w, r)
}

func (s *Server) deactivateUser(w http.ResponseWriter, r *http.Request) {
	s.deactivateDurableUser(w, r)
}

func (s *Server) createRoleBinding(w http.ResponseWriter, r *http.Request) {
	s.createDurableRoleBinding(w, r)
}

func (s *Server) listRoleBindings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	request, err := s.parsePageRequest(r, actor, "role-bindings")
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	result, err := s.roleBindingQuery.ListPage(r.Context(), actor, appquery.PageRequest{PageSize: request.pageSize, Sort: request.sort, Direction: request.direction}, request.after)
	if err != nil {
		switch {
		case errors.Is(err, identityquery.ErrValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
			err = app.ErrValidation
		case errors.Is(err, application.ErrUnauthorized):
			err = app.ErrUnauthorized
		case errors.Is(err, application.ErrForbidden):
			err = app.ErrForbidden
		}
		writeProblem(w, r, err)
		return
	}
	page := appquery.Result[domain.RoleBinding]{Next: result.Next, Items: make([]domain.RoleBinding, 0, len(result.Items))}
	for _, binding := range result.Items {
		page.Items = append(page.Items, roleBindingFromQuery(binding))
	}
	writePage(s, w, r, actor, "role-bindings", request, page)
}

func (s *Server) createSSOProvider(w http.ResponseWriter, r *http.Request) {
	s.createDurableSSOProvider(w, r)
}

func (s *Server) updateSSOProviderTrustMaterial(w http.ResponseWriter, r *http.Request) {
	s.updateDurableSSOTrustMaterial(w, r)
}

func (s *Server) refreshSSOProviderOIDCTrustMaterial(w http.ResponseWriter, r *http.Request) {
	s.refreshDurableSSOTrustMaterial(w, r)
}

func (s *Server) linkSSOIdentity(w http.ResponseWriter, r *http.Request) {
	s.linkDurableSSOIdentity(w, r)
}

func (s *Server) createSSOSession(w http.ResponseWriter, r *http.Request) {
	s.createDurableSSOSession(w, r)
}

func (s *Server) exchangeSSOCredential(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	in, err := decodeSSOExchangeRequest(body)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	v, result, secret, exchangeErr := s.ssoExchangeCommands.ExchangeSSOCredential(r.Context(), in)
	verification, session, err := app.ProviderVerificationFromIdentity(v), domain.SSOSession(result), mapIdentityCommandError(exchangeErr)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setSSOSessionCookie(w, secret, session.ExpiresAt)
	writeData(w, http.StatusCreated, map[string]any{"verification": verification, "session": session, "secret": secret})
}

func (s *Server) revokeSSOSession(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.revokeDurableSSOSession(w, r)
}

func (s *Server) logoutSSOSession(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.logoutDurableSSOSession(w, r)
}

func setSSOSessionCookie(w http.ResponseWriter, secret string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCookieName,
		Value:    secret,
		Path:     "/v1",
		Expires:  expiresAt.UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSSOSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCookieName,
		Value:    "",
		Path:     "/v1",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

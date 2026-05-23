package httpapi

import (
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func (s *Server) createLegalHold(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
		Reason    string `json:"reason"`
		Owner     string `json:"owner"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		hold, err := s.ledger.CreateLegalHold(r.Context(), actor, app.CreateLegalHoldInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, Reason: req.Reason, Owner: req.Owner})
		return http.StatusCreated, hold, err
	})
}

func (s *Server) createRetentionOverride(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeType      string    `json:"scope_type"`
		ScopeID        string    `json:"scope_id"`
		RetentionUntil time.Time `json:"retention_until"`
		Reason         string    `json:"reason"`
		Owner          string    `json:"owner"`
	}
	s.create(w, r, func(actor domain.Actor, body []byte) (int, any, error) {
		if err := decodeJSON(body, &req); err != nil {
			return 0, nil, err
		}
		override, err := s.ledger.CreateRetentionOverride(r.Context(), actor, app.CreateRetentionOverrideInput{ScopeType: req.ScopeType, ScopeID: req.ScopeID, RetentionUntil: req.RetentionUntil, Reason: req.Reason, Owner: req.Owner})
		return http.StatusCreated, override, err
	})
}

func (s *Server) retentionReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	report, err := s.ledger.RetentionReport(r.Context(), actor, r.URL.Query().Get("scope_type"), r.URL.Query().Get("scope_id"))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

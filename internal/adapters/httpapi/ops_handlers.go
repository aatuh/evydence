package httpapi

import (
	"net/http"
)

func (s *Server) createLegalHold(w http.ResponseWriter, r *http.Request) {
	s.createRetentionMarker(w, r, false)
}

func (s *Server) createRetentionOverride(w http.ResponseWriter, r *http.Request) {
	s.createRetentionMarker(w, r, true)
}

func (s *Server) retentionReport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	scopeType, scopeID, filterErr := retentionReportFilters(r)
	if filterErr != nil {
		writeProblem(w, r, filterErr)
		return
	}
	focused, err := s.retentionQuery.Report(r.Context(), actor, scopeType, scopeID)
	report := retentionReportFromQuery(focused)
	err = mapInstanceAdminQueryError(err)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

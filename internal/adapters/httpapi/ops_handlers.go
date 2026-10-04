package httpapi

import (
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
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
	var report domain.RetentionReport
	var err error
	if s.retentionQuery != nil {
		var focused operationsdomain.RetentionReport
		focused, err = s.retentionQuery.Report(r.Context(), actor, scopeType, scopeID)
		report = retentionReportFromQuery(focused)
		err = mapInstanceAdminQueryError(err)
	} else {
		report, err = s.ledger.RetentionReport(r.Context(), actor, scopeType, scopeID)
	}
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, report)
}

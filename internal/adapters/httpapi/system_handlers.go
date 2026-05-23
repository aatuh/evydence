package httpapi

import (
	"net/http"
)

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	status, err := s.ledger.ReadinessStatus(r.Context())
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, status)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	metrics, err := s.ledger.Metrics(r.Context(), actor)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeData(w, http.StatusOK, metrics)
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeData(w, http.StatusOK, map[string]string{"version": "dev"})
}

func (s *Server) openapi(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.OpenAPI()
	if err != nil {
		writeProblem(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

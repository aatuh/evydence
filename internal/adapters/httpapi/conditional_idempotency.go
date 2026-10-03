package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// Conditional actions validate If-Match even on replay and bind its canonical
// revision into the request digest. Raw request bytes still reach the command.
func (s *Server) createConditional(w http.ResponseWriter, r *http.Request, run func(*Server, requestContext, domain.Actor, []byte) (int, any, error)) {
	s.createWithFingerprint(w, r, app.SmallJSONRequestLimit, run, conditionalActionFingerprint)
}

func conditionalActionFingerprint(r *http.Request, body []byte) ([]byte, error) {
	revision, err := expectedRevisionFromIfMatch(r)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version  string `json:"version"`
		Revision int64  `json:"revision"`
		Body     []byte `json:"body"`
	}{Version: "conditional-action-v1", Revision: revision, Body: body})
}

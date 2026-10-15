package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
)

func (i *ingressControl) opaqueLimitKey(class, identity string) [32]byte {
	h := hmac.New(sha256.New, i.failureKey[:])
	_, _ = h.Write([]byte(class))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(identity))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func (s *Server) reserveFailureAttempt(w http.ResponseWriter, r *http.Request, class string) (*failureReservation, bool) {
	if s.ingress == nil {
		// Explicit handler-only fixtures have no server ingress. Every constructed
		// native server installs its ingress before registering routes.
		return nil, true
	}
	key := s.ingress.opaqueLimitKey(class, s.clientRateLimitKey(r))
	lease, allowed := s.ingress.failures.reserve(key, s.ingress.failureClock())
	if !allowed {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(w, r, app.ErrRateLimited)
	}
	return lease, allowed
}

func (s *Server) failureLimitedPublicHandler(operation string, next http.Handler) http.Handler {
	class := ""
	switch operation {
	case "exchangeSSOCredential", "beginOIDCAuthentication", "beginSAMLAuthentication":
		class = "sso"
	case "accessCustomerPortalPackage", "downloadCustomerPortalPackage", "customerPortalPackageView", "downloadCustomerPortalPackageView":
		class = "portal"
	default:
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lease, allowed := s.reserveFailureAttempt(w, r, class)
		if !allowed {
			return
		}
		response := &failureStatusWriter{ResponseWriter: w}
		completed := false
		if lease != nil {
			defer func() { lease.finish(!completed || response.status >= http.StatusBadRequest) }()
		}
		next.ServeHTTP(response, r)
		completed = true
	})
}

// These finite JSON/form/download handlers only need final response status;
// body bytes flow directly to the existing writer without buffering. Unwrap
// preserves access through http.ResponseController for streaming controls.
type failureStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *failureStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *failureStatusWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *failureStatusWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(body)
}

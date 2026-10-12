package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/aatuh/evydence/internal/app"
)

const maxConditionalReadBodyBytes = 2 << 20

// conditionalReadMiddleware evaluates If-None-Match only for finite JSON
// resource reads. Downloads, generated documents, reports, and collection
// queries deliberately bypass it so caching never turns an unbounded response
// into a server-side buffer and resource-specific cache semantics stay clear.
func (s *Server) conditionalReadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isConditionalResourceRead(r) {
			next.ServeHTTP(w, r)
			return
		}
		match, err := parseIfNoneMatch(r)
		if err != nil {
			writeProblem(w, r, app.ErrValidation)
			return
		}
		recorder := &conditionalReadWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if recorder.passthrough {
			return
		}
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if status != http.StatusOK || !strings.HasPrefix(strings.ToLower(w.Header().Get("Content-Type")), "application/json") {
			recorder.commit(status)
			return
		}
		etag := resourceETag(recorder.body.Bytes())
		setPrivateETagHeaders(w.Header(), etag)
		if match.matches(etag) {
			w.Header().Del("Content-Type")
			w.Header().Del("Content-Length")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		recorder.commit(status)
	})
}

func isConditionalResourceRead(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet {
		return false
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 3 && parts[0] == "v1" && parts[2] != "" {
		switch parts[1] {
		case "controls", "products", "projects", "releases", "release-candidates", "artifacts", "artifact-signatures", "builds", "deployments", "customer-packages", "evidence", "sboms", "vex", "vulnerability-scans", "openapi-contracts", "release-bundles":
			return true
		}
	}
	return len(parts) == 4 && parts[0] == "v1" && parts[2] != "" && ((parts[1] == "vex" && parts[3] == "import-report") || (parts[1] == "release-bundles" && parts[3] == "manifest"))
}

type conditionalReadWriter struct {
	http.ResponseWriter
	status      int
	body        bytes.Buffer
	passthrough bool
}

func (w *conditionalReadWriter) WriteHeader(status int) {
	if w.passthrough || w.status != 0 {
		return
	}
	w.status = status
}

func (w *conditionalReadWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.passthrough {
		return w.ResponseWriter.Write(body)
	}
	if w.body.Len()+len(body) > maxConditionalReadBodyBytes {
		w.passthrough = true
		w.ResponseWriter.WriteHeader(w.status)
		if w.body.Len() > 0 {
			if _, err := w.ResponseWriter.Write(w.body.Bytes()); err != nil {
				return 0, err
			}
		}
		w.body.Reset()
		return w.ResponseWriter.Write(body)
	}
	return w.body.Write(body)
}

func (w *conditionalReadWriter) commit(status int) {
	w.ResponseWriter.WriteHeader(status)
	if w.body.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.body.Bytes())
	}
}

func resourceETag(body []byte) string {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Data) > 0 {
		var resource struct {
			Revision json.Number `json:"revision"`
		}
		decoder := json.NewDecoder(bytes.NewReader(envelope.Data))
		decoder.UseNumber()
		if decoder.Decode(&resource) == nil {
			if revision, err := strconv.ParseInt(resource.Revision.String(), 10, 64); err == nil && revision > 0 && strconv.FormatInt(revision, 10) == resource.Revision.String() {
				return `"` + resource.Revision.String() + `"`
			}
		}
	}
	digest := sha256.Sum256(body)
	return `"` + hex.EncodeToString(digest[:]) + `"`
}

func setPrivateETagHeaders(headers http.Header, etag string) {
	headers.Set("ETag", etag)
	headers.Set("Cache-Control", "private, max-age=0, must-revalidate")
	for _, value := range headers.Values("Vary") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "Authorization") {
				return
			}
		}
	}
	headers.Add("Vary", "Authorization")
}

type ifNoneMatch struct {
	any  bool
	tags []string
}

func (m ifNoneMatch) matches(etag string) bool {
	if m.any {
		return true
	}
	for _, tag := range m.tags {
		if tag == etag {
			return true
		}
	}
	return false
}

func parseIfNoneMatch(r *http.Request) (ifNoneMatch, error) {
	if r == nil || len(r.Header.Values("If-None-Match")) == 0 {
		return ifNoneMatch{}, nil
	}
	raw := strings.Join(r.Header.Values("If-None-Match"), ",")
	if len(raw) == 0 || len(raw) > 1024 {
		return ifNoneMatch{}, app.ErrValidation
	}
	var parsed ifNoneMatch
	for position := 0; position < len(raw); {
		for position < len(raw) && (raw[position] == ' ' || raw[position] == '\t') {
			position++
		}
		if position == len(raw) {
			return ifNoneMatch{}, app.ErrValidation
		}
		if raw[position] == '*' {
			if parsed.any || len(parsed.tags) != 0 {
				return ifNoneMatch{}, app.ErrValidation
			}
			parsed.any = true
			position++
		} else {
			if strings.HasPrefix(raw[position:], "W/") {
				position += 2
			}
			if position >= len(raw) || raw[position] != '"' {
				return ifNoneMatch{}, app.ErrValidation
			}
			start := position
			position++
			for position < len(raw) && raw[position] != '"' {
				if raw[position] < 0x21 || raw[position] == 0x7f {
					return ifNoneMatch{}, app.ErrValidation
				}
				position++
			}
			if position == len(raw) || position == start+1 {
				return ifNoneMatch{}, app.ErrValidation
			}
			parsed.tags = append(parsed.tags, raw[start:position+1])
			position++
		}
		for position < len(raw) && (raw[position] == ' ' || raw[position] == '\t') {
			position++
		}
		if position == len(raw) {
			break
		}
		if raw[position] != ',' || parsed.any {
			return ifNoneMatch{}, app.ErrValidation
		}
		position++
	}
	return parsed, nil
}

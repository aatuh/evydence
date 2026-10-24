package httpgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

var errReadiness = errors.New("signing gateway dependency is unavailable")

func validateReadinessEndpoint(value string, signingURL *url.URL) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil // Existing signing-only configurations remain constructible.
	}
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Scheme != signingURL.Scheme || !strings.EqualFold(endpoint.Hostname(), signingURL.Hostname()) || originPort(endpoint) != originPort(signingURL) {
		return "", app.ErrValidation
	}
	return value, nil
}

func originPort(endpoint *url.URL) string {
	if port := endpoint.Port(); port != "" {
		return port
	}
	if endpoint.Scheme == "https" {
		return "443"
	}
	return "80"
}

// CheckReadiness uses an explicitly configured, non-mutating GET endpoint.
// The gateway must answer 200 with exactly {"status":"ok"} once its required
// signing dependencies are available. Redirects and cross-origin credentials
// are forbidden. This is an availability signal, not signature verification.
func (e *Executor) CheckReadiness(ctx context.Context) error {
	if e == nil || e.client == nil || e.readinessEndpoint == "" || ctx == nil {
		return app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := e.client.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, e.readinessEndpoint, nil)
	if err != nil {
		return readinessError(callCtx, err)
	}
	request.Header.Set("Accept", "application/json")
	if e.bearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+e.bearerToken)
	}
	response, err := e.client.Do(request)
	if err != nil {
		return readinessError(callCtx, err)
	}
	defer func() { _ = response.Body.Close() }()
	const maxReadinessBytes = 4096
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReadinessBytes+1))
	if err != nil {
		return readinessError(callCtx, err)
	}
	if response.StatusCode != http.StatusOK || len(body) > maxReadinessBytes {
		return readinessError(callCtx, errReadiness)
	}
	var decoded struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoder.Decode(&struct{}{}) != io.EOF || decoded.Status != "ok" {
		return readinessError(callCtx, errReadiness)
	}
	return readinessError(callCtx, nil)
}

func readinessError(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if err == nil {
		return nil
	}
	// Transport/body errors may expose cancellation before the context timer does.
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errReadiness
}

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"
	authshared "github.com/aatuh/api-toolkit/v3/middleware/auth/shared"
)

const workerMetricsSnapshotTimeout = 2 * time.Second

var errWorkerMetricsUnavailable = errors.New("worker metrics snapshot is unavailable")

type workerMetricsSnapshotter interface {
	Snapshot(context.Context) (string, error)
}

func newWorkerMetricsHandler(config workerMetricsConfig, source workerMetricsSnapshotter) (http.Handler, error) {
	if !config.enabled || config.tokenHash == ([sha256.Size]byte{}) || missingWorkerPort(source) {
		return nil, errWorkerMetricsConfig
	}
	admitted := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		reject := func(code int) {
			if code == http.StatusServiceUnavailable {
				w.Header().Set("Retry-After", "1")
			}
			if code == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="worker-metrics"`)
			}
			httpx.WriteProblem(w, code, httpx.Problem{Type: "about:blank", Title: http.StatusText(code), Status: code})
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			reject(http.StatusMethodNotAllowed)
			return
		}
		if len(r.RequestURI) > 1024 || r.URL.ForceQuery || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" {
			reject(http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/metrics" || (r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path) {
			reject(http.StatusNotFound)
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) != 1 || len(headers[0]) > 128 {
			reject(http.StatusUnauthorized)
			return
		}
		token, present, err := authshared.ParseBearerToken(headers[0])
		if err != nil || !present || !validWorkerMetricsToken(token) {
			reject(http.StatusUnauthorized)
			return
		}
		hash := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(hash[:], config.tokenHash[:]) != 1 {
			reject(http.StatusUnauthorized)
			return
		}
		select {
		case admitted <- struct{}{}:
			defer func() { <-admitted }()
		default:
			reject(http.StatusServiceUnavailable)
			return
		}
		body, err := workerMetricSnapshot(r.Context(), source)
		if err != nil {
			reject(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	}), nil
}

func workerMetricSnapshot(ctx context.Context, source workerMetricsSnapshotter) (body string, err error) {
	defer func() {
		if recover() != nil {
			body = ""
			err = errWorkerMetricsUnavailable
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, workerMetricsSnapshotTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", errWorkerMetricsUnavailable
	}
	body, err = source.Snapshot(ctx)
	if err != nil || ctx.Err() != nil || len(body) > 8<<20 {
		return "", errWorkerMetricsUnavailable
	}
	return body, nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/api-toolkit/v3/httpx"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/health"
)

const workerProbeTimeout = 5 * time.Second

var errWorkerProbeUnavailable = errors.New("worker lifecycle probe is unavailable")

// workerHealthAddress accepts only literal loopback addresses. The worker's
// operational listener is neither a public API nor a remote probe client.
func workerHealthAddress() (netip.AddrPort, error) {
	value := strings.TrimSpace(os.Getenv("EVYDENCE_WORKER_HEALTH_ADDR"))
	if value == "" {
		value = "127.0.0.1:8081"
	}
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.Port() == 0 || !address.Addr().Unmap().IsLoopback() || address.Addr().Zone() != "" {
		return netip.AddrPort{}, errors.New("EVYDENCE_WORKER_HEALTH_ADDR must be a literal loopback address and nonzero port")
	}
	return address, nil
}

func newWorkerHealthHandler(monitor *health.Monitor) http.Handler {
	admitted := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		reject := func(code int) {
			httpx.WriteProblem(w, code, httpx.Problem{Type: "about:blank", Title: http.StatusText(code), Status: code})
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			reject(http.StatusMethodNotAllowed)
			return
		}
		if len(r.RequestURI) > 1024 || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Content-Encoding") != "" {
			reject(http.StatusBadRequest)
			return
		}
		if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
			reject(http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case "/v1/health":
			writeWorkerProbe(w, monitor.Live())
			return
		case "/v1/startup", "/v1/ready":
		default:
			reject(http.StatusNotFound)
			return
		}
		select {
		case admitted <- struct{}{}:
			defer func() { <-admitted }()
		default:
			writeWorkerProbe(w, false)
			return
		}
		snapshot, err := monitor.Snapshot(r.Context())
		ready := err == nil && snapshot.Ready
		if r.URL.Path == "/v1/startup" {
			ready = err == nil && snapshot.StartupReady
		}
		writeWorkerProbe(w, ready)
	})
}

func writeWorkerProbe(w http.ResponseWriter, ready bool) {
	code, state := http.StatusOK, "ok"
	data := map[string]any{}
	if !ready {
		code, state = http.StatusServiceUnavailable, "unavailable"
		problem := app.DescribeProblem(app.ErrDependencyUnavailable)
		data["retryable"], data["retry_class"] = problem.Retryable, problem.RetryClass
		if problem.RetryAfterSeconds > 0 {
			data["retry_after_seconds"] = problem.RetryAfterSeconds
			w.Header().Set("Retry-After", strconv.Itoa(problem.RetryAfterSeconds))
		}
	}
	data["status"] = state
	httpx.WriteJSON(w, code, map[string]any{"data": data, "meta": map[string]string{"api_version": "v1", "process": "worker"}})
}

func runWorkerHealthcheck(ctx context.Context, args []string) error {
	if ctx == nil {
		return errWorkerProbeUnavailable
	}
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	liveness, startup := flags.Bool("liveness", false, ""), flags.Bool("startup", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || (*liveness && *startup) {
		return errors.New("worker healthcheck accepts one of --liveness or --startup, or no flags for readiness")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	address, err := workerHealthAddress()
	if err != nil {
		return err
	}
	path := "/v1/ready"
	if *liveness {
		path = "/v1/health"
	} else if *startup {
		path = "/v1/startup"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address.String()+path, nil)
	if err != nil {
		return errWorkerProbeUnavailable
	}
	request.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout:       workerProbeTimeout,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errWorkerProbeUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	var result struct {
		Data struct{ Status string }  `json:"data"`
		Meta struct{ Process string } `json:"meta"`
	}
	if err != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Data.Status != "ok" || result.Meta.Process != "worker" {
		return errWorkerProbeUnavailable
	}
	return ctx.Err()
}

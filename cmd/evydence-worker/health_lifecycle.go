package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/platform/health"
	"github.com/aatuh/evydence/internal/platform/logging"
)

var errWorkerProbeDrainTimeout = errors.New("worker probe shutdown deadline exceeded; process exit is required")

type workerMetricsEndpoint struct {
	listener net.Listener
	handler  http.Handler
}

// runWorkerWithHealth owns the lifecycle listener, optional metrics listener,
// serving goroutines and work loop. It publishes draining before cancelling
// the work root. Both HTTP servers share one shutdown budget. The native
// worker loop retains ownership of admitted jobs and their drain deadlines.
func runWorkerWithHealth(ctx context.Context, listener net.Listener, monitor *health.Monitor, shutdownTimeout time.Duration, work func(context.Context) error, metrics ...workerMetricsEndpoint) error {
	closeListeners := func() error {
		var result error
		if !missingWorkerPort(listener) {
			result = listener.Close()
		}
		for _, endpoint := range metrics {
			if !missingWorkerPort(endpoint.listener) {
				result = errors.Join(result, endpoint.listener.Close())
			}
		}
		return result
	}
	validMetrics := len(metrics) <= 1
	for _, endpoint := range metrics {
		validMetrics = validMetrics && !missingWorkerPort(endpoint.listener) && !missingWorkerPort(endpoint.handler)
	}
	if ctx == nil || missingWorkerPort(listener) || monitor == nil || shutdownTimeout <= 0 || work == nil || !validMetrics {
		return errors.Join(errors.New("worker probes require context, listener, monitor, shutdown budget, work loop and valid optional metrics endpoint"), closeListeners())
	}
	if ctx.Err() != nil {
		monitor.MarkDraining()
		closeErr := closeListeners()
		if errors.Is(ctx.Err(), context.Canceled) {
			return closeErr
		}
		return errors.Join(ctx.Err(), closeErr)
	}
	newServer := func(handler http.Handler) *http.Server {
		return &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       workerProbeTimeout,
			WriteTimeout:      workerProbeTimeout,
			IdleTimeout:       workerProbeTimeout,
			MaxHeaderBytes:    4096,
			ErrorLog:          log.New(logging.DiagnosticWriter(ctx), "", 0),
			BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		}
	}
	servers := []struct {
		listener net.Listener
		server   *http.Server
	}{{listener, newServer(newWorkerHealthHandler(monitor))}}
	for _, endpoint := range metrics {
		servers = append(servers, struct {
			listener net.Listener
			server   *http.Server
		}{endpoint.listener, newServer(endpoint.handler)})
	}
	// Cancellation is owned here so the monitor changes state before the loop
	// observes cancellation; values, including log correlation, are preserved.
	workCtx, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	served, worked := make(chan error, len(servers)), make(chan error, 1)
	for _, owned := range servers {
		go func() { served <- owned.server.Serve(owned.listener) }()
	}
	go func() { worked <- work(workCtx) }()
	var serveErr, workErr error
	serveFinished, workFinished := 0, false
	collectServe := func(result error) {
		serveFinished++
		if !errors.Is(result, http.ErrServerClosed) {
			serveErr = errors.Join(serveErr, result)
		}
	}
	select {
	case result := <-served:
		collectServe(result)
	case workErr = <-worked:
		workFinished = true
	case <-ctx.Done():
	}
	monitor.MarkDraining()
	cancelWork()
	// HTTP shutdown overlaps the native job drain instead of adding another
	// sequential budget to the daemon's termination grace period.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancelShutdown()
	shutdownResults := make(chan error, len(servers))
	for _, owned := range servers {
		go func() {
			err := owned.server.Shutdown(shutdownCtx)
			if err != nil {
				err = errors.Join(errWorkerProbeDrainTimeout, err, owned.server.Close())
			}
			shutdownResults <- err
		}()
	}
	var shutdownErr error
	for range servers {
		shutdownErr = errors.Join(shutdownErr, <-shutdownResults)
	}
	cancelShutdown()
	for serveFinished < len(servers) {
		collectServe(<-served)
	}
	if !workFinished {
		workErr = <-worked
	}
	var stopErr error
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled) {
		stopErr = ctx.Err()
	}
	return errors.Join(serveErr, workErr, shutdownErr, stopErr)
}

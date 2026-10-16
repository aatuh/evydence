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

// runWorkerWithHealth owns the supplied listener, serving goroutine and work
// loop. It publishes draining before cancelling the work root. The native
// worker loop retains ownership of admitted jobs and their drain deadlines.
func runWorkerWithHealth(ctx context.Context, listener net.Listener, monitor *health.Monitor, shutdownTimeout time.Duration, work func(context.Context) error) error {
	if ctx == nil || missingWorkerPort(listener) || monitor == nil || shutdownTimeout <= 0 || work == nil {
		if !missingWorkerPort(listener) {
			_ = listener.Close()
		}
		return errors.New("worker probes require context, listener, monitor, shutdown budget and work loop")
	}
	if ctx.Err() != nil {
		monitor.MarkDraining()
		closeErr := listener.Close()
		if errors.Is(ctx.Err(), context.Canceled) {
			return closeErr
		}
		return errors.Join(ctx.Err(), closeErr)
	}
	server := &http.Server{
		Handler:           newWorkerHealthHandler(monitor),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       workerProbeTimeout,
		WriteTimeout:      workerProbeTimeout,
		IdleTimeout:       workerProbeTimeout,
		MaxHeaderBytes:    4096,
		ErrorLog:          log.New(logging.DiagnosticWriter(ctx), "", 0),
	}
	// Cancellation is owned here so the monitor changes state before the loop
	// observes cancellation; values, including log correlation, are preserved.
	workCtx, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	served, worked := make(chan error, 1), make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	go func() { worked <- work(workCtx) }()
	var serveErr, workErr error
	serveFinished, workFinished := false, false
	select {
	case serveErr = <-served:
		serveFinished = true
	case workErr = <-worked:
		workFinished = true
	case <-ctx.Done():
	}
	monitor.MarkDraining()
	cancelWork()
	// HTTP shutdown overlaps the native job drain instead of adding another
	// sequential budget to the daemon's termination grace period.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancelShutdown()
	if shutdownErr != nil {
		shutdownErr = errors.Join(errWorkerProbeDrainTimeout, shutdownErr, server.Close())
	}
	if !serveFinished {
		serveErr = <-served
	}
	if !workFinished {
		workErr = <-worked
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	var stopErr error
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled) {
		stopErr = ctx.Err()
	}
	return errors.Join(serveErr, workErr, shutdownErr, stopErr)
}

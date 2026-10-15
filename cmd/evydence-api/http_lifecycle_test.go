package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errDrainTestAccept = errors.New("injected permanent accept failure")

type drainTestListener struct {
	net.Listener
	closed     chan struct{}
	fail       chan struct{}
	accepted   atomic.Bool
	once       sync.Once
	closeErr   error
	closeCalls atomic.Int32
	failure    error
}

func (l *drainTestListener) Accept() (net.Conn, error) {
	if l.fail != nil && l.accepted.Swap(true) {
		select {
		case <-l.fail:
			if l.failure != nil {
				return nil, l.failure
			}
			return nil, errDrainTestAccept
		case <-l.closed:
			return nil, net.ErrClosed
		}
	}
	return l.Listener.Accept()
}
func (l *drainTestListener) Close() error {
	l.closeCalls.Add(1)
	l.once.Do(func() { l.closeErr = l.Listener.Close(); close(l.closed) })
	return l.closeErr
}

type httpDrainFixture struct {
	listener                    *drainTestListener
	server                      *http.Server
	cancel                      context.CancelFunc
	draining, release, finished chan struct{}
	entered                     chan context.Context
	done                        chan error
	response                    chan struct {
		status int
		body   string
		err    error
	}
	client      *http.Client
	releaseOnce sync.Once
	commits     atomic.Int32
}

func startHTTPDrainFixture(t *testing.T, timeout time.Duration, failAccept bool) *httpDrainFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &httpDrainFixture{
		listener: &drainTestListener{Listener: listener, closed: make(chan struct{})},
		draining: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{}),
		entered: make(chan context.Context, 1), done: make(chan error, 1),
		response: make(chan struct {
			status int
			body   string
			err    error
		}, 1),
		client: &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second},
	}
	if failAccept {
		f.listener.fail = make(chan struct{})
	}
	f.server = newHTTPServer(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(f.finished)
		f.entered <- r.Context()
		select {
		case <-f.release:
			if r.Context().Err() != nil {
				return
			}
			f.commits.Add(1)
			_, _ = io.WriteString(w, "committed")
		case <-r.Context().Done():
		}
	}), httpRuntimeConfig{})
	f.server.RegisterOnShutdown(func() { close(f.draining) })
	ctx, cancel := context.WithCancel(t.Context())
	f.cancel = cancel
	go func() { f.done <- serveHTTPOnListener(ctx, f.server, f.listener, timeout) }()
	go func() {
		response, err := f.client.Get("http://" + listener.Addr().String() + "/transaction")
		var status int
		var body string
		if err == nil {
			status = response.StatusCode
			data, readErr := io.ReadAll(response.Body)
			err = errors.Join(readErr, response.Body.Close())
			body = string(data)
		}
		f.response <- struct {
			status int
			body   string
			err    error
		}{status, body, err}
	}()
	t.Cleanup(func() {
		f.finish()
		cancel()
		_ = f.server.Close()
		f.client.CloseIdleConnections()
	})
	return f
}

func (f *httpDrainFixture) finish() { f.releaseOnce.Do(func() { close(f.release) }) }
func awaitHTTPDrainEvent[T any](t *testing.T, event <-chan T) T {
	t.Helper()
	select {
	case value := <-event:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP lifecycle event did not occur")
		var zero T
		return zero
	}
}

func TestHTTPDrainActiveRequestCompletesAndRejectsNewWork(t *testing.T) {
	f := startHTTPDrainFixture(t, time.Second, false)
	requestCtx := awaitHTTPDrainEvent(t, f.entered)
	f.cancel()
	awaitHTTPDrainEvent(t, f.draining)
	awaitHTTPDrainEvent(t, f.listener.closed)
	if requestCtx.Err() != nil {
		t.Fatal("signal canceled admitted request before drain completed")
	}
	select {
	case err := <-f.done:
		t.Fatal("server returned with active work", err)
	default:
	}
	conn, err := net.DialTimeout("tcp", f.listener.Addr().String(), time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("new connection accepted during drain")
	}
	f.finish()
	response := awaitHTTPDrainEvent(t, f.response)
	if response.err != nil || response.status != http.StatusOK || response.body != "committed" {
		t.Fatal("admitted request lost its response", response)
	}
	if err := awaitHTTPDrainEvent(t, f.done); err != nil {
		t.Fatal("graceful stop failed", err)
	}
	if f.commits.Load() != 1 {
		t.Fatal("request effect did not complete once")
	}
	if f.listener.closeCalls.Load() != 1 {
		t.Fatal("listener ownership did not close once", f.listener.closeCalls.Load())
	}
}

func TestHTTPDrainDeadlineCancelsRequestAndReturnsFailure(t *testing.T) {
	f := startHTTPDrainFixture(t, 25*time.Millisecond, false)
	requestCtx := awaitHTTPDrainEvent(t, f.entered)
	f.cancel()
	if err := awaitHTTPDrainEvent(t, f.done); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errAPIForcedDrain) {
		t.Fatal("deadline not reported as failure", err)
	}
	awaitHTTPDrainEvent(t, f.finished)
	if requestCtx.Err() == nil || f.commits.Load() != 0 {
		t.Fatal("forced shutdown failed to cancel unfinished work")
	}
	if response := awaitHTTPDrainEvent(t, f.response); response.err == nil {
		t.Fatal("forced request falsely received success", response)
	}
}

func TestHTTPDrainServeFailureWaitsForAdmittedRequest(t *testing.T) {
	f := startHTTPDrainFixture(t, time.Second, true)
	requestCtx := awaitHTTPDrainEvent(t, f.entered)
	close(f.listener.fail)
	select {
	case <-f.draining:
	case err := <-f.done:
		t.Fatal("serve failure returned without draining active request", err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve failure did not start drain")
	}
	if requestCtx.Err() != nil {
		t.Fatal("serve failure canceled active request before deadline")
	}
	select {
	case err := <-f.done:
		t.Fatal("serve failure returned before active work completed", err)
	default:
	}
	f.finish()
	if response := awaitHTTPDrainEvent(t, f.response); response.err != nil || response.body != "committed" {
		t.Fatal("request failed during serve-error drain", response)
	}
	if err := awaitHTTPDrainEvent(t, f.done); !errors.Is(err, errDrainTestAccept) {
		t.Fatal("serve failure was hidden", err)
	}
	if f.commits.Load() != 1 {
		t.Fatal("admitted work was not completed once")
	}
}

func TestHTTPDrainServeFailureAlsoBoundsUnfinishedRequest(t *testing.T) {
	f := startHTTPDrainFixture(t, 25*time.Millisecond, true)
	requestCtx := awaitHTTPDrainEvent(t, f.entered)
	close(f.listener.fail)
	err := awaitHTTPDrainEvent(t, f.done)
	if !errors.Is(err, errDrainTestAccept) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("serve or drain failure was hidden", err)
	}
	awaitHTTPDrainEvent(t, f.finished)
	if requestCtx.Err() == nil || f.commits.Load() != 0 {
		t.Fatal("serve-error deadline left unfinished work running")
	}
	if response := awaitHTTPDrainEvent(t, f.response); response.err == nil {
		t.Fatal("unfinished work returned success", response)
	}
}

func TestHTTPDrainRootDeadlineIsNotNormalShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler(), httpRuntimeConfig{})
	if err = serveHTTPOnListener(ctx, server, listener, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired root was silently reported healthy", err)
	}
}

func TestHTTPDrainInvalidInputsCloseOwnedListener(t *testing.T) {
	for _, missing := range []string{"context", "server", "listener"} {
		t.Run(missing, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx := t.Context()
			server := &http.Server{ReadHeaderTimeout: time.Second}
			owned := listener
			switch missing {
			case "context":
				ctx = nil
			case "server":
				server = nil
			case "listener":
				owned = nil
			}
			if err = serveHTTPOnListener(ctx, server, owned, time.Second); err == nil || !strings.Contains(err.Error(), "required") {
				t.Fatal("missing dependency accepted", err)
			}
			if owned != nil {
				conn, dialErr := net.DialTimeout("tcp", listener.Addr().String(), 100*time.Millisecond)
				if dialErr == nil {
					_ = conn.Close()
					t.Fatal("owned listener leaked on startup failure")
				}
			}
		})
	}
}

func TestHTTPDrainClosesIdleKeepAliveConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	idle := make(chan struct{})
	var once sync.Once
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler(), httpRuntimeConfig{})
	server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateIdle {
			once.Do(func() { close(idle) })
		}
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- serveHTTPOnListener(ctx, server, listener, time.Second) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	awaitHTTPDrainEvent(t, idle)
	cancel()
	if err = awaitHTTPDrainEvent(t, done); err != nil {
		t.Fatal("idle shutdown failed", err)
	}
	if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err = conn.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatal("idle connection was not closed", err)
	}
}

func TestHTTPDrainAlreadyClosedServerIsNormal(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newHTTPServer(listener.Addr().String(), http.NotFoundHandler(), httpRuntimeConfig{})
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	owned := &drainTestListener{Listener: listener, closed: make(chan struct{})}
	if err = serveHTTPOnListener(t.Context(), server, owned, time.Second); err != nil {
		t.Fatal("ErrServerClosed was not normal", err)
	}
	awaitHTTPDrainEvent(t, owned.closed)
	if owned.closeCalls.Load() != 1 {
		t.Fatal("closed server leaked or double-closed listener")
	}
}

func TestHTTPDrainStatusOmitsRawFailureDetails(t *testing.T) {
	var diagnostics bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&diagnostics)
	defer log.SetOutput(previous)
	f := startHTTPDrainFixture(t, time.Second, true)
	awaitHTTPDrainEvent(t, f.entered)
	const secret = "raw-provider-error-private-canary"
	// Accept waits on this channel. Closing it publishes the injected error
	// before the listener reads it, without racing the running server.
	f.listener.failure = errors.New(secret)
	close(f.listener.fail)
	select {
	case <-f.draining:
	case err := <-f.done:
		t.Fatal("drain did not start", err)
	case <-time.After(5 * time.Second):
		t.Fatal("missing drain status")
	}
	f.finish()
	if err := awaitHTTPDrainEvent(t, f.done); err == nil {
		t.Fatal("serve failure lost")
	}
	awaitHTTPDrainEvent(t, f.response)
	if output := diagnostics.String(); strings.Contains(output, secret) || !strings.Contains(output, "API drain started") || !strings.Contains(output, "API drain completed") {
		t.Fatal("unsafe or missing lifecycle diagnostics", output)
	}
}

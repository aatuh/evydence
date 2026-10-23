package logging

import (
	"context"
	"io"
	"regexp"
	"time"

	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type loggerKey struct{}
type correlationKey struct{}

// Correlation contains only validated opaque log references. Persist these in
// dedicated operational columns, never in hashed evidence or provider payloads.
type Correlation struct{ RequestID, OperationID string }

var referencePattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func WithLogger(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}
func FromContext(ctx context.Context) *Logger {
	if ctx == nil {
		return nil
	}
	l, _ := ctx.Value(loggerKey{}).(*Logger)
	return l
}
func CorrelationFromContext(ctx context.Context) Correlation {
	if ctx == nil {
		return Correlation{}
	}
	c, _ := ctx.Value(correlationKey{}).(Correlation)
	return c
}
func WithCorrelation(ctx context.Context, c Correlation) context.Context {
	if !referencePattern.MatchString(c.RequestID) {
		c.RequestID = ""
	}
	if !referencePattern.MatchString(c.OperationID) {
		c.OperationID = ""
	}
	return context.WithValue(ctx, correlationKey{}, c)
}
func WithRequest(ctx context.Context, id string) context.Context {
	c := CorrelationFromContext(ctx)
	c.RequestID = Reference("request", id)
	return WithCorrelation(ctx, c)
}
func WithOperation(ctx context.Context, id string) context.Context {
	c := CorrelationFromContext(ctx)
	c.OperationID = Reference("operation", id)
	return WithCorrelation(ctx, c)
}
func Emit(ctx context.Context, event Event, f Fields) { FromContext(ctx).Log(ctx, event, f) }

// RunConfigured runs a process with explicitly supplied logging options. It
// consults no environment reader; callers can validate captured configuration
// before emitting startup records or entering the operation.
func RunConfigured(ctx context.Context, service string, identity runtimeinfo.Identity, output io.Writer, config Config, run func(context.Context) error) error {
	logger, err := New(output, service, identity, config)
	if err != nil {
		return rejectSetup(ctx, service, identity, output, err)
	}
	ctx = WithLogger(ctx, logger)
	start := time.Now()
	logger.Log(ctx, Startup, Fields{Result: Started})
	err = run(ctx)
	result := Succeeded
	if err != nil {
		result = Failed
	}
	logger.Log(ctx, Shutdown, Fields{Duration: time.Since(start), Result: result})
	return err
}

func rejectSetup(ctx context.Context, service string, identity runtimeinfo.Identity, output io.Writer, err error) error {
	RejectStartup(ctx, service, identity, output)
	return err
}

// RejectStartup emits one fixed JSON rejection record before an operation has
// started. It accepts no error or configuration payload that could enter logs.
func RejectStartup(ctx context.Context, service string, identity runtimeinfo.Identity, output io.Writer) {
	fallback, _ := New(output, service, identity, Config{})
	fallback.Log(ctx, Startup, Fields{Result: Rejected})
}

// DiagnosticWriter adapts standard-library internal diagnostics. net/http may
// supply panic values, URLs and stack traces, so the bytes are discarded and
// only a fixed failure event is emitted.
func DiagnosticWriter(ctx context.Context) io.Writer { return diagnosticWriter{ctx} }

type diagnosticWriter struct{ ctx context.Context }

func (w diagnosticWriter) Write(p []byte) (int, error) {
	Emit(w.ctx, HTTPRequest, Fields{Result: Uncertain})
	return len(p), nil
}

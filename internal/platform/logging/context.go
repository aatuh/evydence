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

// Run validates configuration before invoking the process. Failed setup uses a
// fixed JSON record; arbitrary errors never become log messages or attributes.
// The caller retains the original error and exit-code decision.
func Run(ctx context.Context, service string, identity runtimeinfo.Identity, output io.Writer, getenv func(string) string, run func(context.Context) error) error {
	config, err := ConfigFromEnv(getenv)
	if err != nil {
		fallback, _ := New(output, service, identity, Config{})
		fallback.Log(ctx, Startup, Fields{Result: Rejected})
		return err
	}
	logger, err := New(output, service, identity, config)
	if err != nil {
		return err
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

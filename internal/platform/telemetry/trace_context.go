package telemetry

import "context"

// TraceContext is an SDK-independent operational carrier for internally created
// trace identifiers. It has no baggage, identity, URL, attribute or trace-state
// fields. Keep it out of evidence, audit hashes, deduplication and backup models.
// The zero value represents a job created without tracing.
type TraceContext struct {
	traceID string
	spanID  string
	sampled bool
}

// NewTraceContext accepts only canonical identifiers produced by the owned
// tracing adapter or read from dedicated operational columns. It is not an
// incoming HTTP-header parser and must not be used to trust caller trace input.
func NewTraceContext(traceID, spanID string, sampled bool) (TraceContext, bool) {
	if !canonicalTraceIdentifier(traceID, 32) || !canonicalTraceIdentifier(spanID, 16) {
		return TraceContext{}, false
	}
	return TraceContext{traceID: traceID, spanID: spanID, sampled: sampled}, true
}

func canonicalTraceIdentifier(value string, length int) bool {
	if len(value) != length {
		return false
	}
	nonzero := false
	for i := range len(value) {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}

func (c TraceContext) Valid() bool {
	return canonicalTraceIdentifier(c.traceID, 32) && canonicalTraceIdentifier(c.spanID, 16)
}

// Identifier access is explicit; ordinary formatting and JSON omit the values.
func (c TraceContext) TraceID() string { return c.traceID }
func (c TraceContext) SpanID() string  { return c.spanID }
func (c TraceContext) Sampled() bool   { return c.sampled }
func (TraceContext) String() string    { return "trace context" }
func (TraceContext) GoString() string  { return "telemetry.TraceContext{}" }

// MarshalJSON deliberately omits identifiers even when the carrier is embedded
// in a diagnostic struct. Persistence must use the explicit identifier methods.
func (TraceContext) MarshalJSON() ([]byte, error) { return []byte(`"trace context"`), nil }

type traceContextKey struct{}

// WithTraceContext preserves cancellation and unrelated values. An empty or
// invalid carrier deliberately shadows any previous job's operational context.
func WithTraceContext(ctx context.Context, carrier TraceContext) context.Context {
	if !carrier.Valid() {
		carrier = TraceContext{}
	}
	return context.WithValue(ctx, traceContextKey{}, carrier)
}

func TraceContextFromContext(ctx context.Context) TraceContext {
	if ctx == nil {
		return TraceContext{}
	}
	carrier, _ := ctx.Value(traceContextKey{}).(TraceContext)
	return carrier
}

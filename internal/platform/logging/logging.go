// Package logging emits a fixed operational schema through slog. There is no
// free-form message, error, attribute, body or credential parameter. Untrusted
// identifiers become domain-separated references before reaching the handler.
package logging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/runtimeinfo"
)

type Config struct{ Level, Format string }

// ConfigFromEnv validates values without including operator input in errors.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, errors.New("logging environment reader is required")
	}
	c := Config{Level: getenv("EVYDENCE_LOG_LEVEL"), Format: getenv("EVYDENCE_LOG_FORMAT")}
	_, _, err := c.options()
	return c, err
}

func (c Config) options() (slog.Level, string, error) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(c.Level)) {
	case "", "info":
		level = slog.LevelInfo
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return 0, "", errors.New("EVYDENCE_LOG_LEVEL must be debug, info, warn or error")
	}
	format := strings.ToLower(strings.TrimSpace(c.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" {
		return 0, "", errors.New("EVYDENCE_LOG_FORMAT must be json or text")
	}
	return level, format, nil
}

type Event uint8

const (
	Startup Event = iota
	Shutdown
	HTTPRequest
	Command
	Outbox
	Provider
	Audit
	Bootstrap
	Drain
	Cleanup
)

var eventNames = [...]string{"startup", "shutdown", "http_request", "command", "outbox", "provider", "audit", "bootstrap", "drain", "cleanup"}

type Result uint8

const (
	Started Result = iota
	Succeeded
	Rejected
	Failed
	Uncertain
)

var resultNames = [...]string{"started", "succeeded", "rejected", "failed", "uncertain"}

type RetryClass uint8

const (
	NoRetry RetryClass = iota
	Transient
	Permanent
	Poisoned
)

var retryNames = [...]string{"none", "transient", "permanent", "poisoned"}

// Fields deliberately contains no error, arbitrary attributes or raw payload.
// All string fields are references, never rendered verbatim. Empty fields stay
// empty so operators can distinguish absent correlation from a real reference.
type Fields struct {
	RequestID, TenantID, ResourceID, JobID, ReceiptID, OperationID string
	Duration                                                       time.Duration
	Status, Attempt                                                int
	Result                                                         Result
	Retry                                                          RetryClass
}

type Logger struct{ logger *slog.Logger }

var (
	versionPattern = regexp.MustCompile(`^(dev|unknown|v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`)
	commitPattern  = regexp.MustCompile(`^(unknown|[0-9a-f]{7,64})$`)
	goPattern      = regexp.MustCompile(`^(unknown|go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:rc[0-9]+|beta[0-9]+)?)$`)
	digestPattern  = regexp.MustCompile(`^(unknown|sha256:[0-9a-f]{64})$`)
)

func buildField(value string, pattern *regexp.Regexp) string {
	if len(value) > 128 || !pattern.MatchString(value) {
		return "unknown"
	}
	return value
}

// New owns neither the output writer nor its lifetime. slog serializes writes
// for this logger. Process-owned build metadata is validated independently of
// request data; supported release metadata is retained exactly.
func New(output io.Writer, service string, identity runtimeinfo.Identity, config Config) (*Logger, error) {
	level, format, err := config.options()
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, errors.New("logging output is required")
	}
	if service != "api" && service != "worker" && service != "migrate" && service != "cli" {
		return nil, errors.New("unsupported logging service")
	}
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(output, options)
	} else {
		handler = slog.NewTextHandler(output, options)
	}
	buildTime := identity.BuildTime
	if _, err := time.Parse(time.RFC3339Nano, buildTime); err != nil {
		buildTime = "unknown"
	}
	logger := slog.New(handler).With("service", service,
		"version", buildField(identity.Version, versionPattern), "commit", buildField(identity.Commit, commitPattern),
		"build_time", buildTime, "dirty", identity.Dirty, "go_version", buildField(identity.GoVersion, goPattern),
		"release_manifest_digest", buildField(identity.ReleaseManifestDigest, digestPattern))
	return &Logger{logger: logger}, nil
}

// Reference is a stable SHA-256 reference for joining operational records with
// authorized durable IDs. It is not encryption, anonymization or authorization.
func Reference(kind, value string) string {
	if value == "" {
		return ""
	}
	if len(value) > 4096 {
		return "invalid"
	}
	sum := sha256.Sum256([]byte("evydence-log.v1\x00" + kind + "\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (l *Logger) Log(ctx context.Context, event Event, f Fields) {
	if l == nil || int(event) >= len(eventNames) {
		return
	}
	result := "unknown"
	if int(f.Result) < len(resultNames) {
		result = resultNames[f.Result]
	}
	retry := "unknown"
	if int(f.Retry) < len(retryNames) {
		retry = retryNames[f.Retry]
	}
	level := slog.LevelInfo
	switch f.Result {
	case Rejected:
		level = slog.LevelWarn
	case Failed, Uncertain:
		level = slog.LevelError
	}
	if f.Duration < 0 {
		f.Duration = 0
	}
	if f.Status < 100 || f.Status > 599 {
		f.Status = 0
	}
	if f.Attempt < 0 {
		f.Attempt = 0
	}
	c := CorrelationFromContext(ctx)
	if f.RequestID != "" {
		c.RequestID = Reference("request", f.RequestID)
	}
	if f.OperationID != "" {
		c.OperationID = Reference("operation", f.OperationID)
	}
	l.logger.Log(ctx, level, eventNames[event],
		"request_id", c.RequestID, "tenant_id", Reference("tenant", f.TenantID),
		"resource_id", Reference("resource", f.ResourceID), "job_id", Reference("job", f.JobID),
		"receipt_id", Reference("receipt", f.ReceiptID), "operation_id", c.OperationID,
		"duration_ms", float64(f.Duration)/float64(time.Millisecond), "status", f.Status, "attempt", f.Attempt,
		"result_code", result, "retry_class", retry)
}

package config

import (
	"net/netip"
	"time"
)

// WorkerSettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type WorkerSettings struct {
	redactedValue
	ParserReplayTimeout   time.Duration  `env:"EVYDENCE_PARSER_REPLAY_TIMEOUT"`
	ReconciliationTimeout time.Duration  `env:"EVYDENCE_RECONCILIATION_TIMEOUT"`
	BatchSize             int64          `env:"EVYDENCE_WORKER_BATCH_SIZE"`
	HealthAddress         netip.AddrPort `env:"EVYDENCE_WORKER_HEALTH_ADDR"`
	MaxPayloadBytes       int64          `env:"EVYDENCE_WORKER_MAX_PAYLOAD_BYTES"`
	MetricsAddress        netip.AddrPort `env:"EVYDENCE_WORKER_METRICS_ADDR"`
	MetricsTokenFile      string         `env:"EVYDENCE_WORKER_METRICS_TOKEN_FILE"`
	PollInterval          time.Duration  `env:"EVYDENCE_WORKER_POLL_INTERVAL"`
	ShutdownTimeout       time.Duration  `env:"EVYDENCE_WORKER_SHUTDOWN_TIMEOUT_SECONDS"`
}

package config

import (
	"net/netip"
	"slices"
	"time"
)

// APISettings is a value copy. Slice accessors return owned copies.
// Formatting and JSON redact the entire settings value.
type APISettings struct {
	redactedValue
	Address                          string         `env:"EVYDENCE_ADDR"`
	KeyPepper                        Secret         `env:"EVYDENCE_API_KEY_PEPPER"`
	WriterMode                       string         `env:"EVYDENCE_API_WRITER_MODE"`
	WriterReplicas                   int64          `env:"EVYDENCE_API_WRITER_REPLICAS"`
	AuthFailuresPerMinute            int64          `env:"EVYDENCE_AUTH_FAILURES_PER_MINUTE"`
	BootstrapDisabled                bool           `env:"EVYDENCE_BOOTSTRAP_DISABLED"`
	BootstrapTenant                  string         `env:"EVYDENCE_BOOTSTRAP_TENANT"`
	ExpensiveTenantRequestsPerMinute int64          `env:"EVYDENCE_EXPENSIVE_TENANT_REQUESTS_PER_MINUTE"`
	HTTPIdleTimeout                  time.Duration  `env:"EVYDENCE_HTTP_IDLE_TIMEOUT_SECONDS"`
	HTTPMaxConcurrentUploads         int64          `env:"EVYDENCE_HTTP_MAX_CONCURRENT_UPLOADS"`
	HTTPMaxHeaderBytes               int64          `env:"EVYDENCE_HTTP_MAX_HEADER_BYTES"`
	HTTPMaxInFlightRequests          int64          `env:"EVYDENCE_HTTP_MAX_IN_FLIGHT_REQUESTS"`
	HTTPMaxURLBytes                  int64          `env:"EVYDENCE_HTTP_MAX_URL_BYTES"`
	HTTPReadHeaderTimeout            time.Duration  `env:"EVYDENCE_HTTP_READ_HEADER_TIMEOUT_SECONDS"`
	HTTPReadTimeout                  time.Duration  `env:"EVYDENCE_HTTP_READ_TIMEOUT_SECONDS"`
	HTTPShutdownTimeout              time.Duration  `env:"EVYDENCE_HTTP_SHUTDOWN_TIMEOUT_SECONDS"`
	HTTPWriteTimeout                 time.Duration  `env:"EVYDENCE_HTTP_WRITE_TIMEOUT_SECONDS"`
	PrintBootstrapSecret             bool           `env:"EVYDENCE_PRINT_BOOTSTRAP_SECRET"`
	RateLimitBucketCapacity          int64          `env:"EVYDENCE_RATE_LIMIT_BUCKET_CAPACITY"`
	RateLimitRequestsPerMinute       int64          `env:"EVYDENCE_RATE_LIMIT_REQUESTS_PER_MINUTE"`
	SSOSessionIdleTimeout            time.Duration  `env:"EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS"`
	SSOSessionMaxLifetime            time.Duration  `env:"EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS"`
	trustedProxyCIDRs                []netip.Prefix `env:"EVYDENCE_TRUSTED_PROXY_CIDRS"`
	WorkerOwnedParserSideEffects     bool           `env:"EVYDENCE_WORKER_OWNED_PARSER_SIDE_EFFECTS"`
}

func (s APISettings) TrustedProxyCIDRs() []netip.Prefix {
	return slices.Clone(s.trustedProxyCIDRs)
}

package main

import (
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/config"
)

type httpRuntimeConfig struct {
	ReadHeaderTimeout                time.Duration
	ReadTimeout                      time.Duration
	WriteTimeout                     time.Duration
	IdleTimeout                      time.Duration
	ShutdownTimeout                  time.Duration
	MaxHeaderBytes                   int
	MaxURLBytes                      int
	MaxInboundRequestBytes           int64
	MaxInFlightRequests              int
	MaxConcurrentUploads             int
	RateLimitRequestsPerMinute       int
	AuthenticationFailuresPerMinute  int
	ExpensiveTenantRequestsPerMinute int
	RateLimitBucketCapacity          int
	TrustedProxyCIDRs                []string
}

// Shared preflight owns defaults, bounds and CIDR validation. This projection
// only adapts those typed values to the server's existing operational controls.
func httpRuntimeConfigFromSettings(settings config.APISettings) httpRuntimeConfig {
	prefixes := settings.TrustedProxyCIDRs()
	var trusted []string
	if len(prefixes) != 0 {
		trusted = make([]string, len(prefixes))
		for i, prefix := range prefixes {
			trusted[i] = prefix.String()
		}
	}
	return httpRuntimeConfig{
		ReadHeaderTimeout: settings.HTTPReadHeaderTimeout, ReadTimeout: settings.HTTPReadTimeout,
		WriteTimeout: settings.HTTPWriteTimeout, IdleTimeout: settings.HTTPIdleTimeout, ShutdownTimeout: settings.HTTPShutdownTimeout,
		MaxHeaderBytes: int(settings.HTTPMaxHeaderBytes), MaxURLBytes: int(settings.HTTPMaxURLBytes),
		MaxInboundRequestBytes: app.EvidenceDocumentLimit, MaxInFlightRequests: int(settings.HTTPMaxInFlightRequests),
		MaxConcurrentUploads: int(settings.HTTPMaxConcurrentUploads), RateLimitRequestsPerMinute: int(settings.RateLimitRequestsPerMinute),
		AuthenticationFailuresPerMinute: int(settings.AuthFailuresPerMinute), ExpensiveTenantRequestsPerMinute: int(settings.ExpensiveTenantRequestsPerMinute),
		RateLimitBucketCapacity: int(settings.RateLimitBucketCapacity), TrustedProxyCIDRs: trusted,
	}
}

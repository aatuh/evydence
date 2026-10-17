package main

import (
	"crypto/sha256"
	"errors"
	"net/netip"

	"github.com/aatuh/evydence/internal/platform/config"
)

var errWorkerMetricsConfig = errors.New("worker metrics require a private literal bind and a private metrics-only credential file")

type workerMetricsConfig struct {
	enabled   bool
	address   netip.AddrPort
	tokenHash [sha256.Size]byte
}

func workerMetricsConfigFromSettings(settings config.Configuration) (workerMetricsConfig, error) {
	hash, enabled := settings.WorkerMetricsTokenHash()
	address := settings.Worker().MetricsAddress
	if enabled != address.IsValid() {
		return workerMetricsConfig{}, errWorkerMetricsConfig
	}
	return workerMetricsConfig{enabled: enabled, address: address, tokenHash: hash}, nil
}

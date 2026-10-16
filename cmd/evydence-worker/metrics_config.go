package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

var errWorkerMetricsConfig = errors.New("worker metrics require a private literal bind and a private metrics-only credential file")

type workerMetricsConfig struct {
	enabled   bool
	address   netip.AddrPort
	tokenHash [sha256.Size]byte
}

func workerMetricsConfigFromEnv() (workerMetricsConfig, error) {
	var empty workerMetricsConfig
	address, file := os.Getenv("EVYDENCE_WORKER_METRICS_ADDR"), os.Getenv("EVYDENCE_WORKER_METRICS_TOKEN_FILE")
	if address == "" && file == "" {
		return empty, nil
	}
	if len(address) > 128 || len(file) > 4096 || file == "" || file != strings.TrimSpace(file) || !filepath.IsAbs(file) {
		return empty, errWorkerMetricsConfig
	}
	if address == "" {
		address = "127.0.0.1:9091"
	}
	bind, err := netip.ParseAddrPort(address)
	if err != nil || bind.Port() == 0 || bind.Addr().Zone() != "" || (!bind.Addr().Unmap().IsLoopback() && !bind.Addr().Unmap().IsPrivate()) {
		return empty, errWorkerMetricsConfig
	}
	root, err := os.OpenRoot(filepath.Dir(file))
	if err != nil {
		return empty, errWorkerMetricsConfig
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(file)
	info, err := root.Stat(name)
	if err != nil || !validWorkerMetricsFile(info) {
		return empty, errWorkerMetricsConfig
	}
	secret, err := root.Open(name)
	if err != nil {
		return empty, errWorkerMetricsConfig
	}
	defer func() { _ = secret.Close() }()
	info, err = secret.Stat()
	if err != nil || !validWorkerMetricsFile(info) {
		return empty, errWorkerMetricsConfig
	}
	data, err := io.ReadAll(io.LimitReader(secret, 130))
	if err != nil {
		return empty, errWorkerMetricsConfig
	}
	token := strings.TrimSuffix(string(data), "\n")
	if !validWorkerMetricsToken(token) {
		return empty, errWorkerMetricsConfig
	}
	return workerMetricsConfig{enabled: true, address: bind, tokenHash: sha256.Sum256([]byte(token))}, nil
}

func validWorkerMetricsFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Size() <= 129 && info.Size() >= 75 && info.Mode().Perm()&0027 == 0
}

func validWorkerMetricsToken(token string) bool {
	const prefix = "evymetrics_"
	if len(token) != len(prefix)+64 || !strings.HasPrefix(token, prefix) {
		return false
	}
	suffix := token[len(prefix):]
	decoded, err := hex.DecodeString(suffix)
	return err == nil && hex.EncodeToString(decoded) == suffix
}

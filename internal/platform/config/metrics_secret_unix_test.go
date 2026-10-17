//go:build unix

package config

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestResolveWorkerMetricsCredentialRetainsOnlyHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "PRIVATE_METRICS")
	input, err := Prepare(roleEnvironment(t, Worker, true, "EVYDENCE_WORKER_METRICS_TOKEN_FILE="+path), Worker)
	if err != nil {
		t.Fatal("preflight opened the metrics file", err)
	}
	if cfg, err := Resolve(context.Background(), input, false); err != nil || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("disabled resolution opened a metrics file", err)
	}
	token := "evymetrics_" + strings.Repeat("a", 64)
	for _, suffix := range []string{"", "\n"} {
		writePrivateSecret(t, path, token+suffix)
		cfg, err := Resolve(context.Background(), input, true)
		if err != nil {
			t.Fatal(err)
		}
		hash, enabled := cfg.WorkerMetricsTokenHash()
		if !enabled || hash != sha256.Sum256([]byte(token)) || cfg.Worker().MetricsAddress.String() != "127.0.0.1:9091" {
			t.Fatal("metrics resolution changed the hash or listener contract")
		}
		encoded, err := json.Marshal(cfg)
		if err != nil || strings.Contains(string(encoded)+fmt.Sprintf("%v %#v", cfg, cfg), "PRIVATE") || strings.Contains(string(encoded)+fmt.Sprintf("%v %#v", cfg, cfg), token) {
			t.Fatal("metrics resolution disclosed a token or file path")
		}
		hash[0] ^= 0xff
		if owned, _ := cfg.WorkerMetricsTokenHash(); owned != sha256.Sum256([]byte(token)) {
			t.Fatal("returned hash aliases stored state")
		}
	}
	input, err = Prepare(roleEnvironment(t, Worker, true), Worker)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve(context.Background(), input, true)
	if hash, enabled := cfg.WorkerMetricsTokenHash(); err != nil || enabled || hash != [sha256.Size]byte{} {
		t.Fatal("unset metrics acquired credentials", err)
	}
}

func TestResolveWorkerMetricsRejectsMalformedAndUnsafeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_METRICS")
	input, err := Prepare(roleEnvironment(t, Worker, true, "EVYDENCE_WORKER_METRICS_TOKEN_FILE="+path), Worker)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "PRIVATE_VALUE", "evymetrics_" + strings.Repeat("A", 64), "evymetrics_" + strings.Repeat("a", 64) + "\n\n", "evymetrics_" + strings.Repeat("a", 130)} {
		writePrivateSecret(t, path, token)
		cfg, err := Resolve(context.Background(), input, true)
		if !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) || strings.Contains(fmt.Sprint(err), "PRIVATE") {
			t.Fatal("malformed metrics credential returned settings or unsafe diagnostics", err)
		}
	}
	writePrivateSecret(t, path, "evymetrics_"+strings.Repeat("a", 64))
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Resolve(context.Background(), input, true); !errors.Is(err, ErrSecretResolution) || !reflect.DeepEqual(cfg, Configuration{}) {
		t.Fatal("public metrics secret accepted", err)
	}
}

func TestPrepareRejectsNoncanonicalMetricsReferencesBeforeReading(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{dir + "/unused/../PRIVATE_TOKEN", dir + "/PRIVATE_TOKEN/"} {
		input, err := Prepare(roleEnvironment(t, Worker, true, "EVYDENCE_WORKER_METRICS_TOKEN_FILE="+path), Worker)
		if !errors.Is(err, ErrInvalidValue) || !reflect.DeepEqual(input, PreparedInput{}) {
			t.Fatal("noncanonical metrics reference passed preflight", err)
		}
	}
}

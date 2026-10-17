package config

import (
	"context"
	"crypto/sha256"
	"strings"
)

// resolveWorkerMetricsSecret preserves the metrics-only credential format and
// retains only its digest. The shared reader owns bounds, permissions and handles.
func resolveWorkerMetricsSecret(ctx context.Context, input parsedInput, remaining int) ([sha256.Size]byte, bool, error) {
	var empty [sha256.Size]byte
	file := input.values["EVYDENCE_WORKER_METRICS_TOKEN_FILE"].text
	if input.role != Worker || file == "" {
		return empty, false, nil
	}
	secret, err := readSecretFile(ctx, file, min(129, remaining))
	if err != nil {
		return empty, false, err
	}
	token := strings.TrimSuffix(secret.value, "\n")
	if !ValidWorkerMetricsToken(token) {
		return empty, false, ErrSecretResolution
	}
	return sha256.Sum256([]byte(token)), true, nil
}

// ValidWorkerMetricsToken validates the distinct metrics-only credential grammar.
// It performs no I/O and exposes neither the supplied token nor its hash.
func ValidWorkerMetricsToken(token string) bool {
	const prefix = "evymetrics_"
	if len(token) != len(prefix)+64 || !strings.HasPrefix(token, prefix) {
		return false
	}
	for _, c := range token[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

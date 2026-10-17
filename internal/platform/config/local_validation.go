package config

import (
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// validateLocalInput checks local combinations without resolving names, opening
// files or constructing providers. File metadata/content belong to resolution.
func validateLocalInput(input parsedInput) error {
	v := input.values
	if input.role == API || input.role == Worker {
		revision, file := v["EVYDENCE_CONFIGURATION_REVISION"].text, v["EVYDENCE_CONFIGURATION_REVISION_FILE"].text
		if (revision == "") != (file == "") || (file != "" && (!validRevision(revision) || !filepath.IsAbs(file))) {
			return ErrInvalidValue
		}
	}
	if input.role == API {
		if v["EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS"].duration > v["EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS"].duration ||
			strings.TrimSpace(v["EVYDENCE_BOOTSTRAP_TENANT"].text) == "" ||
			!validAPIAddress(v["EVYDENCE_ADDR"].text) {
			return ErrInvalidValue
		}
		// Characterizes identity/app.LocalDevelopmentPepper. EVY-1216 must
		// retire the duplicate startup policy when adopting this configuration.
		if input.production && (v["EVYDENCE_API_WRITER_REPLICAS"].integer != 1 || strings.TrimSpace(v["EVYDENCE_API_KEY_PEPPER"].text) == "local-dev-pepper-change-me") {
			return ErrUnsafeProduction
		}
	}
	if input.role == Worker {
		return validateWorkerListeners(input)
	}
	return nil
}

func validRevision(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	for _, c := range raw {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validAPIAddress(raw string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || port == "" || strings.ContainsAny(host, "/?#@\\") || strings.ContainsFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return err == nil
}

func validateWorkerListeners(input parsedInput) error {
	v := input.values
	health, err := netip.ParseAddrPort(strings.TrimSpace(v["EVYDENCE_WORKER_HEALTH_ADDR"].text))
	if err != nil || health.Port() == 0 || health.Addr().Zone() != "" || !health.Addr().Unmap().IsLoopback() {
		return ErrInvalidValue
	}
	address, file := v["EVYDENCE_WORKER_METRICS_ADDR"].text, v["EVYDENCE_WORKER_METRICS_TOKEN_FILE"].text
	if address == "" && file == "" {
		return nil
	}
	if !validSecretReferencePath(file) {
		return ErrInvalidValue
	}
	metrics, err := netip.ParseAddrPort(address)
	if err != nil || metrics.Port() == 0 || metrics.Addr().Zone() != "" || (!metrics.Addr().Unmap().IsLoopback() && !metrics.Addr().Unmap().IsPrivate()) {
		return ErrInvalidValue
	}
	if netip.AddrPortFrom(health.Addr().Unmap(), health.Port()) == netip.AddrPortFrom(metrics.Addr().Unmap(), metrics.Port()) {
		return ErrInvalidValue
	}
	return nil
}

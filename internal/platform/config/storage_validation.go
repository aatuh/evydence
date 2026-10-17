package config

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// ParseS3BucketName reuses the exact pinned SDK grammar used by BucketExists.
// Its validator is pure; underlying errors are discarded rather than exposed.
func ParseS3BucketName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if s3utils.CheckValidBucketName(name) != nil {
		return "", ErrInvalidValue
	}
	return name, nil
}

func validateStorageInput(input parsedInput) error {
	if input.role&runtimeRoles == 0 {
		return nil
	}
	v := input.values
	kind := v["EVYDENCE_OBJECT_STORE"].text
	endpoint := strings.TrimSpace(v["EVYDENCE_S3_ENDPOINT"].text)
	region := strings.TrimSpace(v["EVYDENCE_S3_REGION"].text)
	if kind == "s3" || kind == "minio" {
		for _, name := range []string{"EVYDENCE_S3_ENDPOINT", "EVYDENCE_S3_BUCKET", "EVYDENCE_S3_ACCESS_KEY_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY"} {
			if strings.TrimSpace(v[name].text) == "" && !input.deferred[name] {
				return ErrMissingValue
			}
		}
	}
	if region != "" && !validS3Region(region) {
		return ErrInvalidValue
	}
	if endpoint != "" {
		if _, _, err := ValidateS3Endpoint(endpoint, region, v["EVYDENCE_S3_USE_SSL"].boolean); err != nil {
			return err
		}
	}
	return nil
}

// ValidateS3Endpoint applies the adapter's authority, TLS and region policy
// without constructing a client or resolving a destination.
func ValidateS3Endpoint(endpoint, region string, useSSL bool) (string, string, error) {
	endpoint = strings.TrimSpace(endpoint)
	region = strings.TrimSpace(region)
	if !utf8.ValidString(endpoint) || !utf8.ValidString(region) || endpoint == "" || strings.Contains(endpoint, "://") || strings.ContainsAny(endpoint, "/?#") {
		return "", "", ErrInvalidValue
	}
	for _, r := range endpoint {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", "", ErrInvalidValue
		}
	}
	parsed, err := url.Parse("//" + endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", ErrInvalidValue
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || strings.Contains(host, "%") {
		return "", "", ErrInvalidValue
	}
	if net.ParseIP(host) == nil && !s3utils.IsValidDomain(host) {
		return "", "", ErrInvalidValue
	}
	if strings.HasPrefix(parsed.Host, "[") {
		if ip := net.ParseIP(host); ip == nil || !strings.Contains(host, ":") {
			return "", "", ErrInvalidValue
		}
	} else if strings.Contains(host, ":") {
		return "", "", ErrInvalidValue
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", "", ErrInvalidValue
		}
	}
	if region != "" && !validS3Region(region) {
		return "", "", ErrInvalidValue
	}
	if isAWSS3Endpoint(host) {
		if !useSSL || region == "" {
			return "", "", ErrInvalidValue
		}
	}
	if !useSSL && !insecureS3EndpointAllowed(host) {
		return "", "", ErrInvalidValue
	}
	return endpoint, region, nil
}

func validS3Region(region string) bool {
	if region == "" || len(region) > 63 || region != strings.TrimSpace(region) {
		return false
	}
	for index, r := range region {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			if index == 0 && (r == '-' || r == '_' || r == '.') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func isAWSS3Endpoint(host string) bool {
	return host == "s3.amazonaws.com" || strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
}

func insecureS3EndpointAllowed(host string) bool {
	// Classify literals before single-label hostnames: public IPv6 addresses
	// have no dot and must not inherit the private hostname exception.
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".internal", ".svc", ".svc.cluster.local"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

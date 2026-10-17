package config

import (
	"encoding/base64"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidValue never wraps a parser error or includes supplied input.
var ErrInvalidValue = errors.New("invalid runtime configuration value")

// scalarValue is package-owned typed input. String-like kinds retain their raw
// bytes for dedicated endpoint, path, credential and cross-field validation.
// This primitive parser alone does not validate a complete configuration.
type scalarValue struct {
	text      string
	boolean   bool
	integer   int64
	duration  time.Duration
	prefixes  []netip.Prefix
	bytes     []byte
	timestamp time.Time
}

func parseScalar(d Definition, raw string) (scalarValue, error) {
	if len(raw) > maxEnvironmentBytes || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return scalarValue{}, ErrInvalidValue
	}
	byteLimit := d.MaxBytes
	if byteLimit <= 0 || byteLimit > maxEnvironmentBytes {
		byteLimit = maxEnvironmentBytes
	}
	if d.Kind != Base64 && len(raw) > byteLimit {
		return scalarValue{}, ErrInvalidValue
	}
	var value scalarValue
	trimmed := strings.TrimSpace(raw)
	switch d.Kind {
	case Text, URL, Path:
		value.text = raw
	case S3BucketName:
		name, err := ParseS3BucketName(raw)
		if err != nil {
			return scalarValue{}, err
		}
		value.text = name
	case Boolean:
		switch {
		case strings.EqualFold(trimmed, "true"):
			value.boolean = true
		case strings.EqualFold(trimmed, "false"):
		default:
			return scalarValue{}, ErrInvalidValue
		}
	case Integer, Seconds:
		n, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil || n < d.Min || n > d.Max {
			return scalarValue{}, ErrInvalidValue
		}
		if d.Kind == Seconds {
			if n > math.MaxInt64/int64(time.Second) || n < math.MinInt64/int64(time.Second) {
				return scalarValue{}, ErrInvalidValue
			}
			value.duration = time.Duration(n) * time.Second
		} else {
			value.integer = n
		}
	case Duration:
		duration, err := time.ParseDuration(trimmed)
		if err != nil || int64(duration) < d.Min || int64(duration) > d.Max {
			return scalarValue{}, ErrInvalidValue
		}
		value.duration = duration
	case Choice:
		for _, allowed := range d.Allowed {
			if strings.EqualFold(trimmed, allowed) {
				value.text = allowed
				return value, nil
			}
		}
		return scalarValue{}, ErrInvalidValue
	case CIDRs:
		if trimmed == "" {
			return value, nil
		}
		itemLimit := d.MaxItems
		if itemLimit <= 0 || itemLimit > maxSelectedSettings {
			itemLimit = maxSelectedSettings
		}
		count := strings.Count(trimmed, ",") + 1
		if count > itemLimit {
			return scalarValue{}, ErrInvalidValue
		}
		value.prefixes = make([]netip.Prefix, 0, count)
		for part := range strings.SplitSeq(trimmed, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
			if err != nil {
				return scalarValue{}, ErrInvalidValue
			}
			value.prefixes = append(value.prefixes, prefix.Masked())
		}
	case Base64:
		if trimmed == "" {
			return value, nil
		}
		if len(trimmed) > base64.StdEncoding.EncodedLen(byteLimit) {
			return scalarValue{}, ErrInvalidValue
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(trimmed)
		if err != nil || len(decoded) == 0 || len(decoded) > byteLimit {
			return scalarValue{}, ErrInvalidValue
		}
		value.bytes = decoded
	case Timestamp:
		if trimmed == "" {
			return value, nil
		}
		parsed, err := time.Parse(time.RFC3339Nano, trimmed)
		if err != nil {
			return scalarValue{}, ErrInvalidValue
		}
		value.timestamp = parsed.UTC()
	default:
		return scalarValue{}, ErrInvalidValue
	}
	return value, nil
}

func (scalarValue) String() string   { return "config.scalarValue{redacted}" }
func (scalarValue) GoString() string { return "config.scalarValue{redacted}" }
func (scalarValue) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

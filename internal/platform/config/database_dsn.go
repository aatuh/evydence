package config

// PostgreSQL URL and keyword grammar adapted from pgx/v5 v5.9.2,
// pgconn/config.go. Copyright (c) 2013-2021 Jack Christensen.
// SPDX-License-Identifier: MIT
// See database_dsn.LICENSE for the upstream permission notice.

import (
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	maxDatabaseSettings = 128
	maxDatabaseHosts    = 16
	databaseSpace       = " \t\n\r\v\f"
)

// databaseSettings owns only explicit connection input. Native defaults,
// environment, service/pass/TLS files and connectivity are separate boundaries.
type databaseSettings struct {
	redactedValue
	values map[string]string
}

type databaseBuilder struct {
	redactedValue
	values map[string]string
	count  int
}

func parseDatabaseDSN(raw string) (databaseSettings, error) {
	settings, err := parseDatabaseDSNParts(raw)
	if err != nil || validateDatabaseRelationships(settings.values, false) != nil {
		return databaseSettings{}, ErrInvalidValue
	}
	return settings, nil
}

// parseDatabaseDSNParts checks grammar and individual values. Runtime roles
// apply relationships after native inputs and explicit DSN values are merged.
func parseDatabaseDSNParts(raw string) (databaseSettings, error) {
	if len(raw) > maxEnvironmentBytes || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return databaseSettings{}, ErrInvalidValue
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return databaseSettings{}, ErrInvalidValue
	}
	b := databaseBuilder{values: make(map[string]string)}
	var err error
	if strings.HasPrefix(raw, "postgres://") || strings.HasPrefix(raw, "postgresql://") {
		err = parseDatabaseURL(raw, &b)
	} else {
		err = parseDatabaseKeywords(raw, &b)
	}
	if err != nil || validateDatabaseFields(b.values) != nil {
		return databaseSettings{}, ErrInvalidValue
	}
	return databaseSettings{values: b.values}, nil
}

func (b *databaseBuilder) set(key, value string) error {
	b.count++
	if b.count > maxDatabaseSettings || !validDatabaseKey(key) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return ErrInvalidValue
	}
	if key == "dbname" {
		key = "database"
	}
	if key == "user" && value == "" {
		return nil // Preserve the driver's explicit empty-user behavior.
	}
	if old, exists := b.values[key]; exists && old != value {
		return ErrInvalidValue
	}
	b.values[key] = value
	return nil
}

func validDatabaseKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for i := range len(key) {
		c := key[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && (c == '.' || (c >= '0' && c <= '9')) {
			continue
		}
		return false
	}
	return true
}

func parseDatabaseURL(raw string, b *databaseBuilder) error {
	u, err := url.Parse(raw)
	if err != nil || strings.Contains(raw, "#") || u.Opaque != "" {
		return ErrInvalidValue
	}
	if u.User != nil {
		if err := b.set("user", u.User.Username()); err != nil {
			return err
		}
		if password, exists := u.User.Password(); exists {
			if err := b.set("password", password); err != nil {
				return err
			}
		}
	}
	if strings.Count(u.Host, ",")+1 > maxDatabaseHosts {
		return ErrInvalidValue
	}
	var hosts, ports []string
	for host := range strings.SplitSeq(u.Host, ",") {
		if host == "" {
			continue
		}
		if net.ParseIP(strings.Trim(host, "[]")) != nil || !strings.Contains(host, ":") {
			hosts = append(hosts, strings.Trim(host, "[]"))
			continue
		}
		h, p, splitErr := net.SplitHostPort(host)
		if splitErr != nil {
			return ErrInvalidValue
		}
		if h != "" {
			hosts = append(hosts, h)
		}
		if p != "" {
			ports = append(ports, p)
		}
	}
	if len(hosts) > 0 {
		if err := b.set("host", strings.Join(hosts, ",")); err != nil {
			return err
		}
	}
	if len(ports) > 0 {
		if err := b.set("port", strings.Join(ports, ",")); err != nil {
			return err
		}
	}
	if database := strings.TrimLeft(u.Path, "/"); database != "" {
		if err := b.set("database", database); err != nil {
			return err
		}
	}
	if u.RawQuery != "" && strings.Count(u.RawQuery, "&")+1 > maxDatabaseSettings-b.count {
		return ErrInvalidValue
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ErrInvalidValue
	}
	q := databaseBuilder{values: make(map[string]string), count: b.count}
	for name, values := range query {
		for _, value := range values {
			if err := q.set(name, value); err != nil {
				return err
			}
		}
	}
	// As in pgx, the query layer intentionally overrides URL components.
	// Conflicting duplicates inside that layer still fail deterministically.
	for name, value := range q.values {
		b.values[name] = value
	}
	b.count = q.count
	return nil
}

func parseDatabaseKeywords(s string, b *databaseBuilder) error {
	for {
		s = strings.TrimLeft(s, databaseSpace)
		if s == "" {
			return nil
		}
		equal := strings.IndexByte(s, '=')
		if equal < 0 {
			return ErrInvalidValue
		}
		key := strings.Trim(s[:equal], databaseSpace)
		s = strings.TrimLeft(s[equal+1:], databaseSpace)
		quoted := strings.HasPrefix(s, "'")
		if quoted {
			s = s[1:]
		}
		end, closed := 0, !quoted
		for end < len(s) {
			if quoted && s[end] == '\'' {
				closed = true
				break
			}
			if !quoted && strings.ContainsRune(databaseSpace, rune(s[end])) {
				break
			}
			if s[end] == '\\' {
				if end+1 >= len(s) {
					return ErrInvalidValue
				}
				end += 2
			} else {
				end++
			}
		}
		if !closed {
			return ErrInvalidValue
		}
		value := strings.ReplaceAll(strings.ReplaceAll(s[:end], "\\\\", "\\"), "\\'", "'")
		if err := b.set(key, value); err != nil {
			return err
		}
		if quoted || end < len(s) {
			s = s[end+1:]
		} else {
			s = ""
		}
	}
}

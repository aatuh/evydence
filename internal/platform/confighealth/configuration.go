package confighealth

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	configurationRevisionEnv     = "EVYDENCE_CONFIGURATION_REVISION"
	configurationRevisionFileEnv = "EVYDENCE_CONFIGURATION_REVISION_FILE"
	maxConfigurationRevisionSize = 256
)

var errConfigurationUnavailable = errors.New("loaded configuration is unavailable or stale")

// New captures the process environment before runtime
// composition. Only its digest is retained. Operators can additionally project
// a desired revision through a local regular file; reopening it on each cached
// health refresh observes Kubernetes' atomic volume projection replacements.
// This does not reload configuration or query an external configuration API.
func New(ctx context.Context, environ func() []string) (func(context.Context) error, error) {
	if environ == nil {
		return nil, errConfigurationUnavailable
	}
	loaded, revision, path, err := configurationEnvironment(environ())
	if err != nil {
		return nil, err
	}
	if (revision == "") != (path == "") || (path != "" && (!validConfigurationRevision(revision) || !filepath.IsAbs(path))) {
		return nil, errConfigurationUnavailable
	}
	probe := func(ctx context.Context) error {
		if ctx == nil {
			return errConfigurationUnavailable
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		current, _, _, err := configurationEnvironment(environ())
		if err != nil || current != loaded {
			return errConfigurationUnavailable
		}
		if path != "" && !configurationRevisionMatches(path, revision) {
			return errConfigurationUnavailable
		}
		return ctx.Err()
	}
	if err := probe(ctx); err != nil {
		return nil, err
	}
	return probe, nil
}

func configurationEnvironment(entries []string) ([32]byte, string, string, error) {
	var empty [32]byte
	selected := make([]string, 0, min(len(entries), 128))
	seen := make(map[string]bool)
	var revision, path string
	bytes := 0
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || (name != "ENV" && !strings.HasPrefix(name, "EVYDENCE_") && !strings.HasPrefix(name, "AWS_") && !strings.HasPrefix(name, "GOOGLE_") && !strings.HasPrefix(name, "AZURE_")) {
			continue
		}
		bytes += len(entry)
		if seen[name] || strings.ContainsRune(entry, '\x00') || len(selected) >= 1024 || bytes > 8<<20 {
			return empty, "", "", errConfigurationUnavailable
		}
		seen[name] = true
		selected = append(selected, entry)
		switch name {
		case configurationRevisionEnv:
			revision = value
		case configurationRevisionFileEnv:
			path = value
		}
	}
	sort.Strings(selected)
	digest := sha256.New()
	for _, entry := range selected {
		_, _ = digest.Write([]byte(entry))
		_, _ = digest.Write([]byte{0})
	}
	var fingerprint [32]byte
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint, revision, path, nil
}

func validConfigurationRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func configurationRevisionMatches(path, revision string) bool {
	// The operator owns the path and its parent directory. Resolve projection
	// aliases on every refresh, including absolute aliases within that directory.
	// Both metadata and content access then use a pinned directory handle: a
	// replacement symlink cannot redirect the open outside that directory.
	directory, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return false
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return false
	}
	defer func() { _ = root.Close() }()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	name, err := filepath.Rel(directory, resolved)
	if err != nil || !filepath.IsLocal(name) {
		return false
	}
	// Reject special files and oversized contents before opening, and recheck
	// the opened inode before a bounded read.
	info, err := root.Stat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigurationRevisionSize {
		return false
	}
	file, err := root.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return false
	}
	value, err := io.ReadAll(io.LimitReader(file, maxConfigurationRevisionSize+1))
	return err == nil && len(value) <= maxConfigurationRevisionSize && strings.TrimSpace(string(value)) == revision
}

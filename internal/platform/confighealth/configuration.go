package confighealth

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxConfigurationRevisionSize = 256

var errConfigurationUnavailable = errors.New("loaded configuration is unavailable or stale")

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

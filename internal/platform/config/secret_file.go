package config

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrSecretResolution carries no reference, file contents or underlying cause.
var ErrSecretResolution = errors.New("secret reference resolution failed")

// readSecretFile is a private primitive, not permission to resolve a complete
// configuration. Schema-selected activation and reference policy are separate.
// Cancellation is checked between bounded local filesystem operations; no
// detached goroutine is used to abandon a blocking kernel filesystem call.
func readSecretFile(ctx context.Context, path string, maxBytes int) (Secret, error) {
	if ctx == nil {
		return Secret{}, ErrSecretResolution
	}
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	if !privateSecretFilesSupported || maxBytes < 1 || maxBytes > maxEnvironmentBytes ||
		len(path) > 4096 || !utf8.ValidString(path) || path != strings.TrimSpace(path) ||
		strings.ContainsFunc(path, unicode.IsControl) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Secret{}, ErrSecretResolution
	}
	directory, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return Secret{}, ErrSecretResolution
	}
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return Secret{}, ErrSecretResolution
	}
	defer func() { _ = root.Close() }()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Secret{}, ErrSecretResolution
	}
	name, err := filepath.Rel(directory, resolved)
	if err != nil || !filepath.IsLocal(name) {
		return Secret{}, ErrSecretResolution
	}
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	before, err := root.Stat(name)
	if err != nil || !validPrivateSecretFile(before, maxBytes) {
		return Secret{}, ErrSecretResolution
	}
	file, err := openPrivateSecretFile(root, name)
	if err != nil {
		return Secret{}, ErrSecretResolution
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !validPrivateSecretFile(opened, maxBytes) || !os.SameFile(before, opened) {
		return Secret{}, ErrSecretResolution
	}
	data, err := readSecretBytes(ctx, file, maxBytes)
	if err != nil {
		return Secret{}, err
	}
	defer clear(data)
	after, err := file.Stat()
	if err != nil || !validPrivateSecretFile(after, maxBytes) || !os.SameFile(opened, after) || after.Size() != int64(len(data)) {
		return Secret{}, ErrSecretResolution
	}
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	return Secret{value: string(data)}, nil
}

func validPrivateSecretFile(info os.FileInfo, maxBytes int) bool {
	return info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= int64(maxBytes) &&
		info.Mode().Perm()&0027 == 0 && info.Mode().Perm()&0111 == 0
}

func readSecretBytes(ctx context.Context, reader io.Reader, maxBytes int) ([]byte, error) {
	if ctx == nil || reader == nil || maxBytes < 1 || maxBytes > maxEnvironmentBytes {
		return nil, ErrSecretResolution
	}
	var chunk [4096]byte
	defer clear(chunk[:])
	data := make([]byte, 0, min(maxBytes, len(chunk)))
	fail := func(err error) ([]byte, error) {
		clear(data)
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		remaining := maxBytes + 1 - len(data)
		n, err := reader.Read(chunk[:min(len(chunk), remaining)])
		if contextErr := ctx.Err(); contextErr != nil {
			return fail(contextErr)
		}
		if n < 0 || n > min(len(chunk), remaining) {
			return fail(ErrSecretResolution)
		}
		data = append(data, chunk[:n]...)
		if len(data) > maxBytes {
			return fail(ErrSecretResolution)
		}
		if err == io.EOF {
			if len(data) == 0 {
				return fail(ErrSecretResolution)
			}
			return data, nil
		}
		if err != nil || n == 0 {
			return fail(ErrSecretResolution)
		}
	}
}

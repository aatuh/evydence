package postgres

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	maxMigrationFiles            = 1024
	maxMigrationDirectoryEntries = 8192
	maxMigrationFileBytes        = 4 << 20
	maxMigrationCatalogBytes     = 32 << 20
)

// Catalog errors omit operator-controlled names, paths and file contents.
var errMigrationCatalog = errors.New("invalid or excessive migration catalog")

// body is an owned immutable string, loaded before any database coordination.
type migrationScript struct{ name, body string }

func migrationNames(dir string) ([]string, error) {
	return migrationNamesContext(context.Background(), dir)
}

func migrationNamesContext(ctx context.Context, dir string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errMigrationCatalog
	}
	defer func() { _ = root.Close() }()
	return migrationNamesInRoot(ctx, root)
}

func migrationNamesInRoot(ctx context.Context, root *os.Root) ([]string, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, errMigrationCatalog
	}
	defer func() { _ = directory.Close() }()
	names := []string{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := directory.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, errMigrationCatalog
		}
		count += len(entries)
		if count > maxMigrationDirectoryEntries {
			return nil, errMigrationCatalog
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".up.sql") {
				continue
			}
			info, err := root.Lstat(entry.Name())
			if err != nil || !info.Mode().IsRegular() || len(names) >= maxMigrationFiles {
				return nil, errMigrationCatalog
			}
			names = append(names, entry.Name())
		}
		if err == io.EOF {
			sort.Strings(names)
			return names, nil
		}
	}
}

func loadMigrationCatalog(ctx context.Context, dir string) ([]migrationScript, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errMigrationCatalog
	}
	defer func() { _ = root.Close() }()
	names, err := migrationNamesInRoot(ctx, root)
	if err != nil {
		return nil, err
	}
	catalog := make([]migrationScript, 0, len(names))
	remaining := maxMigrationCatalogBytes
	for _, name := range names {
		body, err := readMigrationScript(ctx, root, name, min(remaining, maxMigrationFileBytes))
		if err != nil {
			return nil, err
		}
		remaining -= len(body)
		catalog = append(catalog, migrationScript{name: name, body: body})
	}
	return catalog, nil
}

// Root containment and inode/type checks prevent following a replacement out
// of the chosen directory. This is not an atomic filesystem snapshot or release
// authentication. Cancellation is checked between bounded filesystem operations;
// no detached goroutine abandons a blocked kernel filesystem call.
func readMigrationScript(ctx context.Context, root *os.Root, name string, maxBytes int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(maxBytes) {
		return "", errMigrationCatalog
	}
	file, err := openMigrationFile(root, name)
	if err != nil {
		return "", errMigrationCatalog
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() || !opened.ModTime().Equal(before.ModTime()) {
		return "", errMigrationCatalog
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil || len(body) > maxBytes {
		return "", errMigrationCatalog
	}
	after, err := file.Stat()
	if err != nil || after.Size() != opened.Size() || after.Size() != int64(len(body)) || !after.ModTime().Equal(opened.ModTime()) {
		return "", errMigrationCatalog
	}
	named, err := root.Lstat(name)
	if err != nil || !named.Mode().IsRegular() || !os.SameFile(opened, named) {
		return "", errMigrationCatalog
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return string(body), nil
}

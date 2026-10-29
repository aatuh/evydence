package postgres

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ErrMigrationPlan    = errors.New("invalid migration target or checksum inputs")
	ErrMigrationHistory = errors.New("database migration history does not match target prefix")
	// Match the existing migrations.sha256 release format. Filenames are
	// logical release names; only a validated basename is opened under root.
	migrationChecksumLine = regexp.MustCompile(`^([a-f0-9]{64}) [ *]migrations/([A-Za-z0-9][A-Za-z0-9_.-]{0,250}\.sql)$`)
)

// MigrationPlan owns verified immutable input SQL. It does not authenticate its
// checksum source or verify the SQL previously executed for existing versions.
// Its zero value is invalid; construct it with PrepareMigrationPlan.
type MigrationPlan struct {
	catalog []migrationScript
	target  string
}

func (plan MigrationPlan) TargetVersion() string { return plan.target }
func (MigrationPlan) String() string             { return "postgres.MigrationPlan{redacted}" }
func (plan MigrationPlan) GoString() string      { return plan.String() }
func (MigrationPlan) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// PrepareMigrationPlan validates all up files, including files beyond target,
// plus every other listed SQL file, before returning the selected prefix.
func PrepareMigrationPlan(ctx context.Context, dir, target, checksumsPath string) (MigrationPlan, error) {
	if err := ctx.Err(); err != nil {
		return MigrationPlan{}, err
	}
	if target == "" || checksumsPath == "" {
		return MigrationPlan{}, ErrMigrationPlan
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return MigrationPlan{}, ErrMigrationPlan
	}
	defer func() { _ = root.Close() }()
	catalog, err := loadMigrationCatalogInRoot(ctx, root)
	if err != nil {
		return MigrationPlan{}, errors.Join(ErrMigrationPlan, err)
	}
	targetIndex := -1
	for i, script := range catalog {
		if strings.TrimSuffix(script.name, ".up.sql") == target {
			targetIndex = i
		}
	}
	if targetIndex < 0 {
		return MigrationPlan{}, ErrMigrationPlan
	}
	records, err := readMigrationChecksums(ctx, checksumsPath)
	if err != nil {
		return MigrationPlan{}, errors.Join(ErrMigrationPlan, err)
	}
	upNames := make(map[string]bool, len(catalog))
	remaining := maxMigrationCatalogBytes
	for _, script := range catalog {
		if records[script.name] != fmt.Sprintf("%x", sha256.Sum256([]byte(script.body))) {
			return MigrationPlan{}, ErrMigrationPlan
		}
		upNames[script.name] = true
		remaining -= len(script.body)
	}
	for name, expected := range records {
		if strings.HasSuffix(name, ".up.sql") {
			if !upNames[name] {
				return MigrationPlan{}, ErrMigrationPlan
			}
			continue
		}
		body, err := readMigrationScript(ctx, root, name, min(remaining, maxMigrationFileBytes))
		if err != nil {
			return MigrationPlan{}, errors.Join(ErrMigrationPlan, err)
		}
		if fmt.Sprintf("%x", sha256.Sum256([]byte(body))) != expected {
			return MigrationPlan{}, ErrMigrationPlan
		}
		remaining -= len(body)
	}
	if err := ctx.Err(); err != nil {
		return MigrationPlan{}, err
	}
	prefix := append([]migrationScript(nil), catalog[:targetIndex+1]...)
	return MigrationPlan{catalog: prefix, target: target}, nil
}

func readMigrationChecksums(ctx context.Context, path string) (map[string]string, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, ErrMigrationPlan
	}
	defer func() { _ = root.Close() }()
	body, err := readMigrationScript(ctx, root, filepath.Base(path), 64<<10)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	records := map[string]string{}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		match := migrationChecksumLine.FindStringSubmatch(scanner.Text())
		if match == nil || len(records) >= 256 || records[match[2]] != "" {
			return nil, ErrMigrationPlan
		}
		records[match[2]] = match[1]
	}
	if scanner.Err() != nil || len(records) == 0 {
		return nil, ErrMigrationPlan
	}
	return records, nil
}

func (s *Store) ApplyMigrationPlan(ctx context.Context, plan MigrationPlan) (int, error) {
	if len(plan.catalog) == 0 || plan.target == "" || strings.TrimSuffix(plan.catalog[len(plan.catalog)-1].name, ".up.sql") != plan.target {
		return 0, ErrMigrationPlan
	}
	return s.applyMigrationCatalog(ctx, plan.catalog, true)
}

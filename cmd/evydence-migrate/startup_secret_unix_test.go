//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestMigrationProcessResolvesProjectedDSNBeforeOperation(t *testing.T) {
	dir := t.TempDir()
	file, projection := filepath.Join(dir, "PRIVATE_DSN"), filepath.Join(dir, "PRIVATE_PROJECTION")
	if err := os.WriteFile(file, []byte("host=PRIVATE_DATABASE dbname=evidence\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(file), projection); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	called := false
	err := runMigrationProcess(t.Context(), migrationEnvironment(t, "EVYDENCE_DATABASE_URL_FILE="+projection), &output, func(_ context.Context, settings config.Configuration) error {
		called = true
		if settings.Runtime().DatabaseURL.Reveal() != "host=PRIVATE_DATABASE dbname=evidence" {
			t.Fatal("migration did not receive the resolved DSN")
		}
		return nil
	})
	if err != nil || !called || strings.Contains(output.String(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"succeeded"`) {
		t.Fatal("projected DSN was not resolved safely before migration", err)
	}
}

func TestMigrationProcessRejectsSecretFailuresBeforeOperation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "PRIVATE_DSN")
	for _, tc := range []struct {
		content string
		mode    os.FileMode
		extra   []string
		want    error
	}{
		{"PRIVATE_INVALID_DSN", 0600, nil, config.ErrSecretResolution},
		{"host=db", 0644, nil, config.ErrSecretResolution},
		{"host=db", 0600, []string{"EVYDENCE_DATABASE_URL=host=PRIVATE_INLINE"}, config.ErrConflictingSecretSources},
		{"host=db", 0600, []string{"EVYDENCE_LOG_FORMAT=PRIVATE_FORMAT"}, config.ErrInvalidValue},
	} {
		if err := os.WriteFile(file, []byte(tc.content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, tc.mode); err != nil {
			t.Fatal(err)
		}
		entries := append([]string{"EVYDENCE_DATABASE_URL_FILE=" + file}, tc.extra...)
		var output bytes.Buffer
		called := false
		err := runMigrationProcess(t.Context(), migrationEnvironment(t, entries...), &output, func(context.Context, config.Configuration) error { called = true; return nil })
		if !errors.Is(err, tc.want) || called || strings.Contains(output.String()+err.Error(), "PRIVATE") || !strings.Contains(output.String(), `"result_code":"rejected"`) || strings.Contains(output.String(), `"result_code":"started"`) {
			t.Fatal("secret failure reached migration or disclosed operator input", err)
		}
	}
}

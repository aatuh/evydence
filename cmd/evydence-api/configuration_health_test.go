package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConfigurationReadinessDetectsEnvironmentDriftAndRecovery(t *testing.T) {
	values := []string{"ENV=production", "EVYDENCE_API_KEY_PEPPER=private-pepper", "UNRELATED=first"}
	probe, err := newConfigurationReadiness(t.Context(), func() []string { return values })
	if err != nil {
		t.Fatal(err)
	}
	check := func(unavailable bool) {
		t.Helper()
		err := probe(t.Context())
		if (err != nil) != unavailable {
			t.Fatalf("unavailable=%v err=%v", unavailable, err)
		}
		if err != nil && strings.Contains(err.Error(), "private-") {
			t.Fatal("configuration probe disclosed secret input")
		}
	}
	check(false)
	values = []string{"UNRELATED=changed", "EVYDENCE_API_KEY_PEPPER=private-pepper", "ENV=production"}
	check(false) // Order and unrelated environment changes are not drift.
	values[1] = "EVYDENCE_API_KEY_PEPPER=private-rotated"
	check(true)
	values[1] = "EVYDENCE_API_KEY_PEPPER=private-pepper"
	check(false)
	values = append(values, "EVYDENCE_OBJECT_STORE=s3")
	check(true)
	values = values[:len(values)-1]
	check(false)
	values = values[:2] // Removed ENV must also invalidate the loaded snapshot.
	check(true)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := probe(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestConfigurationReadinessDetectsProjectedRevisionChanges(t *testing.T) {
	dir := t.TempDir()
	current := strings.Repeat("a", 64)
	file := filepath.Join(dir, "revision")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(current + "\n")
	values := []string{"EVYDENCE_CONFIGURATION_REVISION=" + current, "EVYDENCE_CONFIGURATION_REVISION_FILE=" + file}
	probe, err := newConfigurationReadiness(t.Context(), func() []string { return values })
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{strings.Repeat("b", 64), "private-invalid-revision", strings.Repeat("a", 4096), ""} {
		write(revision)
		if err := probe(t.Context()); err == nil || strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), file) {
			t.Fatalf("unsafe/healthy changed revision: %v", err)
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); err == nil {
		t.Fatal("missing revision reported fresh")
	}
	write(current)
	if err := probe(t.Context()); err != nil {
		t.Fatalf("revision restoration did not recover: %v", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); err == nil {
		t.Fatal("directory reported as a valid revision file")
	}
}

func TestConfigurationReadinessFollowsAtomicProjectionSymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "revision")
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	revision := strings.Repeat("a", 64)
	for path, value := range map[string]string{first: revision, second: strings.Repeat("b", 64)} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(first, file); err != nil {
		t.Fatal(err)
	}
	values := []string{"EVYDENCE_CONFIGURATION_REVISION=" + revision, "EVYDENCE_CONFIGURATION_REVISION_FILE=" + file}
	probe, err := newConfigurationReadiness(t.Context(), func() []string { return values })
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Kubernetes switches a projected directory symlink rather than mutating
	// the original file. Reopen on each refresh to observe that replacement.
	next := filepath.Join(dir, "next")
	if err := os.Symlink(second, next); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, file); err != nil {
		t.Fatal(err)
	}
	if err := probe(t.Context()); err == nil {
		t.Fatal("atomic projected revision change was not detected")
	}
}

func TestConfigurationReadinessRejectsIncompleteOrUnsafeRevisionConfig(t *testing.T) {
	revision := strings.Repeat("a", 64)
	for _, values := range [][]string{
		{"EVYDENCE_CONFIGURATION_REVISION=" + revision},
		{"EVYDENCE_CONFIGURATION_REVISION_FILE=/missing/private-file"},
		{"EVYDENCE_CONFIGURATION_REVISION=private-token", "EVYDENCE_CONFIGURATION_REVISION_FILE=/missing/private-file"},
		{"EVYDENCE_CONFIGURATION_REVISION=" + revision, "EVYDENCE_CONFIGURATION_REVISION_FILE=relative"},
		{"EVYDENCE_CONFIGURATION_REVISION=" + revision, "EVYDENCE_CONFIGURATION_REVISION_FILE=/missing/private-file"},
	} {
		probe, err := newConfigurationReadiness(t.Context(), func() []string { return values })
		if err == nil || probe != nil || strings.Contains(err.Error(), "private-") {
			t.Fatalf("unsafe configuration accepted/disclosed: %v", err)
		}
	}
}

func TestConfigurationReadinessIncludesProviderEnvironment(t *testing.T) {
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_TENANT_ID"} {
		t.Run(name, func(t *testing.T) {
			values := []string{name + "=private-initial"}
			probe, err := newConfigurationReadiness(t.Context(), func() []string { return values })
			if err != nil {
				t.Fatal(err)
			}
			values[0] = name + "=private-replacement"
			if err := probe(t.Context()); err == nil || strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), name) {
				t.Fatalf("provider drift accepted/disclosed: %v", err)
			}
		})
	}
}

func TestConfigurationReadinessRejectsInvalidSourcesBeforeServing(t *testing.T) {
	if probe, err := newConfigurationReadiness(t.Context(), nil); probe != nil || err == nil {
		t.Fatal("nil environment source accepted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if probe, err := newConfigurationReadiness(canceled, os.Environ); probe != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled startup accepted", err)
	}
	tooMany := make([]string, 1025)
	for index := range tooMany {
		tooMany[index] = "EVYDENCE_TEST_" + strconv.Itoa(index) + "=value"
	}
	for _, values := range [][]string{
		{"EVYDENCE_SECRET=private-a", "EVYDENCE_SECRET=private-b"},
		{"EVYDENCE_SECRET=private-\x00"},
		{"EVYDENCE_SECRET=" + strings.Repeat("x", 8<<20)},
		tooMany,
	} {
		if probe, err := newConfigurationReadiness(t.Context(), func() []string { return values }); probe != nil || err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatalf("invalid environment accepted/disclosed: %v", err)
		}
	}
	file := filepath.Join(t.TempDir(), "revision")
	if err := os.WriteFile(file, []byte(strings.Repeat("b", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	values := []string{"EVYDENCE_CONFIGURATION_REVISION=" + strings.Repeat("a", 64), "EVYDENCE_CONFIGURATION_REVISION_FILE=" + file}
	if probe, err := newConfigurationReadiness(t.Context(), func() []string { return values }); probe != nil || err == nil {
		t.Fatal("initial desired revision mismatch accepted")
	}
}

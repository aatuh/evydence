//go:build unix

package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writePrivateSecret(t *testing.T, path, value string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSecretFileReadOwnsExactBytesAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_REFERENCE")
	writePrivateSecret(t, path, " PRIVATE_VALUE\n")
	for _, mode := range []os.FileMode{0o600, 0o400, 0o640, 0o440} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		secret, err := readSecretFile(context.Background(), path, 64)
		if err != nil || secret.Reveal() != " PRIVATE_VALUE\n" {
			t.Fatal("private secret file bytes changed", err)
		}
		data, err := json.Marshal(secret)
		if err != nil || strings.Contains(string(data), "PRIVATE") || strings.Contains(fmt.Sprintf("%v %#v", secret, secret), "PRIVATE") {
			t.Fatal("resolved secret escaped default redaction", err)
		}
		writePrivateSecret(t, path, "PRIVATE_REPLACED")
		if secret.Reveal() != " PRIVATE_VALUE\n" {
			t.Fatal("resolved secret did not own its content")
		}
		writePrivateSecret(t, path, " PRIVATE_VALUE\n")
	}
}

func TestSecretFileReadFollowsContainedProjections(t *testing.T) {
	dir := t.TempDir()
	version := filepath.Join(dir, "..PRIVATE_VERSION")
	if err := os.Mkdir(version, 0o700); err != nil {
		t.Fatal(err)
	}
	writePrivateSecret(t, filepath.Join(version, "token"), "PRIVATE_FIRST")
	if err := os.Symlink(filepath.Base(version), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "token"), filepath.Join(dir, "token")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"token", "absolute"} {
		if name == "absolute" {
			if err := os.Symlink(filepath.Join(version, "token"), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		secret, err := readSecretFile(context.Background(), filepath.Join(dir, name), 64)
		if err != nil || secret.Reveal() != "PRIVATE_FIRST" {
			t.Fatal("contained projection was not resolved", err)
		}
	}
	writePrivateSecret(t, filepath.Join(version, "token"), "PRIVATE_ROTATED")
	secret, err := readSecretFile(context.Background(), filepath.Join(dir, "token"), 64)
	if err != nil || secret.Reveal() != "PRIVATE_ROTATED" {
		t.Fatal("later resolution reused stale file contents", err)
	}
	next := filepath.Join(dir, "..PRIVATE_NEXT")
	if err := os.Mkdir(next, 0o700); err != nil {
		t.Fatal(err)
	}
	writePrivateSecret(t, filepath.Join(next, "token"), "PRIVATE_ATOMIC_ROTATION")
	if err := os.Symlink(filepath.Base(next), filepath.Join(dir, "..next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "..next"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	secret, err = readSecretFile(context.Background(), filepath.Join(dir, "token"), 64)
	if err != nil || secret.Reveal() != "PRIVATE_ATOMIC_ROTATION" {
		t.Fatal("atomic projection swap was not observed on later resolution", err)
	}
}

func TestPrivateSecretOpenDoesNotWaitForFIFOWriter(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	type result struct {
		file *os.File
		err  error
	}
	done := make(chan result, 1)
	go func() {
		file, err := openPrivateSecretFile(root, "fifo")
		done <- result{file: file, err: err}
	}()
	var opened result
	select {
	case opened = <-done:
	case <-time.After(2 * time.Second):
		// Release a regressed blocking open and join its goroutine before failing.
		peer, err := root.OpenFile("fifo", os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened = <-done
		_ = peer.Close()
		t.Error("private secret open waited for a FIFO peer")
	}
	if opened.file != nil {
		_ = opened.file.Close()
	}
	if opened.err != nil {
		t.Fatal("nonblocking private open failed", opened.err)
	}
}

func TestSecretFileReadRejectsUnsafeSourcesWithoutEcho(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "PRIVATE_VALID")
	writePrivateSecret(t, valid, "PRIVATE_VALUE")
	outside := filepath.Join(t.TempDir(), "PRIVATE_OUTSIDE")
	writePrivateSecret(t, outside, "PRIVATE_OUTSIDE_VALUE")
	escape := filepath.Join(dir, "PRIVATE_ESCAPE")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "PRIVATE_FIFO")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		max  int
	}{
		{"", 64}, {"PRIVATE_RELATIVE", 64}, {valid + string(os.PathSeparator), 64},
		{filepath.Dir(valid) + "/../" + filepath.Base(filepath.Dir(valid)) + "/" + filepath.Base(valid), 64},
		{filepath.Join(dir, "PRIVATE_MISSING"), 64}, {dir, 64}, {fifo, 64}, {escape, 64},
		{valid, 0}, {valid, maxEnvironmentBytes + 1}, {valid, 3},
	} {
		secret, err := readSecretFile(context.Background(), tc.path, tc.max)
		if !errors.Is(err, ErrSecretResolution) || secret.IsSet() || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("unsafe secret reference returned data or a revealing diagnostic", err)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o660, 0o620, 0o601, 0o700} {
		if err := os.Chmod(valid, mode); err != nil {
			t.Fatal(err)
		}
		if secret, err := readSecretFile(context.Background(), valid, 64); !errors.Is(err, ErrSecretResolution) || secret.IsSet() {
			t.Fatal("unsafe secret permissions were accepted", err)
		}
	}
}

func TestSecretFileReadBoundsAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PRIVATE_BOUNDARY")
	writePrivateSecret(t, path, strings.Repeat("x", 64))
	if secret, err := readSecretFile(context.Background(), path, 64); err != nil || len(secret.Reveal()) != 64 {
		t.Fatal("exact secret size bound was rejected", err)
	}
	writePrivateSecret(t, path, strings.Repeat("x", 65))
	if secret, err := readSecretFile(context.Background(), path, 64); !errors.Is(err, ErrSecretResolution) || secret.IsSet() {
		t.Fatal("oversized secret file was accepted", err)
	}
	writePrivateSecret(t, path, "")
	if secret, err := readSecretFile(context.Background(), path, 64); !errors.Is(err, ErrSecretResolution) || secret.IsSet() {
		t.Fatal("empty secret reference was accepted", err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("PRIVATE_CANCEL_CAUSE"))
	for _, tc := range []struct {
		ctx  context.Context
		want error
	}{{ctx, context.Canceled}, {nil, ErrSecretResolution}} {
		secret, err := readSecretFile(tc.ctx, filepath.Join(t.TempDir(), "PRIVATE_MISSING"), 64)
		if !errors.Is(err, tc.want) || secret.IsSet() || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
			t.Fatal("invalid secret-resolution context returned data or an unsafe error", err)
		}
	}
}

type secretReadProbe struct {
	value  string
	err    error
	cancel context.CancelFunc
	bytes  int
}

func (r *secretReadProbe) Read(p []byte) (int, error) {
	n := copy(p, r.value)
	r.bytes += n
	if r.cancel != nil {
		r.cancel()
	}
	return n, r.err
}

func TestSecretBytesCancelDuringReadAndDiscardPartialFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &secretReadProbe{value: "PRIVATE_PARTIAL", cancel: cancel}
	data, err := readSecretBytes(ctx, reader, 64)
	if !errors.Is(err, context.Canceled) || len(data) != 0 || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
		t.Fatal("cancellation during read returned partial secret data", err)
	}
	reader = &secretReadProbe{value: "PRIVATE_PARTIAL", err: errors.New("PRIVATE_IO_ERROR")}
	if data, err := readSecretBytes(context.Background(), reader, 64); !errors.Is(err, ErrSecretResolution) || len(data) != 0 || strings.Contains(fmt.Sprintf("%v %#v", err, err), "PRIVATE") {
		t.Fatal("reader failure exposed data or its underlying cause", err)
	}
	reader = &secretReadProbe{value: strings.Repeat("x", 128), err: io.EOF}
	if data, err := readSecretBytes(context.Background(), reader, 64); !errors.Is(err, ErrSecretResolution) || len(data) != 0 || reader.bytes > 65 {
		t.Fatal("bounded reader consumed more than its limit plus sentinel", err)
	}
}

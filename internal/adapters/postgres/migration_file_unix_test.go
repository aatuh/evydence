//go:build unix

package postgres

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestMigrationSnapshotRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "PRIVATE.up.sql"), 0o600); err != nil {
		t.Fatal(err)
	}
	if catalog, err := loadMigrationCatalog(t.Context(), dir); !errors.Is(err, errMigrationCatalog) || catalog != nil {
		t.Fatal("snapshot admitted a FIFO", err)
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
		file, err := openMigrationFile(root, "PRIVATE.up.sql")
		done <- result{file, err}
	}()
	var opened result
	select {
	case opened = <-done:
	case <-time.After(2 * time.Second):
		// Own and join a regressed blocking open before reporting failure.
		peer, err := root.OpenFile("PRIVATE.up.sql", os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened = <-done
		_ = peer.Close()
		t.Error("migration file open waited for a FIFO peer")
	}
	if opened.file != nil {
		_ = opened.file.Close()
	}
	if opened.err != nil {
		t.Fatal("nonblocking migration open failed", opened.err)
	}
}

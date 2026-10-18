//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestArtifactOpenDoesNotWaitForFIFOWriter(t *testing.T) {
	directory := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(directory, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
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
		file, err := openArtifactFile(root, "fifo")
		done <- result{file: file, err: err}
	}()
	var opened result
	select {
	case opened = <-done:
	case <-time.After(2 * time.Second):
		// Join the blocked reader before reporting a regression.
		peer, err := root.OpenFile("fifo", os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened = <-done
		_ = peer.Close()
		t.Error("artifact open waited for a FIFO peer")
	}
	if opened.file != nil {
		_ = opened.file.Close()
	}
	if opened.err != nil {
		t.Fatal("nonblocking artifact open failed", opened.err)
	}
}

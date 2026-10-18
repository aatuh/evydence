//go:build unix

package main

import (
	"os"
	"syscall"
)

func openArtifactFile(root *os.Root, name string) (*os.File, error) {
	// A FIFO can replace the regular file after lstat. Do not wait for a peer;
	// readArtifact rejects the opened inode before attempting a read.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

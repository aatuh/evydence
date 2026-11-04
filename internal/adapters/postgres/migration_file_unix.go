//go:build unix

package postgres

import (
	"os"
	"syscall"
)

func openMigrationFile(root *os.Root, name string) (*os.File, error) {
	// A FIFO can replace a regular file after lstat. Do not wait for a peer;
	// readMigrationScript rejects the opened inode before attempting a read.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

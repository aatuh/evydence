//go:build unix

package config

import (
	"os"
	"syscall"
)

const privateSecretFilesSupported = true

func openPrivateSecretFile(root *os.Root, name string) (*os.File, error) {
	// A regular file can be replaced by a FIFO between stat and open. Keep the
	// open nonblocking and reject the opened inode before attempting any read.
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

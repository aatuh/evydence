//go:build !unix

package postgres

import "os"

func openMigrationFile(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

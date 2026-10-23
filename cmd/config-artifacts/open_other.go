//go:build !unix

package main

import "os"

func openArtifactFile(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

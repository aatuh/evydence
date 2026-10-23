package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/aatuh/evydence/internal/platform/configartifact"
)

var errArtifactFile = errors.New("invalid configuration artifact file")

type managedArtifact struct {
	parent        *os.Root
	name          string
	info          os.FileInfo
	before, after []byte
	temporary     string
}

func openArtifact(root *os.Root, target string) (*managedArtifact, error) {
	parent, err := openArtifactParent(root, path.Dir(target))
	if err != nil {
		return nil, errArtifactFile
	}
	name := path.Base(target)
	body, info, err := readArtifact(parent, name)
	if err != nil {
		_ = parent.Close()
		return nil, errArtifactFile
	}
	return &managedArtifact{parent: parent, name: name, info: info, before: body}, nil
}

// Pin each directory handle, rejecting links even when they resolve inside the
// repository. os.Root also enforces containment during each open operation.
func openArtifactParent(root *os.Root, directory string) (*os.Root, error) {
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, errArtifactFile
	}
	if directory == "." {
		return current, nil
	}
	for component := range strings.SplitSeq(directory, "/") {
		info, err := current.Lstat(component)
		if err != nil || !info.IsDir() {
			_ = current.Close()
			return nil, errArtifactFile
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, errArtifactFile
		}
		opened, statErr := next.Stat(".")
		closeErr := current.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(info, opened) {
			_ = next.Close()
			return nil, errArtifactFile
		}
		current = next
	}
	return current, nil
}

func readArtifact(parent *os.Root, name string) ([]byte, os.FileInfo, error) {
	info, err := parent.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > configartifact.MaxArtifactBytes {
		return nil, nil, errArtifactFile
	}
	file, err := openArtifactFile(parent, name)
	if err != nil {
		return nil, nil, errArtifactFile
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, errArtifactFile
	}
	body, readErr := io.ReadAll(io.LimitReader(file, configartifact.MaxArtifactBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(body) > configartifact.MaxArtifactBytes {
		return nil, nil, errArtifactFile
	}
	return body, opened, nil
}

func (artifact *managedArtifact) stage() error {
	// Exclusive creation prevents following a pre-existing link or clobbering
	// another generator's staging file. Permissions expand only after writing.
	name := "evydence-config-" + rand.Text()
	file, err := artifact.parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errArtifactFile
	}
	artifact.temporary = name
	_, writeErr := file.Write(artifact.after)
	chmodErr := file.Chmod(artifact.info.Mode().Perm())
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || chmodErr != nil || syncErr != nil || closeErr != nil {
		return errArtifactFile
	}
	return nil
}

func (artifact *managedArtifact) unchanged() bool {
	body, info, err := readArtifact(artifact.parent, artifact.name)
	return err == nil && os.SameFile(artifact.info, info) && artifact.info.Mode() == info.Mode() && bytes.Equal(artifact.before, body)
}

func (artifact *managedArtifact) close() error {
	var removeErr error
	if artifact.temporary != "" {
		removeErr = artifact.parent.Remove(artifact.temporary)
	}
	return errors.Join(removeErr, artifact.parent.Close())
}

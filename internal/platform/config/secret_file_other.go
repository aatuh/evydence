//go:build !unix

package config

import "os"

// POSIX mode checks cannot establish private ACLs on other platforms. This
// private primitive fails closed until a platform-specific policy is provided.
const privateSecretFilesSupported = false

func openPrivateSecretFile(_ *os.Root, _ string) (*os.File, error) {
	return nil, ErrSecretResolution
}

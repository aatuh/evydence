package config

import "time"

// Shared composition defaults also serve programmatic infrastructure callers.
// Commands still receive their validated values through Configuration; these
// constants do not read a process source or bypass role-specific preflight.
const (
	DefaultObjectStoreBackend = "filesystem"
	DefaultObjectDirectory    = "tmp/objects"
	DefaultCleanupTimeout     = 5 * time.Second
	MinCleanupTimeout         = time.Second
	MaxCleanupTimeout         = time.Minute
)

// Package wiring validates process-wide runtime selection before infrastructure
// is opened. Adapter construction belongs here as the composition root grows.
package wiring

import (
	"errors"
	"strings"
)

type Process string

const (
	API    Process = "api"
	Worker Process = "worker"
)

type Profile string

const (
	LocalMemory Profile = "local_memory"
	PostgreSQL  Profile = "postgres"
)

// ResolveRuntimeProfile requires an explicit profile. It never echoes raw
// connection settings, which can include passwords, in configuration errors.
func ResolveRuntimeProfile(raw string, production bool, databaseURL string, process Process) (Profile, error) {
	if process != API && process != Worker {
		return "", errors.New("unsupported runtime process")
	}
	profile := Profile(strings.TrimSpace(raw))
	switch profile {
	case LocalMemory:
		if production || process != API {
			return "", errors.New("EVYDENCE_RUNTIME_PROFILE=local_memory is only available for local API development")
		}
		if strings.TrimSpace(databaseURL) != "" {
			return "", errors.New("EVYDENCE_RUNTIME_PROFILE=local_memory requires EVYDENCE_DATABASE_URL to be unset")
		}
	case PostgreSQL:
		if strings.TrimSpace(databaseURL) == "" {
			return "", errors.New("EVYDENCE_RUNTIME_PROFILE=postgres requires EVYDENCE_DATABASE_URL")
		}
	default:
		return "", errors.New("EVYDENCE_RUNTIME_PROFILE must be local_memory or postgres")
	}
	return profile, nil
}

func (profile Profile) Limitations() []string {
	if profile != LocalMemory {
		return nil
	}
	return []string{
		"Local-memory state is non-durable and is lost when the API process exits.",
		"Local-memory mode has no durable outbox or worker and is for local development only.",
		"Configured local filesystem payload bytes can remain after in-memory metadata is lost; discard them together.",
	}
}

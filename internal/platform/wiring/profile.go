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
	PostgreSQL Profile = "postgres"
)

const retiredMemoryProfileMessage = "EVYDENCE_RUNTIME_PROFILE=local_memory has been retired; use postgres with EVYDENCE_DATABASE_URL"

// ResolveRuntimeProfile requires an explicit profile. It never echoes raw
// connection settings, which can include passwords, in configuration errors.
func ResolveRuntimeProfile(raw string, production bool, databaseURL string, process Process) (Profile, error) {
	if process != API && process != Worker {
		return "", errors.New("unsupported runtime process")
	}
	profile := Profile(strings.TrimSpace(raw))
	switch profile {
	case "local_memory":
		return "", errors.New(retiredMemoryProfileMessage)
	case PostgreSQL:
		if strings.TrimSpace(databaseURL) == "" {
			return "", errors.New("EVYDENCE_RUNTIME_PROFILE=postgres requires EVYDENCE_DATABASE_URL")
		}
	default:
		return "", errors.New("EVYDENCE_RUNTIME_PROFILE must be postgres")
	}
	return profile, nil
}

// Package runtimeinfo exposes immutable build metadata injected by the build
// pipeline. Linker variables remain strings because Go's -X flag only sets
// string variables; Current converts them into the API representation.
package runtimeinfo

import (
	"runtime"
	"strings"
)

var (
	Version               = "dev"
	Commit                = "unknown"
	BuildTime             = "unknown"
	Dirty                 = "unknown"
	GoVersion             string
	ReleaseManifestDigest = "unknown"
)

// Identity is immutable process metadata. It intentionally includes no
// environment-derived configuration, endpoint, credential, path, or tenant
// information.
type Identity struct {
	Version               string `json:"version"`
	Commit                string `json:"commit"`
	BuildTime             string `json:"build_time"`
	Dirty                 bool   `json:"dirty"`
	GoVersion             string `json:"go_version"`
	ReleaseManifestDigest string `json:"release_manifest_digest"`
}

func Current() Identity {
	return Identity{
		Version:               nonEmpty(Version, "dev"),
		Commit:                nonEmpty(Commit, "unknown"),
		BuildTime:             nonEmpty(BuildTime, "unknown"),
		Dirty:                 strings.EqualFold(strings.TrimSpace(Dirty), "true"),
		GoVersion:             nonEmpty(GoVersion, runtime.Version()),
		ReleaseManifestDigest: nonEmpty(ReleaseManifestDigest, "unknown"),
	}
}

func (i Identity) IsZero() bool {
	return strings.TrimSpace(i.Version) == "" &&
		strings.TrimSpace(i.Commit) == "" &&
		strings.TrimSpace(i.BuildTime) == "" &&
		strings.TrimSpace(i.GoVersion) == "" &&
		strings.TrimSpace(i.ReleaseManifestDigest) == "" &&
		!i.Dirty
}

func (i Identity) String() string {
	return "version=" + nonEmpty(i.Version, "dev") +
		" commit=" + nonEmpty(i.Commit, "unknown") +
		" build_time=" + nonEmpty(i.BuildTime, "unknown") +
		" dirty=" + boolString(i.Dirty) +
		" go_version=" + nonEmpty(i.GoVersion, runtime.Version()) +
		" release_manifest_digest=" + nonEmpty(i.ReleaseManifestDigest, "unknown")
}

func nonEmpty(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

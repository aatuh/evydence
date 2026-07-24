package runtimeinfo

import "testing"

func TestIdentityZeroAndStringAreSafeAndDeterministic(t *testing.T) {
	if !(Identity{}).IsZero() {
		t.Fatal("zero identity must be detected")
	}
	identity := Identity{Version: "v1.2.3", Commit: "0123456789abcdef", BuildTime: "2026-07-24T12:00:00Z", Dirty: true, GoVersion: "go1.26.0", ReleaseManifestDigest: "sha256:abc"}
	if identity.IsZero() {
		t.Fatal("populated identity must not be zero")
	}
	want := "version=v1.2.3 commit=0123456789abcdef build_time=2026-07-24T12:00:00Z dirty=true go_version=go1.26.0 release_manifest_digest=sha256:abc"
	if got := identity.String(); got != want {
		t.Fatalf("identity string = %q, want %q", got, want)
	}
}

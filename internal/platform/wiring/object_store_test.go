package wiring

import (
	"context"
	"strings"
	"testing"
)

func TestOpenObjectStoreSelectsFilesystemAndRejectsUnknownBackend(t *testing.T) {
	root := t.TempDir()
	store, description, err := OpenObjectStore(context.Background(), ObjectStoreConfig{Backend: "filesystem", Directory: root})
	if err != nil || store == nil || !strings.Contains(description, root) {
		t.Fatalf("filesystem composition store=%T description=%q error=%v", store, description, err)
	}
	store, description, err = OpenObjectStore(context.Background(), ObjectStoreConfig{Backend: "unknown"})
	if err == nil || store != nil || description != "" || !strings.Contains(err.Error(), "unsupported EVYDENCE_OBJECT_STORE") {
		t.Fatalf("unknown backend store=%T description=%q error=%v", store, description, err)
	}
}

func TestOpenObjectStoreRejectsIncompleteS3WithoutLeakingCredentials(t *testing.T) {
	secret := "private-s3-password"
	store, description, err := OpenObjectStore(context.Background(), ObjectStoreConfig{Backend: "s3", AccessKeyID: "private-access-key", SecretAccessKey: secret})
	if err == nil || store != nil || description != "" {
		t.Fatalf("incomplete S3 configuration store=%T description=%q error=%v", store, description, err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "private-access-key") {
		t.Fatalf("S3 error exposed credentials: %v", err)
	}
}

func TestObjectStoreConfigFromEnvMapsRuntimeSettings(t *testing.T) {
	t.Setenv("EVYDENCE_OBJECT_STORE", "filesystem")
	t.Setenv("EVYDENCE_OBJECT_DIR", t.TempDir())
	t.Setenv("EVYDENCE_S3_USE_SSL", "true")
	config := ObjectStoreConfigFromEnv()
	if config.Backend != "filesystem" || config.Directory == "" || !config.UseSSL {
		t.Fatalf("object-store runtime mapping = %#v", config)
	}
}

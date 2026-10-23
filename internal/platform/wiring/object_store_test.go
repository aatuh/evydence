package wiring

import (
	"context"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
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

func TestObjectStoreConfigFromSettingsMapsCapturedValues(t *testing.T) {
	root := t.TempDir()
	environment, err := config.Capture([]string{"EVYDENCE_RUNTIME_PROFILE=postgres", "EVYDENCE_DATABASE_URL=host=fixture", "EVYDENCE_OBJECT_STORE=s3", "EVYDENCE_OBJECT_DIR=" + root, "EVYDENCE_S3_USE_SSL=true", "EVYDENCE_S3_ENDPOINT=storage.example.test:9000", "EVYDENCE_S3_BUCKET=evidence", "EVYDENCE_S3_REGION=eu-west-1", "EVYDENCE_S3_ACCESS_KEY_ID=PRIVATE_ID", "EVYDENCE_S3_SECRET_ACCESS_KEY=PRIVATE_SECRET"})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := config.Parse(environment, config.Worker)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVYDENCE_OBJECT_STORE", "PRIVATE_CHANGED")
	t.Setenv("EVYDENCE_S3_SECRET_ACCESS_KEY", "PRIVATE_CHANGED")
	got := ObjectStoreConfigFromSettings(settings.Storage())
	if got.Backend != "s3" || got.Directory != root || !got.UseSSL || got.Endpoint != "storage.example.test:9000" || got.Bucket != "evidence" || got.Region != "eu-west-1" || got.AccessKeyID != "PRIVATE_ID" || got.SecretAccessKey != "PRIVATE_SECRET" {
		t.Fatal("typed object-store mapping changed or reread input; values withheld")
	}
}

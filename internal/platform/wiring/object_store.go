package wiring

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/app"
	runtimeconfig "github.com/aatuh/evydence/internal/platform/config"
)

// ObjectStoreConfig is the process configuration shared by API and worker
// composition. Credentials are used only for opening the adapter and are
// never included in configuration errors or the returned description.
type ObjectStoreConfig struct {
	Backend         string
	Directory       string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	Region          string
	UseSSL          bool
}

// ObjectStoreConfigFromSettings projects already validated values at the
// infrastructure boundary. It reads no environment or files and adds no defaults.
func ObjectStoreConfigFromSettings(storage runtimeconfig.StorageSettings) ObjectStoreConfig {
	return ObjectStoreConfig{Backend: storage.Kind, Directory: storage.Directory, Endpoint: storage.S3Endpoint, AccessKeyID: storage.S3AccessKeyID.Reveal(), SecretAccessKey: storage.S3SecretAccessKey.Reveal(), Bucket: storage.S3Bucket, Region: storage.S3Region, UseSSL: storage.S3UseSSL}
}

func OpenObjectStore(ctx context.Context, config ObjectStoreConfig) (app.ObjectStore, string, error) {
	if ctx == nil {
		return nil, "", errors.New("object-store context is required")
	}
	backend := strings.ToLower(strings.TrimSpace(config.Backend))
	if backend == "" {
		backend = runtimeconfig.DefaultObjectStoreBackend
	}
	switch backend {
	case "file", "filesystem":
		root := strings.TrimSpace(config.Directory)
		if root == "" {
			root = filepath.FromSlash(runtimeconfig.DefaultObjectDirectory)
		}
		store, err := filesystem.New(root)
		if err != nil {
			return nil, "", err
		}
		return store, "filesystem root " + root, nil
	case "s3", "minio":
		store, err := s3store.New(ctx, s3store.Config{
			Endpoint:        config.Endpoint,
			AccessKeyID:     config.AccessKeyID,
			SecretAccessKey: config.SecretAccessKey,
			Bucket:          config.Bucket,
			Region:          config.Region,
			UseSSL:          config.UseSSL,
		})
		if err != nil {
			return nil, "", err
		}
		return store, "S3-compatible bucket " + strings.TrimSpace(config.Bucket), nil
	default:
		return nil, "", errors.New("unsupported EVYDENCE_OBJECT_STORE")
	}
}

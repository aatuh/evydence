package wiring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/app"
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

func ObjectStoreConfigFromEnv() ObjectStoreConfig {
	return ObjectStoreConfig{
		Backend:         os.Getenv("EVYDENCE_OBJECT_STORE"),
		Directory:       os.Getenv("EVYDENCE_OBJECT_DIR"),
		Endpoint:        os.Getenv("EVYDENCE_S3_ENDPOINT"),
		AccessKeyID:     os.Getenv("EVYDENCE_S3_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("EVYDENCE_S3_SECRET_ACCESS_KEY"),
		Bucket:          os.Getenv("EVYDENCE_S3_BUCKET"),
		Region:          os.Getenv("EVYDENCE_S3_REGION"),
		UseSSL:          strings.EqualFold(strings.TrimSpace(os.Getenv("EVYDENCE_S3_USE_SSL")), "true"),
	}
}

func OpenObjectStore(ctx context.Context, config ObjectStoreConfig) (app.ObjectStore, string, error) {
	if ctx == nil {
		return nil, "", errors.New("object-store context is required")
	}
	switch strings.ToLower(strings.TrimSpace(config.Backend)) {
	case "", "file", "filesystem":
		root := strings.TrimSpace(config.Directory)
		if root == "" {
			root = filepath.Join("tmp", "objects")
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

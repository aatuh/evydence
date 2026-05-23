package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/aatuh/evydence/internal/app"
)

type Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	Region          string
	UseSSL          bool
}

type Store struct {
	client *minio.Client
	bucket string
}

func New(ctx context.Context, cfg Config) (*Store, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	bucket := strings.TrimSpace(cfg.Bucket)
	if endpoint == "" || bucket == "" || strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, app.ErrValidation
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: strings.TrimSpace(cfg.Region),
	})
	if err != nil {
		return nil, fmt.Errorf("create s3 client: %w", err)
	}
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return nil, fmt.Errorf("check s3 bucket: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("s3 bucket %q does not exist", bucket)
	}
	return &Store{client: client, bucket: bucket}, nil
}

func (s *Store) Put(ctx context.Context, object app.Object) error {
	if s == nil || s.client == nil {
		return app.ErrValidation
	}
	if object.Key == "" || object.TenantID == "" || !strings.HasPrefix(object.Key, "tenants/"+object.TenantID+"/") {
		return app.ErrValidation
	}
	opts := minio.PutObjectOptions{
		ContentType: strings.TrimSpace(object.MediaType),
		UserMetadata: map[string]string{
			"evydence-tenant-id": object.TenantID,
			"evydence-digest":    object.Digest,
		},
	}
	_, err := s.client.PutObject(ctx, s.bucket, object.Key, bytes.NewReader(object.Bytes), int64(len(object.Bytes)), opts)
	if err != nil {
		return fmt.Errorf("put s3 object: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key string) (app.Object, error) {
	if s == nil || s.client == nil || strings.TrimSpace(key) == "" {
		return app.Object{}, app.ErrValidation
	}
	obj, err := s.client.GetObject(ctx, s.bucket, strings.TrimSpace(key), minio.GetObjectOptions{})
	if err != nil {
		return app.Object{}, fmt.Errorf("get s3 object: %w", err)
	}
	defer obj.Close()
	info, err := obj.Stat()
	if err != nil {
		return app.Object{}, fmt.Errorf("stat s3 object: %w", err)
	}
	body, err := io.ReadAll(obj)
	if err != nil {
		return app.Object{}, fmt.Errorf("read s3 object: %w", err)
	}
	return app.Object{
		Key:       key,
		TenantID:  metadataValue(info.UserMetadata, "X-Amz-Meta-Evydence-Tenant-Id", "evydence-tenant-id"),
		MediaType: info.ContentType,
		Digest:    metadataValue(info.UserMetadata, "X-Amz-Meta-Evydence-Digest", "evydence-digest"),
		Bytes:     body,
		CreatedAt: info.LastModified,
	}, nil
}

func metadataValue(metadata map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := metadata[key]; value != "" {
			return value
		}
	}
	return ""
}

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
	"github.com/aatuh/evydence/internal/domain"
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

func (s *Store) VerifyObjectRetention(ctx context.Context, req app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	if s == nil || s.client == nil {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	if strings.TrimSpace(req.TenantID) == "" || !strings.HasPrefix(strings.TrimSpace(req.ObjectPrefix), "tenants/"+strings.TrimSpace(req.TenantID)+"/") {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	versioning, err := s.client.GetBucketVersioning(ctx, s.bucket)
	if err != nil {
		return app.ObjectRetentionResult{}, fmt.Errorf("check s3 bucket versioning: %w", err)
	}
	mode, validity, unit, err := s.client.GetBucketObjectLockConfig(ctx, s.bucket)
	if err != nil && !objectLockConfigMissing(err) {
		return app.ObjectRetentionResult{}, fmt.Errorf("check s3 object lock: %w", err)
	}
	return evaluateObjectRetention(req, versioning.Enabled(), mode, validity, unit), nil
}

func metadataValue(metadata map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := metadata[key]; value != "" {
			return value
		}
	}
	return ""
}

func objectLockConfigMissing(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == "NoSuchObjectLockConfiguration" || resp.Code == "ObjectLockConfigurationNotFoundError"
}

func evaluateObjectRetention(req app.ObjectRetentionRequest, versioningEnabled bool, mode *minio.RetentionMode, validity *uint, unit *minio.ValidityUnit) app.ObjectRetentionResult {
	expectedPrefix := "tenants/" + strings.TrimSpace(req.TenantID) + "/"
	prefixOK := strings.HasPrefix(strings.TrimSpace(req.ObjectPrefix), expectedPrefix)
	expectedMode := retentionMode(req.Mode)
	actualMode := ""
	if mode != nil {
		actualMode = strings.ToUpper(mode.String())
	}
	retentionDays := retentionDays(validity, unit)
	modeOK := expectedMode != "" && actualMode == expectedMode
	retentionOK := req.RetentionDays > 0 && retentionDays >= uint(req.RetentionDays)
	checks := []domain.VerifyCheck{
		{Name: "s3_bucket_versioning", Result: checkResult(versioningEnabled), Detail: "Bucket versioning must be enabled for object-lock retention."},
		{Name: "s3_object_lock_mode", Result: checkResult(modeOK), Detail: "Bucket default object-lock mode must match the policy mode."},
		{Name: "s3_object_lock_retention", Result: checkResult(retentionOK), Detail: "Bucket default object-lock retention must meet or exceed the policy duration."},
		{Name: "tenant_object_prefix", Result: checkResult(prefixOK), Detail: "Object prefix must stay under the tenant namespace."},
	}
	return app.ObjectRetentionResult{
		Provider: "s3",
		Enforced: versioningEnabled && modeOK && retentionOK && prefixOK,
		Checks:   checks,
		Limitations: []string{
			"S3/MinIO checks validate bucket-level versioning and default object-lock settings only.",
			"Operators remain responsible for bucket creation mode, IAM policy, lifecycle rules, backups, and deployment-specific retention review.",
		},
	}
}

func retentionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "governance":
		return minio.Governance.String()
	case "compliance":
		return minio.Compliance.String()
	default:
		return ""
	}
}

func retentionDays(validity *uint, unit *minio.ValidityUnit) uint {
	if validity == nil || unit == nil {
		return 0
	}
	switch *unit {
	case minio.Days:
		return *validity
	case minio.Years:
		if *validity > ^uint(0)/365 {
			return ^uint(0)
		}
		return *validity * 365
	default:
		return 0
	}
}

func checkResult(ok bool) string {
	if ok {
		return "passed"
	}
	return "failed"
}

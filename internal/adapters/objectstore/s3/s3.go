package s3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

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
	tenantPrefix := "tenants/" + strings.TrimSpace(req.TenantID) + "/"
	objectPrefix := strings.TrimSpace(req.ObjectPrefix)
	objectKey := strings.TrimSpace(req.ObjectKey)
	if strings.TrimSpace(req.TenantID) == "" || !strings.HasPrefix(objectPrefix, tenantPrefix) {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	if objectKey != "" && (!strings.HasPrefix(objectKey, tenantPrefix) || !strings.HasPrefix(objectKey, objectPrefix)) {
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
	var objectMode *minio.RetentionMode
	var retainUntil *time.Time
	if objectKey != "" {
		objectMode, retainUntil, err = s.client.GetObjectRetention(ctx, s.bucket, objectKey, "")
		if err != nil && !objectLockConfigMissing(err) {
			return app.ObjectRetentionResult{}, fmt.Errorf("check s3 object retention: %w", err)
		}
	}
	return evaluateObjectRetention(req, versioning.Enabled(), mode, validity, unit, objectMode, retainUntil, time.Now().UTC()), nil
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

func evaluateObjectRetention(req app.ObjectRetentionRequest, versioningEnabled bool, mode *minio.RetentionMode, validity *uint, unit *minio.ValidityUnit, objectMode *minio.RetentionMode, retainUntil *time.Time, now time.Time) app.ObjectRetentionResult {
	expectedPrefix := "tenants/" + strings.TrimSpace(req.TenantID) + "/"
	prefixOK := strings.HasPrefix(strings.TrimSpace(req.ObjectPrefix), expectedPrefix)
	objectKey := strings.TrimSpace(req.ObjectKey)
	objectKeyOK := objectKey == "" || (strings.HasPrefix(objectKey, expectedPrefix) && strings.HasPrefix(objectKey, strings.TrimSpace(req.ObjectPrefix)))
	expectedMode := retentionMode(req.Mode)
	actualMode := ""
	if mode != nil {
		actualMode = strings.ToUpper(mode.String())
	}
	actualObjectMode := ""
	if objectMode != nil {
		actualObjectMode = strings.ToUpper(objectMode.String())
	}
	retentionDays := retentionDays(validity, unit)
	modeOK := expectedMode != "" && actualMode == expectedMode
	retentionOK := req.RetentionDays > 0 && retentionDays >= uint(req.RetentionDays)
	objectModeOK := objectKey == "" || (expectedMode != "" && actualObjectMode == expectedMode)
	objectRetainUntilOK := objectKey == "" || (retainUntil != nil && retainUntil.UTC().After(now.Add(time.Duration(req.RetentionDays)*24*time.Hour-time.Second)))
	checks := []domain.VerifyCheck{
		{Name: "s3_bucket_versioning", Result: checkResult(versioningEnabled), Detail: "Bucket versioning must be enabled for object-lock retention."},
		{Name: "s3_object_lock_mode", Result: checkResult(modeOK), Detail: "Bucket default object-lock mode must match the policy mode."},
		{Name: "s3_object_lock_retention", Result: checkResult(retentionOK), Detail: "Bucket default object-lock retention must meet or exceed the policy duration."},
		{Name: "tenant_object_prefix", Result: checkResult(prefixOK), Detail: "Object prefix must stay under the tenant namespace."},
	}
	if objectKey != "" {
		checks = append(checks,
			domain.VerifyCheck{Name: "tenant_object_key", Result: checkResult(objectKeyOK), Detail: "Sample object key must stay under the tenant namespace and configured prefix."},
			domain.VerifyCheck{Name: "s3_object_retention_mode", Result: checkResult(objectModeOK), Detail: "Sample object retention mode must match the policy mode."},
			domain.VerifyCheck{Name: "s3_object_retention_until", Result: checkResult(objectRetainUntilOK), Detail: "Sample object retain-until timestamp must meet or exceed the policy duration."},
		)
	}
	enforced := versioningEnabled && modeOK && retentionOK && prefixOK && objectKeyOK && objectModeOK && objectRetainUntilOK
	limitations := []string{
		"S3/MinIO checks validate bucket-level versioning and default object-lock settings.",
		"Operators remain responsible for bucket creation mode, IAM policy, lifecycle rules, backups, and deployment-specific retention review.",
	}
	if objectKey == "" {
		limitations = append(limitations, "No sample object key was supplied, so object-level retention was not verified.")
	} else {
		limitations = append(limitations, "Object-level retention was checked for the configured sample object key only.")
	}
	return app.ObjectRetentionResult{
		Provider:    "s3",
		Enforced:    enforced,
		Checks:      checks,
		Limitations: limitations,
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

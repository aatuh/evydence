package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

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
	endpoint, region, err := validateEndpointPolicy(cfg.Endpoint, cfg.Region, cfg.UseSSL)
	if err != nil {
		return nil, err
	}
	bucket := strings.TrimSpace(cfg.Bucket)
	if bucket == "" || strings.TrimSpace(cfg.AccessKeyID) == "" || strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, app.ErrValidation
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: region,
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
	if s == nil || s.client == nil || validateObjectForWrite(object) != nil {
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
	if s == nil || s.client == nil {
		return app.Object{}, app.ErrValidation
	}
	tenantID, err := app.TenantIDFromObjectKey(key)
	if err != nil {
		return app.Object{}, app.ErrValidation
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return app.Object{}, fmt.Errorf("get s3 object: %w", err)
	}
	defer obj.Close()
	info, err := obj.Stat()
	if err != nil {
		if s3ObjectMissing(err) {
			return app.Object{}, app.ErrNotFound
		}
		return app.Object{}, fmt.Errorf("stat s3 object: %w", err)
	}
	body, err := io.ReadAll(obj)
	if err != nil {
		return app.Object{}, fmt.Errorf("read s3 object: %w", err)
	}
	object := app.Object{
		Key:       key,
		TenantID:  metadataValue(info.UserMetadata, "X-Amz-Meta-Evydence-Tenant-Id", "evydence-tenant-id"),
		MediaType: info.ContentType,
		Digest:    metadataValue(info.UserMetadata, "X-Amz-Meta-Evydence-Digest", "evydence-digest"),
		Bytes:     body,
		CreatedAt: info.LastModified.UTC(),
	}
	if err := validateObjectRead(tenantID, info.Size, object); err != nil {
		return app.Object{}, err
	}
	return object, nil
}

// ListObjectInventory returns provider object metadata under one tenant
// prefix. It never reads payload bytes and never deletes objects. The numeric
// cursor intentionally avoids placing a key or digest in reconciliation
// receipts; because listing can be eventually consistent, callers must not
// use omission from this result as evidence that an expected object is gone.
func (s *Store) ListObjectInventory(ctx context.Context, tenantID string, cursor, limit int) (app.ObjectInventoryPage, error) {
	if s == nil || s.client == nil || s.bucket == "" || app.ValidateObjectTenantID(tenantID) != nil || cursor < 0 || limit < 1 || limit > 10_000 {
		return app.ObjectInventoryPage{}, app.ErrValidation
	}
	listCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	prefix, err := app.TenantObjectPrefix(tenantID)
	if err != nil {
		return app.ObjectInventoryPage{}, err
	}
	page := app.ObjectInventoryPage{Objects: make([]app.ObjectInventoryItem, 0, limit)}
	matched := 0
	for item := range s.client.ListObjects(listCtx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if item.Err != nil {
			return app.ObjectInventoryPage{}, fmt.Errorf("list s3 object inventory: %w", item.Err)
		}
		if !strings.HasPrefix(item.Key, prefix) || app.ValidateTenantObjectKey(tenantID, item.Key) != nil {
			return app.ObjectInventoryPage{}, app.ErrValidation
		}
		if matched < cursor {
			matched++
			continue
		}
		if len(page.Objects) == limit {
			page.NextCursor = cursor + limit
			break
		}
		page.Objects = append(page.Objects, app.ObjectInventoryItem{
			TenantID:  tenantID,
			Key:       item.Key,
			Size:      item.Size,
			CreatedAt: item.LastModified.UTC(),
		})
		matched++
	}
	return page, nil
}

// StagePayload streams a raw payload to its tenant-scoped staging key while
// independently counting and hashing bytes. The payload is not eligible for a
// domain reader until FinalizePayload has copied and verified it.
func (s *Store) StagePayload(ctx context.Context, payload app.ObjectPayload, reader io.Reader) (app.ObjectPayload, error) {
	if s == nil || s.client == nil || reader == nil || app.ValidateObjectPayloadForRepository(payload) != nil || payload.Status != app.ObjectPayloadStaged {
		return app.ObjectPayload{}, app.ErrValidation
	}
	hash := sha256.New()
	count := &countingWriter{}
	stream := io.TeeReader(reader, io.MultiWriter(hash, count))
	_, err := s.client.PutObject(ctx, s.bucket, payload.StagingKey, stream, -1, minio.PutObjectOptions{
		ContentType: strings.TrimSpace(payload.MediaType),
		PartSize:    5 << 20,
		UserMetadata: map[string]string{
			"evydence-tenant-id": payload.TenantID,
			"evydence-digest":    payload.Digest,
		},
	})
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if err != nil {
		return app.ObjectPayload{}, fmt.Errorf("stage s3 object: %w", err)
	}
	if actualDigest != payload.Digest {
		_ = s.client.RemoveObject(context.WithoutCancel(ctx), s.bucket, payload.StagingKey, minio.RemoveObjectOptions{})
		return app.ObjectPayload{}, app.ErrValidation
	}
	payload.Size = count.n
	payload.UpdatedAt = time.Now().UTC()
	if payload.CreatedAt.IsZero() {
		payload.CreatedAt = payload.UpdatedAt
	}
	return payload, nil
}

// FinalizePayload performs a server-side copy. Existing final objects are
// verified first, making the operation safe after a worker crash between copy
// and lifecycle-state transition.
func (s *Store) FinalizePayload(ctx context.Context, payload app.ObjectPayload) (app.Object, error) {
	if s == nil || s.client == nil || app.ValidateObjectPayloadForRepository(payload) != nil {
		return app.Object{}, app.ErrValidation
	}
	if existing, err := s.Get(ctx, payload.FinalKey); err == nil {
		if err := verifyPayloadObject(payload, existing, payload.FinalKey); err != nil {
			return app.Object{}, err
		}
		_ = s.client.RemoveObject(context.WithoutCancel(ctx), s.bucket, payload.StagingKey, minio.RemoveObjectOptions{})
		return existing, nil
	} else if !errors.Is(err, app.ErrNotFound) {
		return app.Object{}, err
	}
	staged, err := s.Get(ctx, payload.StagingKey)
	if err != nil {
		return app.Object{}, err
	}
	if err := verifyPayloadObject(payload, staged, payload.StagingKey); err != nil {
		return app.Object{}, err
	}
	if _, err := s.client.CopyObject(ctx, minio.CopyDestOptions{
		Bucket:          s.bucket,
		Object:          payload.FinalKey,
		ContentType:     strings.TrimSpace(payload.MediaType),
		UserMetadata:    map[string]string{"evydence-tenant-id": payload.TenantID, "evydence-digest": payload.Digest},
		ReplaceMetadata: true,
	}, minio.CopySrcOptions{Bucket: s.bucket, Object: payload.StagingKey}); err != nil {
		if s3ObjectMissing(err) {
			return app.Object{}, app.ErrNotFound
		}
		return app.Object{}, fmt.Errorf("finalize s3 object: %w", err)
	}
	object, err := s.Get(ctx, payload.FinalKey)
	if err != nil {
		return app.Object{}, err
	}
	if err := verifyPayloadObject(payload, object, payload.FinalKey); err != nil {
		return app.Object{}, err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, payload.StagingKey, minio.RemoveObjectOptions{}); err != nil {
		return app.Object{}, fmt.Errorf("remove staged s3 object: %w", err)
	}
	return object, nil
}

// CheckReadiness verifies bucket access using the configured S3 client.
func (s *Store) CheckReadiness(ctx context.Context) error {
	if s == nil || s.client == nil || strings.TrimSpace(s.bucket) == "" {
		return app.ErrValidation
	}
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check s3 readiness: %w", err)
	}
	if !exists {
		return errors.New("s3 bucket is unavailable")
	}
	return nil
}

func (s *Store) VerifyObjectRetention(ctx context.Context, req app.ObjectRetentionRequest) (app.ObjectRetentionResult, error) {
	if s == nil || s.client == nil {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	tenantPrefix, err := app.TenantObjectPrefix(req.TenantID)
	if err != nil {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	objectPrefix := strings.TrimSpace(req.ObjectPrefix)
	objectKey := strings.TrimSpace(req.ObjectKey)
	if !validTenantObjectPrefix(req.TenantID, objectPrefix) || !strings.HasPrefix(objectPrefix, tenantPrefix) {
		return app.ObjectRetentionResult{}, app.ErrValidation
	}
	if objectKey != "" && (app.ValidateTenantObjectKey(req.TenantID, objectKey) != nil || !strings.HasPrefix(objectKey, objectPrefix)) {
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
	var legalHold *minio.LegalHoldStatus
	if objectKey != "" {
		objectMode, retainUntil, err = s.client.GetObjectRetention(ctx, s.bucket, objectKey, "")
		if err != nil && !objectLockConfigMissing(err) {
			return app.ObjectRetentionResult{}, fmt.Errorf("check s3 object retention: %w", err)
		}
		legalHold, err = s.client.GetObjectLegalHold(ctx, s.bucket, objectKey, minio.GetObjectLegalHoldOptions{})
		if err != nil && !objectLockConfigMissing(err) {
			return app.ObjectRetentionResult{}, fmt.Errorf("check s3 object legal hold: %w", err)
		}
	}
	result := evaluateObjectRetention(req, versioning.Enabled(), mode, validity, unit, objectMode, retainUntil, legalHold, time.Now().UTC())
	result.Bucket = s.bucket
	return result, nil
}

func validateEndpointPolicy(endpoint, region string, useSSL bool) (string, string, error) {
	endpoint = strings.TrimSpace(endpoint)
	region = strings.TrimSpace(region)
	if endpoint == "" || strings.Contains(endpoint, "://") || strings.ContainsAny(endpoint, "/?#") {
		return "", "", app.ErrValidation
	}
	for _, r := range endpoint {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", "", app.ErrValidation
		}
	}
	parsed, err := url.Parse("//" + endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", app.ErrValidation
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || strings.Contains(host, "%") {
		return "", "", app.ErrValidation
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", "", app.ErrValidation
		}
	}
	if region != "" && !validS3Region(region) {
		return "", "", app.ErrValidation
	}
	if isAWSS3Endpoint(host) {
		if !useSSL || region == "" {
			return "", "", app.ErrValidation
		}
	}
	if !useSSL && !insecureS3EndpointAllowed(host) {
		return "", "", app.ErrValidation
	}
	return endpoint, region, nil
}

func validS3Region(region string) bool {
	if region == "" || len(region) > 63 || region != strings.TrimSpace(region) {
		return false
	}
	for index, r := range region {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			if index == 0 && (r == '-' || r == '_' || r == '.') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func isAWSS3Endpoint(host string) bool {
	return host == "s3.amazonaws.com" || strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
}

func insecureS3EndpointAllowed(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	for _, suffix := range []string{".local", ".internal", ".svc", ".svc.cluster.local"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func validateObjectForWrite(object app.Object) error {
	if err := app.ValidateTenantObjectKey(object.TenantID, object.Key); err != nil {
		return app.ErrValidation
	}
	if err := app.ValidateObjectMediaType(object.MediaType); err != nil {
		return app.ErrValidation
	}
	if err := app.VerifyObjectDigestBytes(object.Digest, object.Bytes); err != nil {
		return app.ErrValidation
	}
	return nil
}

func validateObjectRead(keyTenantID string, providerSize int64, object app.Object) error {
	if providerSize < 0 || providerSize != int64(len(object.Bytes)) || object.TenantID != keyTenantID || object.CreatedAt.IsZero() {
		return app.ErrValidation
	}
	return validateObjectForWrite(object)
}

func validTenantObjectPrefix(tenantID, prefix string) bool {
	tenantPrefix, err := app.TenantObjectPrefix(tenantID)
	if err != nil || prefix == "" || prefix != strings.TrimSpace(prefix) || !strings.HasPrefix(prefix, tenantPrefix) {
		return false
	}
	candidate := strings.TrimSuffix(prefix, "/") + "/prefix-check"
	return app.ValidateTenantObjectKey(tenantID, candidate) == nil
}

func metadataValue(metadata map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := metadata[key]; value != "" {
			return value
		}
		for candidate, value := range metadata {
			if strings.EqualFold(candidate, key) && value != "" {
				return value
			}
		}
	}
	return ""
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(value []byte) (int, error) {
	w.n += int64(len(value))
	return len(value), nil
}

func verifyPayloadObject(payload app.ObjectPayload, object app.Object, key string) error {
	return app.VerifyObjectPayloadRead(payload, object, key)
}

func s3ObjectMissing(err error) bool {
	response := minio.ToErrorResponse(err)
	return response.Code == "NoSuchKey" || response.Code == "NoSuchObject" || response.Code == "NotFound"
}

func objectLockConfigMissing(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == "NoSuchObjectLockConfiguration" || resp.Code == "ObjectLockConfigurationNotFoundError"
}

func evaluateObjectRetention(req app.ObjectRetentionRequest, versioningEnabled bool, mode *minio.RetentionMode, validity *uint, unit *minio.ValidityUnit, objectMode *minio.RetentionMode, retainUntil *time.Time, legalHold *minio.LegalHoldStatus, now time.Time) app.ObjectRetentionResult {
	objectPrefix := strings.TrimSpace(req.ObjectPrefix)
	prefixOK := validTenantObjectPrefix(req.TenantID, objectPrefix)
	objectKey := strings.TrimSpace(req.ObjectKey)
	objectKeyOK := objectKey == "" || (app.ValidateTenantObjectKey(req.TenantID, objectKey) == nil && strings.HasPrefix(objectKey, objectPrefix))
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
	recordedRetentionDays, retentionDaysRepresentable := retentionDaysForRecord(retentionDays)
	modeOK := expectedMode != "" && actualMode == expectedMode
	retentionOK := retentionDaysRepresentable && req.RetentionDays > 0 && retentionDays >= uint(req.RetentionDays)
	objectModeOK := objectKey == "" || (expectedMode != "" && actualObjectMode == expectedMode)
	objectRetainUntilOK := objectKey == "" || (retainUntil != nil && retainUntil.UTC().After(now.Add(time.Duration(req.RetentionDays)*24*time.Hour-time.Second)))
	legalHoldObserved := objectKey == "" || legalHold != nil
	legalHoldOK := !req.RequireLegalHold || (objectKey != "" && legalHold != nil && *legalHold == minio.LegalHoldEnabled)
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
			domain.VerifyCheck{Name: "s3_object_legal_hold_observed", Result: checkResult(legalHoldObserved), Detail: "Sample object legal-hold state must be observed for a positive provider result."},
		)
	}
	if req.RequireLegalHold {
		checks = append(checks, domain.VerifyCheck{Name: "s3_object_legal_hold", Result: checkResult(legalHoldOK), Detail: "Sample object legal hold must be enabled when the policy requires legal hold proof."})
	}
	enforced := versioningEnabled && modeOK && retentionOK && prefixOK && objectKeyOK && objectModeOK && objectRetainUntilOK && legalHoldObserved && legalHoldOK
	limitations := []string{
		"S3/MinIO checks validate bucket-level versioning and default object-lock settings.",
		"Operators remain responsible for bucket creation mode, IAM policy, lifecycle rules, backups, and deployment-specific retention review.",
	}
	if objectKey == "" {
		limitations = append(limitations, "No sample object key was supplied, so object-level retention was not verified.")
	} else {
		limitations = append(limitations, "Object-level retention was checked for the configured sample object key only.")
	}
	if req.RequireLegalHold {
		limitations = append(limitations, "Object-level legal hold was checked for the configured sample object key only.")
	}
	if !retentionDaysRepresentable {
		limitations = append(limitations, "Provider-reported retention duration exceeds this process's representable record range and is not treated as a positive observation.")
	}
	return app.ObjectRetentionResult{
		Provider:      "s3",
		ObjectKey:     objectKey,
		Mode:          actualMode,
		RetentionDays: recordedRetentionDays,
		LegalHold:     legalHoldEnabled(legalHold),
		ObservedAt:    now.UTC(),
		Enforced:      enforced,
		Checks:        checks,
		Limitations:   limitations,
	}
}

func retentionDaysForRecord(value uint) (int, bool) {
	maxInt := uint(^uint(0) >> 1)
	if value > maxInt {
		return 0, false
	}
	return int(value), true // #nosec G115 -- value is bounded by the target architecture's maximum int above.
}

func legalHoldEnabled(value *minio.LegalHoldStatus) *bool {
	if value == nil {
		return nil
	}
	enabled := *value == minio.LegalHoldEnabled
	return &enabled
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

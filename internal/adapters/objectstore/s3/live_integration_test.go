package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/aatuh/evydence/internal/app"
)

func TestMinIOIntegrationStagesFinalizesMultipartAndChecksObjectLock(t *testing.T) {
	cfg := liveMinIOConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		t.Fatal(err)
	}
	bucket := liveMinIOBucketName(t)
	if err := admin.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: cfg.Region, ObjectLocking: true}); err != nil {
		t.Fatalf("create isolated MinIO bucket: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := removeLiveMinIOBucket(cleanupCtx, admin, bucket); err != nil {
			t.Errorf("clean isolated MinIO bucket: %v", err)
		}
	})

	store, err := New(ctx, Config{
		Endpoint:        cfg.Endpoint,
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
		Bucket:          bucket,
		Region:          cfg.Region,
		UseSSL:          cfg.UseSSL,
	})
	if err != nil {
		t.Fatalf("open store for isolated bucket: %v", err)
	}
	const multipartPayloadSize = (5 << 20) + 257
	payloadChunk := []byte("evydence-minio-integration-payload")
	body := bytes.Repeat(payloadChunk, (multipartPayloadSize+len(payloadChunk)-1)/len(payloadChunk))
	body = body[:multipartPayloadSize]
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	stagingKey, finalKey, err := app.CanonicalObjectPayloadKeys("ten_minio_live", digest)
	if err != nil {
		t.Fatal(err)
	}
	payload := app.ObjectPayload{
		TenantID:   "ten_minio_live",
		Digest:     digest,
		MediaType:  "application/octet-stream",
		StagingKey: stagingKey,
		FinalKey:   finalKey,
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	payload, err = store.StagePayload(ctx, payload, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("stage multipart payload: %v", err)
	}
	if payload.Size != int64(len(body)) {
		t.Fatalf("staged payload size = %d, want %d", payload.Size, len(body))
	}
	staged, err := store.Get(ctx, stagingKey)
	if err != nil || !bytes.Equal(staged.Bytes, body) {
		t.Fatalf("read staged payload: object=%d bytes err=%v", len(staged.Bytes), err)
	}
	final, err := store.FinalizePayload(ctx, payload)
	if err != nil {
		t.Fatalf("finalize payload: %v", err)
	}
	if final.Key != finalKey || !bytes.Equal(final.Bytes, body) {
		t.Fatalf("final payload does not match staged payload")
	}
	if _, err := store.Get(ctx, stagingKey); err == nil {
		t.Fatal("staging object remained visible after finalization")
	}
	if _, err := store.FinalizePayload(ctx, payload); err != nil {
		t.Fatalf("retry finalization after response loss: %v", err)
	}
	page, err := store.ListObjectInventory(ctx, "ten_minio_live", 0, 10)
	if err != nil || len(page.Objects) != 1 || page.Objects[0].Key != finalKey {
		t.Fatalf("isolated tenant inventory = %#v, err=%v", page, err)
	}

	mode := minio.Compliance
	validity := uint(1)
	unit := minio.Days
	if err := admin.SetBucketObjectLockConfig(ctx, bucket, &mode, &validity, &unit); err != nil {
		t.Fatalf("configure MinIO object-lock capability: %v", err)
	}
	retention, err := store.VerifyObjectRetention(ctx, app.ObjectRetentionRequest{
		TenantID:      "ten_minio_live",
		ObjectPrefix:  "tenants/ten_minio_live/payloads/",
		Mode:          "compliance",
		RetentionDays: 1,
	})
	if err != nil || !retention.Enforced {
		t.Fatalf("live MinIO object-lock verification = %#v, err=%v", retention, err)
	}
}

func TestMinIOIntegrationRejectsMissingBucket(t *testing.T) {
	cfg := liveMinIOConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := New(ctx, Config{
		Endpoint:        cfg.Endpoint,
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: cfg.SecretAccessKey,
		Bucket:          liveMinIOBucketName(t),
		Region:          cfg.Region,
		UseSSL:          cfg.UseSSL,
	}); err == nil {
		t.Fatal("adapter accepted an isolated bucket that does not exist")
	}
}

func liveMinIOConfig(t *testing.T) Config {
	t.Helper()
	endpoint := strings.TrimSpace(os.Getenv("EVYDENCE_TEST_S3_ENDPOINT"))
	accessKeyID := strings.TrimSpace(os.Getenv("EVYDENCE_TEST_S3_ACCESS_KEY_ID"))
	secretAccessKey := strings.TrimSpace(os.Getenv("EVYDENCE_TEST_S3_SECRET_ACCESS_KEY"))
	if endpoint == "" || accessKeyID == "" || secretAccessKey == "" {
		t.Skip("EVYDENCE_TEST_S3_ENDPOINT, EVYDENCE_TEST_S3_ACCESS_KEY_ID, and EVYDENCE_TEST_S3_SECRET_ACCESS_KEY are required")
	}
	useSSL := false
	if raw := strings.TrimSpace(os.Getenv("EVYDENCE_TEST_S3_USE_SSL")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatal("EVYDENCE_TEST_S3_USE_SSL must be a boolean")
		}
		useSSL = value
	}
	return Config{Endpoint: endpoint, AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, Region: "us-east-1", UseSSL: useSSL}
}

func liveMinIOBucketName(t *testing.T) string {
	t.Helper()
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	return "evydence-it-" + hex.EncodeToString(entropy[:])
}

func removeLiveMinIOBucket(ctx context.Context, client *minio.Client, bucket string) error {
	for object := range client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
		if object.Err != nil {
			return object.Err
		}
		if err := client.RemoveObject(ctx, bucket, object.Key, minio.RemoveObjectOptions{VersionID: object.VersionID}); err != nil {
			return err
		}
	}
	return client.RemoveBucket(ctx, bucket)
}

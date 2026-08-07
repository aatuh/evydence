package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/aatuh/evydence/internal/app"
)

type fakeS3Object struct {
	body        []byte
	contentType string
	tenantID    string
	digest      string
}

type fakeS3Server struct {
	mu      sync.Mutex
	objects map[string]fakeS3Object
}

func newFakeS3Store(t *testing.T) *Store {
	t.Helper()
	server := &fakeS3Server{objects: map[string]fakeS3Object{}}
	httpServer := httptest.NewServer(http.HandlerFunc(server.handle))
	t.Cleanup(httpServer.Close)
	client, err := minio.New(strings.TrimPrefix(httpServer.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("access", "secret", ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	return &Store{client: client, bucket: "evidence"}
}

func (s *fakeS3Server) handle(w http.ResponseWriter, r *http.Request) {
	if (r.URL.EscapedPath() == "/evidence" || r.URL.EscapedPath() == "/evidence/") && r.URL.Query().Get("list-type") != "2" {
		if _, ok := r.URL.Query()["location"]; ok {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method == http.MethodGet && (r.URL.EscapedPath() == "/evidence" || r.URL.EscapedPath() == "/evidence/") && r.URL.Query().Get("list-type") == "2" {
		prefix := r.URL.Query().Get("prefix")
		s.mu.Lock()
		keys := make([]string, 0, len(s.objects))
		for key := range s.objects {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		s.mu.Unlock()
		sort.Strings(keys)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>evidence</Name><Prefix>`+escapeFakeS3XML(prefix)+`</Prefix><KeyCount>`+strconv.Itoa(len(keys))+`</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`)
		for _, key := range keys {
			s.mu.Lock()
			object := s.objects[key]
			s.mu.Unlock()
			_, _ = io.WriteString(w, `<Contents><Key>`+escapeFakeS3XML(key)+`</Key><LastModified>2026-07-28T08:00:00.000Z</LastModified><ETag>"etag"</ETag><Size>`+strconv.Itoa(len(object.body))+`</Size><StorageClass>STANDARD</StorageClass></Contents>`)
		}
		_, _ = io.WriteString(w, `</ListBucketResult>`)
		return
	}
	key := strings.TrimPrefix(r.URL.EscapedPath(), "/evidence/")
	key, _ = url.PathUnescape(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodPost && r.URL.Query().Has("uploads") {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><Bucket>evidence</Bucket><Key>payload</Key><UploadId>upload</UploadId></InitiateMultipartUploadResult>`)
		return
	}
	if r.Method == http.MethodPut && r.URL.Query().Get("uploadId") != "" {
		body, _ := io.ReadAll(r.Body)
		parts := strings.Split(key, "/")
		tenantID, digest := "", ""
		if len(parts) >= 4 && parts[0] == "tenants" {
			tenantID, digest = parts[1], "sha256:"+parts[len(parts)-1]
		}
		object := s.objects[key]
		object.body = append(object.body, decodeFakeS3Body(body)...)
		object.contentType = r.Header.Get("Content-Type")
		object.tenantID, object.digest = tenantID, digest
		s.objects[key] = object
		w.Header().Set("ETag", `"etag"`)
		return
	}
	if r.Method == http.MethodPost && r.URL.Query().Get("uploadId") != "" {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><Location>http://example.test/evidence/payload</Location><Bucket>evidence</Bucket><Key>payload</Key><ETag>"etag"</ETag></CompleteMultipartUploadResult>`)
		return
	}
	if r.Method == http.MethodPut {
		if source := r.Header.Get("X-Amz-Copy-Source"); source != "" {
			source, _ = url.PathUnescape(strings.TrimPrefix(source, "/"))
			source = strings.TrimPrefix(source, "evidence/")
			object, ok := s.objects[source]
			if !ok {
				writeFakeS3Missing(w)
				return
			}
			s.objects[key] = object
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<CopyObjectResult><ETag>"etag"</ETag><LastModified>2026-07-28T08:00:00Z</LastModified></CopyObjectResult>`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		tenantID, digest := fakeS3Metadata(r, "evydence-tenant-id"), fakeS3Metadata(r, "evydence-digest")
		if tenantID == "" || digest == "" {
			parts := strings.Split(key, "/")
			if len(parts) >= 4 && parts[0] == "tenants" {
				tenantID = parts[1]
				digest = "sha256:" + parts[len(parts)-1]
			}
		}
		s.objects[key] = fakeS3Object{body: decodeFakeS3Body(body), contentType: r.Header.Get("Content-Type"), tenantID: tenantID, digest: digest}
		w.Header().Set("ETag", `"etag"`)
		return
	}
	object, ok := s.objects[key]
	if !ok {
		writeFakeS3Missing(w)
		return
	}
	switch r.Method {
	case http.MethodHead:
		w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
		w.Header().Set("Content-Type", object.contentType)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("X-Amz-Meta-Evydence-Tenant-Id", object.tenantID)
		w.Header().Set("X-Amz-Meta-Evydence-Digest", object.digest)
		w.Header().Set("evydence-tenant-id", object.tenantID)
		w.Header().Set("evydence-digest", object.digest)
		w.Header().Set("ETag", `"etag"`)
	case http.MethodGet:
		w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
		w.Header().Set("Content-Type", object.contentType)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("X-Amz-Meta-Evydence-Tenant-Id", object.tenantID)
		w.Header().Set("X-Amz-Meta-Evydence-Digest", object.digest)
		w.Header().Set("evydence-tenant-id", object.tenantID)
		w.Header().Set("evydence-digest", object.digest)
		_, _ = w.Write(object.body)
	case http.MethodDelete:
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func escapeFakeS3XML(value string) string {
	var body bytes.Buffer
	_ = xml.EscapeText(&body, []byte(value))
	return body.String()
}

func decodeFakeS3Body(body []byte) []byte {
	if !bytes.Contains(body, []byte(";chunk-signature=")) {
		return body
	}
	var decoded []byte
	for len(body) > 0 {
		lineEnd := bytes.Index(body, []byte("\r\n"))
		if lineEnd < 0 {
			return body
		}
		sizeText := strings.SplitN(string(body[:lineEnd]), ";", 2)[0]
		size, err := strconv.ParseInt(sizeText, 16, 64)
		if err != nil || size == 0 || int64(len(body)) < int64(lineEnd+2)+size+2 {
			return decoded
		}
		start := lineEnd + 2
		decoded = append(decoded, body[start:start+int(size)]...)
		body = body[start+int(size)+2:]
	}
	return decoded
}

func fakeS3Metadata(request *http.Request, suffix string) string {
	for key, values := range request.Header {
		if strings.EqualFold(key, "X-Amz-Meta-"+suffix) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func writeFakeS3Missing(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>`)
}

func TestNewRejectsIncompleteConfigWithoutNetwork(t *testing.T) {
	_, err := New(context.Background(), Config{Endpoint: "localhost:9000", Bucket: "evydence"})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatalf("err = %v, want validation", err)
	}
}

func TestPutGetRejectUninitializedStoreAndUnsafeKeys(t *testing.T) {
	if err := (*Store)(nil).Put(context.Background(), app.Object{Key: "tenants/ten_1/raw", TenantID: "ten_1"}); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil put err = %v, want validation", err)
	}
	if _, err := (*Store)(nil).Get(context.Background(), "tenants/ten_1/raw"); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil get err = %v, want validation", err)
	}

	store := &Store{}
	err := store.Put(context.Background(), app.Object{Key: "tenants/other/raw", TenantID: "ten_1"})
	if !errors.Is(err, app.ErrValidation) {
		t.Fatalf("cross-tenant key err = %v, want validation", err)
	}
	if _, err := store.Get(context.Background(), ""); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("empty key err = %v, want validation", err)
	}
	if err := (*Store)(nil).CheckReadiness(context.Background()); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil readiness err = %v, want validation", err)
	}
}

func TestStorePutGetAndFinalizePayloadAgainstS3Protocol(t *testing.T) {
	store := newFakeS3Store(t)
	body := []byte("S3 payload")
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	now := time.Now().UTC()
	payload := app.ObjectPayload{
		TenantID:   "ten_1",
		Digest:     digest,
		Size:       int64(len(body)),
		MediaType:  "application/json",
		StagingKey: "tenants/ten_1/staging/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		FinalKey:   "tenants/ten_1/payloads/sha256/" + strings.TrimPrefix(digest, "sha256:"),
		Status:     app.ObjectPayloadStaged,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	stagedPayload, err := store.StagePayload(context.Background(), payload, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("stage payload: %v", err)
	}
	if stagedPayload.Size != int64(len(body)) || stagedPayload.Digest != digest {
		t.Fatalf("staged payload metadata=%#v", stagedPayload)
	}
	staged, err := store.Get(context.Background(), payload.StagingKey)
	if err != nil || staged.TenantID != payload.TenantID || staged.Digest != digest || string(staged.Bytes) != string(body) {
		t.Fatalf("get staged object=%#v err=%v", staged, err)
	}
	final, err := store.FinalizePayload(context.Background(), payload)
	if err != nil || final.Key != payload.FinalKey || final.Digest != digest || string(final.Bytes) != string(body) {
		t.Fatalf("finalize object=%#v err=%v", final, err)
	}
	if _, err := store.Get(context.Background(), payload.StagingKey); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("staging object after finalize err=%v, want not found", err)
	}
	if _, err := store.FinalizePayload(context.Background(), payload); err != nil {
		t.Fatalf("repeat finalization: %v", err)
	}
	if _, err := (*Store)(nil).StagePayload(context.Background(), payload, strings.NewReader(string(body))); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil staged store error=%v, want validation", err)
	}
	if _, err := (*Store)(nil).FinalizePayload(context.Background(), payload); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("nil finalizer error=%v, want validation", err)
	}
}

func TestStoreListsTenantObjectInventory(t *testing.T) {
	store := newFakeS3Store(t)
	for _, object := range []app.Object{
		s3InventoryObject("ten_1", "tenants/ten_1/payloads/sha256/001", []byte("one")),
		s3InventoryObject("ten_1", "tenants/ten_1/staging/sha256/002", []byte("two")),
		s3InventoryObject("ten_2", "tenants/ten_2/payloads/sha256/003", []byte("three")),
	} {
		if err := store.Put(t.Context(), object); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.ListObjectInventory(t.Context(), "ten_1", 0, 1)
	if err != nil || len(page.Objects) != 1 || page.NextCursor != 1 || page.Objects[0].TenantID != "ten_1" {
		t.Fatalf("first s3 inventory page=%#v err=%v", page, err)
	}
	page, err = store.ListObjectInventory(t.Context(), "ten_1", page.NextCursor, 1)
	if err != nil || len(page.Objects) != 1 || page.NextCursor != 0 {
		t.Fatalf("second s3 inventory page=%#v err=%v", page, err)
	}
	if _, err := store.ListObjectInventory(t.Context(), "../ten_2", 0, 1); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("unsafe tenant inventory err=%v, want validation", err)
	}
}

func s3InventoryObject(tenantID, key string, body []byte) app.Object {
	sum := sha256.Sum256(body)
	return app.Object{Key: key, TenantID: tenantID, Digest: "sha256:" + hex.EncodeToString(sum[:]), Bytes: body, CreatedAt: time.Now().UTC()}
}

func TestS3PayloadHelpersRejectMismatchedObject(t *testing.T) {
	payload := app.ObjectPayload{TenantID: "ten_1", Digest: "sha256:" + strings.Repeat("a", 64), Size: 3, StagingKey: "tenants/ten_1/staging/a", FinalKey: "tenants/ten_1/payloads/a", Status: app.ObjectPayloadStaged, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := verifyPayloadObject(payload, app.Object{Key: payload.FinalKey, TenantID: payload.TenantID, Digest: payload.Digest, Bytes: []byte("too-long")}, payload.FinalKey); !errors.Is(err, app.ErrValidation) {
		t.Fatalf("mismatched object error=%v, want validation", err)
	}
	writer := &countingWriter{}
	if count, err := writer.Write([]byte("count")); err != nil || count != 5 || writer.n != 5 {
		t.Fatalf("counting writer count=%d n=%d err=%v", count, writer.n, err)
	}
	if !s3ObjectMissing(minio.ErrorResponse{Code: "NoSuchKey"}) || !objectLockConfigMissing(minio.ErrorResponse{Code: "NoSuchObjectLockConfiguration"}) {
		t.Fatal("S3 provider error classifiers did not recognize stable missing codes")
	}
}

func TestMetadataValueUsesFirstNonEmptyKey(t *testing.T) {
	metadata := map[string]string{
		"X-Amz-Meta-Evydence-Tenant-Id": "",
		"evydence-tenant-id":            "ten_1",
		"evydence-digest":               "sha256:abc",
	}
	if got := metadataValue(metadata, "X-Amz-Meta-Evydence-Tenant-Id", "evydence-tenant-id"); got != "ten_1" {
		t.Fatalf("tenant metadata = %q", got)
	}
	if got := metadataValue(metadata, "missing", "evydence-digest"); got != "sha256:abc" {
		t.Fatalf("digest metadata = %q", got)
	}
	if got := metadataValue(metadata, "missing"); got != "" {
		t.Fatalf("missing metadata = %q", got)
	}
}

func TestEvaluateObjectRetentionRequiresVersioningLockAndTenantPrefix(t *testing.T) {
	mode := minio.Compliance
	validity := uint(90)
	unit := minio.Days
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/ten_1/raw/",
		Mode:          "compliance",
		RetentionDays: 30,
	}, true, &mode, &validity, &unit, nil, nil, nil, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if !result.Enforced {
		t.Fatalf("expected enforced retention: %#v", result)
	}
	if len(result.Checks) != 4 || result.Checks[0].Result != "passed" {
		t.Fatalf("checks = %#v", result.Checks)
	}
	if len(result.Limitations) == 0 {
		t.Fatal("expected limitations")
	}
	if result.Provider != "s3" || result.Mode != minio.Compliance.String() || result.RetentionDays != 90 || !result.ObservedAt.Equal(time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("provider observation metadata = %#v", result)
	}
}

func TestEvaluateObjectRetentionReportsMissingProviderControls(t *testing.T) {
	mode := minio.Governance
	validity := uint(1)
	unit := minio.Days
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/other/raw/",
		Mode:          "compliance",
		RetentionDays: 30,
	}, false, &mode, &validity, &unit, nil, nil, nil, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if result.Enforced {
		t.Fatalf("unexpected enforced retention: %#v", result)
	}
	failed := 0
	for _, check := range result.Checks {
		if check.Result == "failed" {
			failed++
		}
	}
	if failed != 4 {
		t.Fatalf("failed checks = %d, checks = %#v", failed, result.Checks)
	}
}

func TestEvaluateObjectRetentionRejectsUnrepresentableProviderDuration(t *testing.T) {
	mode := minio.Compliance
	validity := ^uint(0)
	unit := minio.Days
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/ten_1/raw/",
		Mode:          "compliance",
		RetentionDays: 30,
	}, true, &mode, &validity, &unit, nil, nil, nil, time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC))
	if result.Enforced || result.RetentionDays != 0 {
		t.Fatalf("unrepresentable provider duration must not be positive evidence: %#v", result)
	}
	if len(result.Limitations) == 0 || result.Checks[2].Result != "failed" {
		t.Fatalf("unrepresentable provider duration checks = %#v", result)
	}
}

func TestEvaluateObjectRetentionChecksSampleObjectRetention(t *testing.T) {
	mode := minio.Compliance
	validity := uint(90)
	unit := minio.Days
	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	retainUntil := now.Add(45 * 24 * time.Hour)
	legalHold := minio.LegalHoldDisabled
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:      "ten_1",
		ObjectPrefix:  "tenants/ten_1/raw/",
		ObjectKey:     "tenants/ten_1/raw/sample.json",
		Mode:          "compliance",
		RetentionDays: 30,
	}, true, &mode, &validity, &unit, &mode, &retainUntil, &legalHold, now)
	if !result.Enforced {
		t.Fatalf("expected object-level enforced retention: %#v", result)
	}
	if len(result.Checks) != 8 {
		t.Fatalf("checks = %#v", result.Checks)
	}
}

func TestEvaluateObjectRetentionChecksRequiredLegalHold(t *testing.T) {
	mode := minio.Compliance
	validity := uint(90)
	unit := minio.Days
	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	retainUntil := now.Add(45 * 24 * time.Hour)
	legalHold := minio.LegalHoldEnabled
	result := evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:         "ten_1",
		ObjectPrefix:     "tenants/ten_1/raw/",
		ObjectKey:        "tenants/ten_1/raw/sample.json",
		Mode:             "compliance",
		RetentionDays:    30,
		RequireLegalHold: true,
	}, true, &mode, &validity, &unit, &mode, &retainUntil, &legalHold, now)
	if !result.Enforced {
		t.Fatalf("expected legal-hold enforced retention: %#v", result)
	}
	if got := result.Checks[len(result.Checks)-1]; got.Name != "s3_object_legal_hold" || got.Result != "passed" {
		t.Fatalf("legal hold check = %#v", got)
	}

	legalHold = minio.LegalHoldDisabled
	result = evaluateObjectRetention(app.ObjectRetentionRequest{
		TenantID:         "ten_1",
		ObjectPrefix:     "tenants/ten_1/raw/",
		ObjectKey:        "tenants/ten_1/raw/sample.json",
		Mode:             "compliance",
		RetentionDays:    30,
		RequireLegalHold: true,
	}, true, &mode, &validity, &unit, &mode, &retainUntil, &legalHold, now)
	if result.Enforced {
		t.Fatalf("disabled legal hold should not be enforced: %#v", result)
	}
}

func TestRetentionDaysConvertsYears(t *testing.T) {
	validity := uint(2)
	unit := minio.Years
	if got := retentionDays(&validity, &unit); got != uint(730) {
		t.Fatalf("retention days = %d", got)
	}
}

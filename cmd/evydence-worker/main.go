package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
)

const defaultMaxWorkerPayloadBytes = 20 << 20

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("worker requires EVYDENCE_DATABASE_URL")
	}
	ctx := context.Background()
	store, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer store.Close()
	if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
		migrateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := store.ApplyMigrations(migrateCtx, envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")); err != nil {
			cancel()
			return err
		}
		cancel()
	}
	objectStore, objectDescription, err := openObjectStore(ctx)
	if err != nil {
		return err
	}
	pollInterval := durationEnv("EVYDENCE_WORKER_POLL_INTERVAL", time.Second)
	batchSize := intEnv("EVYDENCE_WORKER_BATCH_SIZE", 10)
	log.Printf("evydence worker started with postgres outbox, %s object store, polling interval %s", objectDescription, pollInterval)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs, err := store.ClaimJobs(ctx, batchSize)
		if err != nil {
			log.Printf("outbox claim failed: %v", err)
			time.Sleep(pollInterval)
			continue
		}
		if len(jobs) == 0 {
			time.Sleep(pollInterval)
			continue
		}
		for _, job := range jobs {
			log.Printf("processing outbox job id=%s kind=%s subject_type=%s subject_id=%s attempt=%d", job.ID, job.Kind, job.SubjectType, job.SubjectID, job.Attempts)
			if err := processJobWithObjects(ctx, store, objectStore, job); err != nil {
				log.Printf("outbox job failed id=%s kind=%s: %v", job.ID, job.Kind, err)
				if failErr := store.FailJob(ctx, job.ID, err); failErr != nil {
					log.Printf("record outbox failure failed id=%s: %v", job.ID, failErr)
				}
				continue
			}
			if err := store.CompleteJob(ctx, job.ID); err != nil {
				log.Printf("complete outbox job failed id=%s: %v", job.ID, err)
			}
		}
	}
}

type jobStateLoader interface {
	LoadState(context.Context) (app.PersistedState, bool, error)
}

type jobObjectGetter interface {
	Get(context.Context, string) (app.Object, error)
}

func processJob(ctx context.Context, state jobStateLoader, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, nil, job, false)
}

func processJobWithObjects(ctx context.Context, state jobStateLoader, objects jobObjectGetter, job postgres.ClaimedJob) error {
	return processJobInternal(ctx, state, objects, job, true)
}

func processJobInternal(ctx context.Context, state jobStateLoader, objects jobObjectGetter, job postgres.ClaimedJob, requireObjectReplay bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state == nil {
		return errors.New("outbox job handler requires durable state")
	}
	if requireObjectReplay {
		if err := verifyJobObject(ctx, objects, job); err != nil {
			return err
		}
	}
	snapshot, ok, err := state.LoadState(ctx)
	if err != nil {
		return errors.New("load durable state for outbox job")
	}
	if !ok {
		return errors.New("durable state is not initialized")
	}
	switch job.Kind {
	case "parse_sbom":
		sbom, ok := snapshot.SBOMs[job.SubjectID]
		if !ok || sbom.TenantID != job.TenantID {
			return errors.New("parsed sbom is not available in durable state")
		}
		return requirePayloadHash(job, "")
	case "parse_vulnerability_scan":
		scan, ok := snapshot.Scans[job.SubjectID]
		if !ok || scan.TenantID != job.TenantID {
			return errors.New("parsed vulnerability scan is not available in durable state")
		}
		return requirePayloadHash(job, "")
	case "parse_openapi_contract":
		contract, ok := snapshot.Contracts[job.SubjectID]
		if !ok || contract.TenantID != job.TenantID {
			return errors.New("parsed openapi contract is not available in durable state")
		}
		return requirePayloadHash(job, contract.Hash)
	case "parse_vex":
		vex, ok := snapshot.VEXDocuments[job.SubjectID]
		if !ok || vex.TenantID != job.TenantID {
			return errors.New("parsed vex document is not available in durable state")
		}
		return requirePayloadHash(job, "")
	case "sign_bundle":
		bundle, ok := snapshot.Bundles[job.SubjectID]
		if !ok || bundle.TenantID != job.TenantID {
			return errors.New("release bundle is not available in durable state")
		}
		if len(bundle.SignatureRefs) == 0 {
			return errors.New("release bundle signature is missing")
		}
		return requirePayloadHash(job, bundle.ManifestHash)
	case "verify_subject":
		resultID := payloadString(job, "result_id")
		if resultID == "" {
			return errors.New("verification result reference is missing")
		}
		result, ok := snapshot.Verifications[resultID]
		if !ok || result.TenantID != job.TenantID || result.SubjectType != job.SubjectType || result.SubjectID != job.SubjectID {
			return errors.New("verification result is not available in durable state")
		}
		if result.Result == "" {
			return errors.New("verification result is incomplete")
		}
		return nil
	case "verify_attestation":
		attestation, ok := snapshot.BuildAttestations[job.SubjectID]
		if !ok || attestation.TenantID != job.TenantID {
			return errors.New("build attestation is not available in durable state")
		}
		if attestation.VerificationStatus == "" {
			return errors.New("build attestation verification status is incomplete")
		}
		return requirePayloadHash(job, attestation.PayloadHash)
	default:
		return errors.New("unsupported outbox job kind")
	}
}

func verifyJobObject(ctx context.Context, objects jobObjectGetter, job postgres.ClaimedJob) error {
	key := payloadString(job, "payload_ref")
	if key == "" {
		return nil
	}
	if !strings.HasPrefix(key, "tenants/"+job.TenantID+"/") {
		return errors.New("outbox payload object key is not tenant-prefixed")
	}
	if objects == nil {
		return errors.New("outbox object store is not configured")
	}
	object, err := objects.Get(ctx, key)
	if err != nil {
		return errors.New("read outbox payload object")
	}
	if object.TenantID != "" && object.TenantID != job.TenantID {
		return errors.New("outbox payload object tenant mismatch")
	}
	if len(object.Bytes) > intEnv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", defaultMaxWorkerPayloadBytes) {
		return errors.New("outbox payload object exceeds worker size limit")
	}
	want := payloadString(job, "payload_hash")
	if want == "" {
		return nil
	}
	if object.Digest != "" && object.Digest != want {
		return errors.New("outbox payload object metadata digest mismatch")
	}
	if digestBytes(object.Bytes) != want {
		return errors.New("outbox payload object digest mismatch")
	}
	return nil
}

func requirePayloadHash(job postgres.ClaimedJob, recordedHash string) error {
	want := payloadString(job, "payload_hash")
	if want == "" || recordedHash == "" {
		return nil
	}
	if want != recordedHash {
		return errors.New("outbox payload hash does not match durable state")
	}
	return nil
}

func payloadString(job postgres.ClaimedJob, key string) string {
	if job.Payload == nil {
		return ""
	}
	value, _ := job.Payload[key].(string)
	return strings.TrimSpace(value)
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func intEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func openObjectStore(ctx context.Context) (app.ObjectStore, string, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EVYDENCE_OBJECT_STORE"))) {
	case "", "file", "filesystem":
		objectRoot := envDefault("EVYDENCE_OBJECT_DIR", filepath.Join("tmp", "objects"))
		objectStore, err := filesystem.New(objectRoot)
		if err != nil {
			return nil, "", err
		}
		return objectStore, "filesystem root " + objectRoot, nil
	case "s3", "minio":
		objectStore, err := s3store.New(ctx, s3store.Config{
			Endpoint:        os.Getenv("EVYDENCE_S3_ENDPOINT"),
			AccessKeyID:     os.Getenv("EVYDENCE_S3_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("EVYDENCE_S3_SECRET_ACCESS_KEY"),
			Bucket:          os.Getenv("EVYDENCE_S3_BUCKET"),
			Region:          os.Getenv("EVYDENCE_S3_REGION"),
			UseSSL:          strings.EqualFold(os.Getenv("EVYDENCE_S3_USE_SSL"), "true"),
		})
		if err != nil {
			return nil, "", err
		}
		return objectStore, "S3-compatible bucket " + envDefault("EVYDENCE_S3_BUCKET", ""), nil
	default:
		return nil, "", errors.New("unsupported EVYDENCE_OBJECT_STORE")
	}
}

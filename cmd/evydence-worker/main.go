package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/getkin/kin-openapi/openapi3"
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
	var replayed app.Object
	var hasReplayedObject bool
	if requireObjectReplay {
		object, ok, err := verifyJobObject(ctx, objects, job)
		if err != nil {
			return err
		}
		replayed, hasReplayedObject = object, ok
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
		if hasReplayedObject {
			if err := verifyReplayedSBOM(replayed.Bytes, sbom); err != nil {
				return err
			}
		}
		return requirePayloadHash(job, "")
	case "parse_vulnerability_scan":
		scan, ok := snapshot.Scans[job.SubjectID]
		if !ok || scan.TenantID != job.TenantID {
			return errors.New("parsed vulnerability scan is not available in durable state")
		}
		if hasReplayedObject {
			if err := verifyReplayedVulnerabilityScan(replayed.Bytes, scan); err != nil {
				return err
			}
		}
		return requirePayloadHash(job, "")
	case "parse_openapi_contract":
		contract, ok := snapshot.Contracts[job.SubjectID]
		if !ok || contract.TenantID != job.TenantID {
			return errors.New("parsed openapi contract is not available in durable state")
		}
		if hasReplayedObject {
			if err := verifyReplayedOpenAPIContract(ctx, replayed.Bytes, contract); err != nil {
				return err
			}
		}
		return requirePayloadHash(job, contract.Hash)
	case "parse_vex":
		vex, ok := snapshot.VEXDocuments[job.SubjectID]
		if !ok || vex.TenantID != job.TenantID {
			return errors.New("parsed vex document is not available in durable state")
		}
		if hasReplayedObject {
			if err := verifyReplayedVEX(replayed.Bytes, vex); err != nil {
				return err
			}
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
		if hasReplayedObject {
			if err := verifyReplayedAttestation(replayed.Bytes, attestation); err != nil {
				return err
			}
		}
		return requirePayloadHash(job, attestation.PayloadHash)
	default:
		return errors.New("unsupported outbox job kind")
	}
}

func verifyJobObject(ctx context.Context, objects jobObjectGetter, job postgres.ClaimedJob) (app.Object, bool, error) {
	key := payloadObjectKey(job)
	if key == "" {
		return app.Object{}, false, nil
	}
	if !strings.HasPrefix(key, "tenants/"+job.TenantID+"/") {
		return app.Object{}, false, errors.New("outbox payload object key is not tenant-prefixed")
	}
	if objects == nil {
		return app.Object{}, false, errors.New("outbox object store is not configured")
	}
	object, err := objects.Get(ctx, key)
	if err != nil {
		return app.Object{}, false, errors.New("read outbox payload object")
	}
	if object.TenantID != "" && object.TenantID != job.TenantID {
		return app.Object{}, false, errors.New("outbox payload object tenant mismatch")
	}
	if len(object.Bytes) > intEnv("EVYDENCE_WORKER_MAX_PAYLOAD_BYTES", defaultMaxWorkerPayloadBytes) {
		return app.Object{}, false, errors.New("outbox payload object exceeds worker size limit")
	}
	want := payloadString(job, "payload_hash")
	if want == "" {
		return object, true, nil
	}
	if object.Digest != "" && object.Digest != want {
		return app.Object{}, false, errors.New("outbox payload object metadata digest mismatch")
	}
	if digestBytes(object.Bytes) != want {
		return app.Object{}, false, errors.New("outbox payload object digest mismatch")
	}
	return object, true, nil
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

func payloadObjectKey(job postgres.ClaimedJob) string {
	ref := payloadString(job, "payload_ref")
	return strings.TrimPrefix(ref, "object://")
}

type replayedSBOM struct {
	SpecVersion    string
	ComponentCount int
}

func verifyReplayedSBOM(raw []byte, sbom domain.SBOM) error {
	parsed, err := parseReplayedSBOM(raw)
	if err != nil {
		return err
	}
	if sbom.SpecVersion != "" && parsed.SpecVersion != sbom.SpecVersion {
		return errors.New("replayed sbom payload does not match durable state")
	}
	if sbom.ComponentCount != 0 && parsed.ComponentCount != sbom.ComponentCount {
		return errors.New("replayed sbom payload does not match durable state")
	}
	if len(sbom.Components) != 0 && parsed.ComponentCount != len(sbom.Components) {
		return errors.New("replayed sbom payload does not match durable state")
	}
	return nil
}

func parseReplayedSBOM(raw []byte) (replayedSBOM, error) {
	var doc struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if err := strictDecodeWorker(raw, &doc); err != nil || strings.ToLower(strings.TrimSpace(doc.BOMFormat)) != "cyclonedx" {
		return replayedSBOM{}, errors.New("replayed sbom payload is invalid")
	}
	for _, component := range doc.Components {
		if strings.TrimSpace(component.Name) == "" {
			return replayedSBOM{}, errors.New("replayed sbom payload is invalid")
		}
	}
	return replayedSBOM{SpecVersion: strings.TrimSpace(doc.SpecVersion), ComponentCount: len(doc.Components)}, nil
}

type replayedVulnerabilityScan struct {
	Scanner      string
	TargetRef    string
	FindingCount int
	Summary      map[string]int
}

func verifyReplayedVulnerabilityScan(raw []byte, scan domain.VulnerabilityScan) error {
	parsed, err := parseReplayedVulnerabilityScan(raw)
	if err != nil {
		return err
	}
	if scan.Scanner != "" && parsed.Scanner != scan.Scanner {
		return errors.New("replayed vulnerability scan payload does not match durable state")
	}
	if scan.TargetRef != "" && parsed.TargetRef != scan.TargetRef {
		return errors.New("replayed vulnerability scan payload does not match durable state")
	}
	if len(scan.Findings) != 0 && parsed.FindingCount != len(scan.Findings) {
		return errors.New("replayed vulnerability scan payload does not match durable state")
	}
	for severity, count := range scan.Summary {
		if parsed.Summary[severity] != count {
			return errors.New("replayed vulnerability scan payload does not match durable state")
		}
	}
	return nil
}

func parseReplayedVulnerabilityScan(raw []byte) (replayedVulnerabilityScan, error) {
	var doc struct {
		Scanner   string `json:"scanner"`
		TargetRef string `json:"target_ref"`
		Findings  []struct {
			Vulnerability string `json:"vulnerability"`
			Component     string `json:"component"`
			Severity      string `json:"severity"`
			State         string `json:"state"`
		} `json:"findings"`
		ReleaseID string `json:"release_id"`
	}
	if err := strictDecodeWorker(raw, &doc); err != nil || strings.TrimSpace(doc.Scanner) == "" || strings.TrimSpace(doc.TargetRef) == "" || strings.TrimSpace(doc.ReleaseID) == "" {
		return replayedVulnerabilityScan{}, errors.New("replayed vulnerability scan payload is invalid")
	}
	summary := map[string]int{}
	for _, finding := range doc.Findings {
		if strings.TrimSpace(finding.Vulnerability) == "" || strings.TrimSpace(finding.Severity) == "" {
			return replayedVulnerabilityScan{}, errors.New("replayed vulnerability scan payload is invalid")
		}
		summary[strings.ToLower(strings.TrimSpace(finding.Severity))]++
	}
	return replayedVulnerabilityScan{Scanner: strings.TrimSpace(doc.Scanner), TargetRef: strings.TrimSpace(doc.TargetRef), FindingCount: len(doc.Findings), Summary: summary}, nil
}

func verifyReplayedOpenAPIContract(ctx context.Context, raw []byte, contract domain.OpenAPIContract) error {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(raw)
	if err != nil {
		return errors.New("replayed openapi contract payload is invalid")
	}
	if err := doc.Validate(ctx); err != nil {
		return errors.New("replayed openapi contract payload is invalid")
	}
	pathCount := 0
	if doc.Paths != nil {
		pathCount = len(doc.Paths.Map())
	}
	if contract.PathCount != 0 && pathCount != contract.PathCount {
		return errors.New("replayed openapi contract payload does not match durable state")
	}
	if contract.Hash != "" && digestBytes(raw) != contract.Hash {
		return errors.New("replayed openapi contract payload does not match durable state")
	}
	return nil
}

type replayedVEX struct {
	Author         string
	StatementCount int
	StatusSummary  map[string]int
}

func verifyReplayedVEX(raw []byte, vex domain.VEXDocument) error {
	parsed, err := parseReplayedVEX(raw)
	if err != nil {
		return err
	}
	if vex.Author != "" && parsed.Author != vex.Author {
		return errors.New("replayed vex payload does not match durable state")
	}
	if vex.StatementCount != 0 && parsed.StatementCount != vex.StatementCount {
		return errors.New("replayed vex payload does not match durable state")
	}
	for status, count := range vex.StatusSummary {
		if parsed.StatusSummary[status] != count {
			return errors.New("replayed vex payload does not match durable state")
		}
	}
	return nil
}

func parseReplayedVEX(raw []byte) (replayedVEX, error) {
	var doc struct {
		Context    any    `json:"@context"`
		ID         string `json:"@id"`
		Author     string `json:"author"`
		Timestamp  string `json:"timestamp"`
		Version    any    `json:"version"`
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Products        []map[string]any `json:"products"`
			Status          string           `json:"status"`
			Justification   string           `json:"justification"`
			ImpactStatement string           `json:"impact_statement"`
			ActionStatement string           `json:"action_statement"`
		} `json:"statements"`
	}
	if err := strictDecodeWorker(raw, &doc); err != nil || strings.TrimSpace(doc.Author) == "" || strings.TrimSpace(doc.Timestamp) == "" || len(doc.Statements) == 0 {
		return replayedVEX{}, errors.New("replayed vex payload is invalid")
	}
	summary := map[string]int{}
	for _, statement := range doc.Statements {
		status := strings.TrimSpace(statement.Status)
		if strings.TrimSpace(statement.Vulnerability.Name) == "" || status == "" || len(statement.Products) == 0 {
			return replayedVEX{}, errors.New("replayed vex payload is invalid")
		}
		switch status {
		case "affected", "not_affected", "fixed", "under_investigation":
		default:
			return replayedVEX{}, errors.New("replayed vex payload is invalid")
		}
		summary[status]++
	}
	return replayedVEX{Author: strings.TrimSpace(doc.Author), StatementCount: len(doc.Statements), StatusSummary: summary}, nil
}

func verifyReplayedAttestation(raw []byte, attestation domain.BuildAttestation) error {
	parsed, err := parseReplayedAttestation(raw)
	if err != nil {
		return err
	}
	if attestation.PayloadHash != "" && digestBytes(raw) != attestation.PayloadHash {
		return errors.New("replayed build attestation payload does not match durable state")
	}
	if len(attestation.SubjectDigests) != 0 && !equalStringSets(parsed.SubjectDigests, attestation.SubjectDigests) {
		return errors.New("replayed build attestation payload does not match durable state")
	}
	if attestation.PredicateType != "" && parsed.PredicateType != attestation.PredicateType {
		return errors.New("replayed build attestation payload does not match durable state")
	}
	return nil
}

type replayedAttestation struct {
	PredicateType  string
	SubjectDigests []string
}

func parseReplayedAttestation(raw []byte) (replayedAttestation, error) {
	var envelope struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid,omitempty"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := strictDecodeWorker(raw, &envelope); err != nil || strings.TrimSpace(envelope.PayloadType) == "" || strings.TrimSpace(envelope.Payload) == "" || len(envelope.Signatures) == 0 {
		return replayedAttestation{}, errors.New("replayed build attestation payload is invalid")
	}
	for _, signature := range envelope.Signatures {
		if strings.TrimSpace(signature.Sig) == "" {
			return replayedAttestation{}, errors.New("replayed build attestation payload is invalid")
		}
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return replayedAttestation{}, errors.New("replayed build attestation payload is invalid")
	}
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate map[string]any `json:"predicate"`
	}
	if err := strictDecodeWorker(payload, &statement); err != nil || strings.TrimSpace(statement.Type) == "" || strings.TrimSpace(statement.PredicateType) == "" || len(statement.Subject) == 0 {
		return replayedAttestation{}, errors.New("replayed build attestation payload is invalid")
	}
	digests := make([]string, 0, len(statement.Subject))
	for _, subject := range statement.Subject {
		digest := "sha256:" + strings.ToLower(strings.TrimSpace(subject.Digest["sha256"]))
		if !validWorkerDigest(digest) {
			return replayedAttestation{}, errors.New("replayed build attestation payload is invalid")
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return replayedAttestation{PredicateType: strings.TrimSpace(statement.PredicateType), SubjectDigests: digests}, nil
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func strictDecodeWorker(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}

func validWorkerDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
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

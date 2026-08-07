package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/aatuh/evydence/internal/adapters/objectstore/filesystem"
	s3store "github.com/aatuh/evydence/internal/adapters/objectstore/s3"
	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

const defaultMaxWorkerPayloadBytes = 20 << 20

var expectedParserVersions = map[string]string{
	"parse_sbom":               app.ParserVersionCycloneDXJSON,
	"parse_vulnerability_scan": app.ParserVersionGenericVulnerabilityJSON,
	"parse_openapi_contract":   app.ParserVersionOpenAPIJSON,
	"parse_vex":                app.ParserVersionOpenVEXJSON,
	"verify_attestation":       app.ParserVersionDSSEInTotoJSON,
}

func main() {
	if err := runWithArgs(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	return runWithArgs(nil)
}

func runWithArgs(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "healthcheck", "--healthcheck":
			return nil
		case "reconcile":
			return runObjectReconciliation(args[1:])
		default:
			return fmt.Errorf("unsupported worker command %q", args[0])
		}
	}
	production := strings.EqualFold(os.Getenv("ENV"), "production")
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("worker requires EVYDENCE_DATABASE_URL")
	}
	ctx := context.Background()
	loadMode, err := postgres.ResolveLoadMode(os.Getenv("EVYDENCE_POSTGRES_LOAD_MODE"), production)
	if err != nil {
		return err
	}
	if production {
		if err := postgres.ValidateProductionLoadMode(loadMode); err != nil {
			return err
		}
	}
	store, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{LoadMode: loadMode, DisableSnapshotWrites: production})
	if err != nil {
		return err
	}
	defer store.Close()
	migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
	migrateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
		if _, err := store.ApplyMigrations(migrateCtx, migrationsDir); err != nil {
			cancel()
			return err
		}
	} else if err := store.RequireNoPendingMigrations(migrateCtx, migrationsDir); err != nil {
		cancel()
		return fmt.Errorf("check migrations: %w", err)
	}
	cancel()
	objectStore, _, err := openObjectStore(ctx)
	if err != nil {
		return err
	}
	pollInterval := durationEnv("EVYDENCE_WORKER_POLL_INTERVAL", time.Second)
	batchSize := intEnv("EVYDENCE_WORKER_BATCH_SIZE", 10)
	log.Printf("evydence worker started with postgres outbox, configured object store, polling interval %s", pollInterval)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		jobs, err := store.ClaimJobs(ctx, batchSize)
		if err != nil {
			log.Printf("outbox claim failed")
			time.Sleep(pollInterval)
			continue
		}
		if len(jobs) == 0 {
			time.Sleep(pollInterval)
			continue
		}
		prioritizePayloadFinalization(jobs)
		for _, job := range jobs {
			log.Printf("processing outbox job id=%s kind=%s subject_type=%s subject_id=%s attempt=%d", job.ID, job.Kind, job.SubjectType, job.SubjectID, job.Attempts)
			if err := processJobWithObjects(ctx, store, objectStore, job); err != nil {
				failure := classifyWorkerFailure(err)
				log.Printf("outbox job failed id=%s kind=%s class=%s code=%s", job.ID, job.Kind, failure.Class, failure.Code)
				if failErr := store.FailJob(ctx, job.ID, job.LeaseToken, failure); failErr != nil {
					log.Printf("record outbox failure failed id=%s", job.ID)
				}
				continue
			}
			if err := store.CompleteJob(ctx, job.ID, job.LeaseToken); err != nil {
				log.Printf("complete outbox job failed id=%s", job.ID)
			}
		}
	}
}

// runObjectReconciliation performs a bounded, tenant-scoped reconciliation
// command. It is dry-run by default. --apply only changes lifecycle metadata
// after an explicit abandoned-staging threshold; it never deletes a provider
// object. The printed receipt contains safe counters and opaque numeric
// cursors, not object keys, digests, payload bytes, or provider errors.
func runObjectReconciliation(args []string) error {
	request, err := parseObjectReconciliationArgs(args)
	if err != nil {
		return err
	}
	production := strings.EqualFold(os.Getenv("ENV"), "production")
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("reconcile requires EVYDENCE_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), durationEnv("EVYDENCE_RECONCILIATION_TIMEOUT", 10*time.Minute))
	defer cancel()
	loadMode, err := postgres.ResolveLoadMode(os.Getenv("EVYDENCE_POSTGRES_LOAD_MODE"), production)
	if err != nil {
		return err
	}
	if production {
		if err := postgres.ValidateProductionLoadMode(loadMode); err != nil {
			return err
		}
	}
	store, err := postgres.OpenWithOptions(ctx, databaseURL, postgres.StoreOptions{LoadMode: loadMode, DisableSnapshotWrites: production})
	if err != nil {
		return errors.New("reconcile could not open durable storage")
	}
	defer store.Close()
	migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
	if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
		if _, err := store.ApplyMigrations(ctx, migrationsDir); err != nil {
			return errors.New("reconcile could not apply migrations")
		}
	} else if err := store.RequireNoPendingMigrations(ctx, migrationsDir); err != nil {
		return errors.New("reconcile requires current migrations")
	}
	objects, _, err := openObjectStore(ctx)
	if err != nil {
		return errors.New("reconcile could not open object storage")
	}
	receipt, err := app.ReconcileObjectPayloads(ctx, store, store, objects, request)
	if err != nil {
		return errors.New("payload reconciliation failed")
	}
	if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
		return errors.New("write reconciliation receipt")
	}
	return nil
}

func parseObjectReconciliationArgs(args []string) (app.ObjectReconciliationRequest, error) {
	flags := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tenantID := flags.String("tenant", "", "tenant ID")
	metadataCursor := flags.Int("metadata-cursor", 0, "metadata cursor")
	providerCursor := flags.Int("provider-cursor", 0, "provider cursor")
	limit := flags.Int("limit", 0, "metadata page limit")
	providerLimit := flags.Int("provider-limit", 0, "provider inventory page limit")
	apply := flags.Bool("apply", false, "apply lifecycle quarantine and recovery")
	orphanStagedAfter := flags.Duration("orphan-staged-after", 0, "minimum staging age before quarantine")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return app.ObjectReconciliationRequest{}, errors.New("invalid reconcile command")
	}
	if strings.TrimSpace(*tenantID) == "" {
		return app.ObjectReconciliationRequest{}, errors.New("reconcile requires --tenant")
	}
	if *apply && *orphanStagedAfter < time.Hour {
		return app.ObjectReconciliationRequest{}, errors.New("reconcile --apply requires --orphan-staged-after of at least 1h")
	}
	return app.ObjectReconciliationRequest{
		TenantID:               strings.TrimSpace(*tenantID),
		MetadataCursor:         *metadataCursor,
		ProviderCursor:         *providerCursor,
		Limit:                  *limit,
		ProviderInventoryLimit: *providerLimit,
		Apply:                  *apply,
		OrphanStagedAfter:      *orphanStagedAfter,
	}, nil
}

func prioritizePayloadFinalization(jobs []postgres.ClaimedJob) {
	sort.SliceStable(jobs, func(i, j int) bool {
		return jobs[i].Kind == "finalize_payload" && jobs[j].Kind != "finalize_payload"
	})
}

func classifyWorkerFailure(err error) postgres.JobFailure {
	if err == nil {
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "worker_processing_failed"}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "worker_interrupted"}
	}
	if errors.Is(err, app.ErrNotFound) {
		return postgres.JobFailure{Class: postgres.JobFailurePermanent, Code: "payload_orphaned"}
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "unsupported outbox job kind"), strings.Contains(message, "unsupported outbox parser version"), strings.Contains(message, "unsupported payload lifecycle version"), strings.Contains(message, "tenant-prefixed"), strings.Contains(message, "tenant mismatch"), strings.Contains(message, "digest mismatch"), strings.Contains(message, "payload hash"), strings.Contains(message, "durable state"), strings.Contains(message, "payload lifecycle state is not available"), strings.Contains(message, "payload is invalid"):
		return postgres.JobFailure{Class: postgres.JobFailurePoisoned, Code: "payload_invariant_failed"}
	case strings.Contains(message, "payload finalization pending"):
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "payload_finalization_pending"}
	case strings.Contains(message, "object store is not configured"), strings.Contains(message, "read outbox payload object"):
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "payload_store_unavailable"}
	case strings.Contains(message, "size limit"):
		return postgres.JobFailure{Class: postgres.JobFailurePermanent, Code: "payload_too_large"}
	default:
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "worker_processing_failed"}
	}
}

type jobStateLoader interface {
	LoadState(context.Context) (app.PersistedState, bool, error)
}

type jobStateStore interface {
	jobStateLoader
	SaveState(context.Context, app.PersistedState) error
}

type jobReleaseLedgerMutationStore interface {
	jobStateLoader
	ApplyReleaseLedgerMutation(context.Context, app.ReleaseLedgerMutation) error
}

type jobObjectGetter interface {
	Get(context.Context, string) (app.Object, error)
}

type payloadFinalizer interface {
	app.PayloadObjectStore
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
	if job.Kind == "finalize_payload" {
		lifecycle, ok := state.(app.ObjectPayloadLifecycleStore)
		if !ok {
			return errors.New("payload lifecycle state is not available")
		}
		finalizer, ok := objects.(payloadFinalizer)
		if !ok {
			return errors.New("payload object store is not configured")
		}
		if err := app.FinalizeStagedObjectPayload(ctx, lifecycle, finalizer, job.TenantID, payloadString(job, "payload_digest")); err != nil {
			return err
		}
		return nil
	}
	var replayed app.Object
	var hasReplayedObject bool
	if requireObjectReplay {
		object, ok, err := verifyJobObject(ctx, state, objects, job)
		if err != nil {
			recordVEXImportReportFailure(ctx, state, job, err)
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
	if err := requireParserVersion(job); err != nil {
		if job.Kind == "parse_vex" {
			if vex, ok := snapshot.VEXDocuments[job.SubjectID]; ok && vex.TenantID == job.TenantID {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
		}
		return err
	}
	stateChanged := false
	switch job.Kind {
	case "parse_sbom":
		sbom, ok := snapshot.SBOMs[job.SubjectID]
		if !ok || sbom.TenantID != job.TenantID {
			return errors.New("parsed sbom is not available in durable state")
		}
		if hasReplayedObject {
			parsed, err := parseReplayedSBOM(replayed.Bytes)
			if err != nil {
				return err
			}
			if err := verifyReplayedSBOM(parsed, sbom); err != nil {
				return err
			}
			if updated, changed := mergeReplayedSBOM(sbom, parsed); changed {
				snapshot.SBOMs[job.SubjectID] = updated
				stateChanged = true
			}
		}
		if err := requirePayloadHash(job, ""); err != nil {
			return err
		}
	case "parse_vulnerability_scan":
		scan, ok := snapshot.Scans[job.SubjectID]
		if !ok || scan.TenantID != job.TenantID {
			return errors.New("parsed vulnerability scan is not available in durable state")
		}
		if hasReplayedObject {
			parsed, err := parseReplayedVulnerabilityScan(replayed.Bytes, job.SubjectID)
			if err != nil {
				return err
			}
			if err := verifyReplayedVulnerabilityScan(parsed, scan); err != nil {
				return err
			}
			if updated, changed := mergeReplayedVulnerabilityScan(scan, parsed); changed {
				snapshot.Scans[job.SubjectID] = updated
				stateChanged = true
			}
		}
		if err := requirePayloadHash(job, ""); err != nil {
			return err
		}
	case "parse_openapi_contract":
		contract, ok := snapshot.Contracts[job.SubjectID]
		if !ok || contract.TenantID != job.TenantID {
			return errors.New("parsed openapi contract is not available in durable state")
		}
		if hasReplayedObject {
			parsed, err := parseReplayedOpenAPIContract(ctx, replayed.Bytes)
			if err != nil {
				return err
			}
			if err := verifyReplayedOpenAPIContract(replayed.Bytes, parsed, contract); err != nil {
				return err
			}
			if updated, changed := mergeReplayedOpenAPIContract(contract, parsed); changed {
				snapshot.Contracts[job.SubjectID] = updated
				stateChanged = true
			}
		}
		if err := requirePayloadHash(job, contract.Hash); err != nil {
			return err
		}
	case "parse_vex":
		vex, ok := snapshot.VEXDocuments[job.SubjectID]
		if !ok || vex.TenantID != job.TenantID {
			return errors.New("parsed vex document is not available in durable state")
		}
		if hasReplayedObject {
			parsed, err := parseReplayedVEX(replayed.Bytes)
			if err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			if err := verifyReplayedVEX(parsed, vex); err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			if updated, changed := mergeReplayedVEX(vex, parsed); changed {
				snapshot.VEXDocuments[job.SubjectID] = updated
				stateChanged = true
			}
			if payloadBool(job, "worker_create_decisions") {
				created, superseded, mappingFailures, err := applyReplayedVEXDecisions(&snapshot, job, vex, parsed, replayed.Digest)
				if err != nil {
					return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
				}
				if created > 0 {
					stateChanged = true
				}
				if updateVEXImportReport(&snapshot, job, vex, parsed, created, superseded, mappingFailures) {
					stateChanged = true
				}
			}
		}
		if err := requirePayloadHash(job, ""); err != nil {
			return err
		}
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
			parsed, err := parseReplayedAttestation(replayed.Bytes)
			if err != nil {
				return err
			}
			if err := verifyReplayedAttestation(replayed.Bytes, parsed, attestation); err != nil {
				return err
			}
			if updated, changed := mergeReplayedAttestation(attestation, parsed, replayed.Bytes); changed {
				snapshot.BuildAttestations[job.SubjectID] = updated
				stateChanged = true
			}
		}
		if err := requirePayloadHash(job, attestation.PayloadHash); err != nil {
			return err
		}
	default:
		return errors.New("unsupported outbox job kind")
	}
	if stateChanged {
		return persistParserSideEffects(ctx, state, snapshot, job.Kind)
	}
	return nil
}

func persistParserSideEffects(ctx context.Context, state jobStateLoader, snapshot app.PersistedState, kind string) error {
	if focused, ok := state.(jobReleaseLedgerMutationStore); ok && releaseLedgerParserJob(kind) {
		if err := focused.ApplyReleaseLedgerMutation(ctx, app.ReleaseLedgerMutationFromState(snapshot)); err != nil {
			return errors.New("persist durable parser side effects")
		}
		return nil
	}
	stateStore, ok := state.(jobStateStore)
	if !ok {
		return errors.New("durable parser side effects require writable state")
	}
	if err := stateStore.SaveState(ctx, snapshot); err != nil {
		return errors.New("persist durable parser side effects")
	}
	return nil
}

func releaseLedgerParserJob(kind string) bool {
	switch kind {
	case "parse_sbom", "parse_vulnerability_scan", "parse_openapi_contract", "parse_vex":
		return true
	default:
		return false
	}
}

func requireParserVersion(job postgres.ClaimedJob) error {
	expected, ok := expectedParserVersions[job.Kind]
	if !ok {
		return nil
	}
	got := payloadString(job, "parser_version")
	if got == "" {
		return nil
	}
	if job.Kind == "parse_vex" && (got == app.ParserVersionOpenVEXJSON || got == app.ParserVersionCycloneDXVEXJSON) {
		return nil
	}
	if got != expected {
		return errors.New("unsupported outbox parser version")
	}
	return nil
}

func verifyJobObject(ctx context.Context, state jobStateLoader, objects jobObjectGetter, job postgres.ClaimedJob) (app.Object, bool, error) {
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
	if lifecycleVersion := payloadString(job, "payload_lifecycle"); lifecycleVersion != "" {
		if lifecycleVersion != app.PayloadLifecycleVersion {
			return app.Object{}, false, errors.New("unsupported payload lifecycle version")
		}
		lifecycle, ok := state.(app.ObjectPayloadLifecycleStore)
		if !ok {
			return app.Object{}, false, errors.New("payload lifecycle state is not available")
		}
		if err := app.RequireFinalizedObjectPayload(ctx, lifecycle, job.TenantID, payloadString(job, "payload_digest"), key); err != nil {
			if errors.Is(err, app.ErrConflict) {
				return app.Object{}, false, errors.New("payload finalization pending")
			}
			return app.Object{}, false, err
		}
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

func payloadBool(job postgres.ClaimedJob, key string) bool {
	if job.Payload == nil {
		return false
	}
	value, _ := job.Payload[key].(bool)
	return value
}

func payloadObjectKey(job postgres.ClaimedJob) string {
	ref := payloadString(job, "payload_ref")
	return strings.TrimPrefix(ref, "object://")
}

type replayedSBOM struct {
	SpecVersion    string
	ComponentCount int
	Components     []domain.SBOMComponent
}

func verifyReplayedSBOM(parsed replayedSBOM, sbom domain.SBOM) error {
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

func mergeReplayedSBOM(sbom domain.SBOM, parsed replayedSBOM) (domain.SBOM, bool) {
	changed := false
	if sbom.SpecVersion == "" && parsed.SpecVersion != "" {
		sbom.SpecVersion = parsed.SpecVersion
		changed = true
	}
	if sbom.ComponentCount == 0 && parsed.ComponentCount != 0 {
		sbom.ComponentCount = parsed.ComponentCount
		changed = true
	}
	if len(sbom.Components) == 0 && len(parsed.Components) != 0 {
		sbom.Components = append([]domain.SBOMComponent(nil), parsed.Components...)
		changed = true
	}
	return sbom, changed
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
	components := make([]domain.SBOMComponent, 0, len(doc.Components))
	for _, component := range doc.Components {
		if strings.TrimSpace(component.Name) == "" {
			return replayedSBOM{}, errors.New("replayed sbom payload is invalid")
		}
		components = append(components, domain.SBOMComponent{Name: strings.TrimSpace(component.Name), Version: strings.TrimSpace(component.Version), PURL: strings.TrimSpace(component.PURL)})
	}
	return replayedSBOM{SpecVersion: strings.TrimSpace(doc.SpecVersion), ComponentCount: len(doc.Components), Components: components}, nil
}

type replayedVulnerabilityScan struct {
	Scanner      string
	TargetRef    string
	FindingCount int
	Summary      map[string]int
	Findings     []domain.VulnerabilityFinding
}

func verifyReplayedVulnerabilityScan(parsed replayedVulnerabilityScan, scan domain.VulnerabilityScan) error {
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

func mergeReplayedVulnerabilityScan(scan domain.VulnerabilityScan, parsed replayedVulnerabilityScan) (domain.VulnerabilityScan, bool) {
	changed := false
	if scan.Scanner == "" && parsed.Scanner != "" {
		scan.Scanner = parsed.Scanner
		changed = true
	}
	if scan.TargetRef == "" && parsed.TargetRef != "" {
		scan.TargetRef = parsed.TargetRef
		changed = true
	}
	if scan.Summary == nil && parsed.Summary != nil {
		scan.Summary = cloneIntMap(parsed.Summary)
		changed = true
	}
	if len(scan.Findings) == 0 && len(parsed.Findings) != 0 {
		scan.Findings = append([]domain.VulnerabilityFinding(nil), parsed.Findings...)
		changed = true
	}
	return scan, changed
}

func parseReplayedVulnerabilityScan(raw []byte, subjectID string) (replayedVulnerabilityScan, error) {
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
	findings := make([]domain.VulnerabilityFinding, 0, len(doc.Findings))
	for i, finding := range doc.Findings {
		if strings.TrimSpace(finding.Vulnerability) == "" || strings.TrimSpace(finding.Severity) == "" {
			return replayedVulnerabilityScan{}, errors.New("replayed vulnerability scan payload is invalid")
		}
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		summary[severity]++
		findings = append(findings, domain.VulnerabilityFinding{
			ID:            fmt.Sprintf("%s:finding:%d", strings.TrimSpace(subjectID), i+1),
			Vulnerability: strings.TrimSpace(finding.Vulnerability),
			Component:     strings.TrimSpace(finding.Component),
			Severity:      severity,
			State:         nonEmptyWorker(finding.State, "open"),
		})
	}
	return replayedVulnerabilityScan{Scanner: strings.TrimSpace(doc.Scanner), TargetRef: strings.TrimSpace(doc.TargetRef), FindingCount: len(doc.Findings), Summary: summary, Findings: findings}, nil
}

type replayedOpenAPIContract struct {
	PathCount  int
	Operations []domain.OpenAPIOperation
}

func parseReplayedOpenAPIContract(ctx context.Context, raw []byte) (replayedOpenAPIContract, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(raw)
	if err != nil {
		return replayedOpenAPIContract{}, errors.New("replayed openapi contract payload is invalid")
	}
	if err := doc.Validate(ctx); err != nil {
		return replayedOpenAPIContract{}, errors.New("replayed openapi contract payload is invalid")
	}
	pathCount := 0
	operations := []domain.OpenAPIOperation{}
	if doc.Paths != nil {
		paths := doc.Paths.Map()
		pathCount = len(paths)
		pathNames := make([]string, 0, len(paths))
		for path := range paths {
			pathNames = append(pathNames, path)
		}
		sort.Strings(pathNames)
		for _, path := range pathNames {
			item := paths[path]
			if item == nil {
				continue
			}
			for _, method := range []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"} {
				operation := operationForMethod(item, method)
				if operation == nil {
					continue
				}
				statuses := []string{}
				if operation.Responses != nil {
					for status := range operation.Responses.Map() {
						statuses = append(statuses, status)
					}
					sort.Strings(statuses)
				}
				operations = append(operations, domain.OpenAPIOperation{Path: path, Method: method, OperationID: operation.OperationID, Deprecated: operation.Deprecated, ResponseStatuses: statuses})
			}
		}
	}
	return replayedOpenAPIContract{PathCount: pathCount, Operations: operations}, nil
}

func verifyReplayedOpenAPIContract(raw []byte, parsed replayedOpenAPIContract, contract domain.OpenAPIContract) error {
	if contract.PathCount != 0 && parsed.PathCount != contract.PathCount {
		return errors.New("replayed openapi contract payload does not match durable state")
	}
	if contract.Hash != "" && digestBytes(raw) != contract.Hash {
		return errors.New("replayed openapi contract payload does not match durable state")
	}
	return nil
}

func mergeReplayedOpenAPIContract(contract domain.OpenAPIContract, parsed replayedOpenAPIContract) (domain.OpenAPIContract, bool) {
	changed := false
	if contract.PathCount == 0 && parsed.PathCount != 0 {
		contract.PathCount = parsed.PathCount
		changed = true
	}
	if len(contract.Operations) == 0 && len(parsed.Operations) != 0 {
		contract.Operations = append([]domain.OpenAPIOperation(nil), parsed.Operations...)
		changed = true
	}
	return contract, changed
}

type replayedVEX struct {
	Author         string
	StatementCount int
	StatusSummary  map[string]int
	Statements     []replayedVEXStatement
}

type replayedVEXStatement struct {
	Vulnerability   string
	Products        map[string]struct{}
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
}

func verifyReplayedVEX(parsed replayedVEX, vex domain.VEXDocument) error {
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

func mergeReplayedVEX(vex domain.VEXDocument, parsed replayedVEX) (domain.VEXDocument, bool) {
	changed := false
	if vex.Author == "" && parsed.Author != "" {
		vex.Author = parsed.Author
		changed = true
	}
	if vex.StatementCount == 0 && parsed.StatementCount != 0 {
		vex.StatementCount = parsed.StatementCount
		changed = true
	}
	if vex.StatusSummary == nil && parsed.StatusSummary != nil {
		vex.StatusSummary = cloneIntMap(parsed.StatusSummary)
		changed = true
	}
	return vex, changed
}

func parseReplayedVEX(raw []byte) (replayedVEX, error) {
	var probe struct {
		BOMFormat string `json:"bomFormat"`
	}
	_ = json.Unmarshal(raw, &probe)
	if strings.EqualFold(strings.TrimSpace(probe.BOMFormat), "cyclonedx") {
		return parseReplayedCycloneDXVEX(raw)
	}
	return parseReplayedOpenVEX(raw)
}

func parseReplayedOpenVEX(raw []byte) (replayedVEX, error) {
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
	statements := make([]replayedVEXStatement, 0, len(doc.Statements))
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
		statements = append(statements, replayedVEXStatement{
			Vulnerability:   strings.TrimSpace(statement.Vulnerability.Name),
			Products:        replayedVEXProductIDs(statement.Products),
			Status:          status,
			Justification:   strings.TrimSpace(statement.Justification),
			ImpactStatement: strings.TrimSpace(statement.ImpactStatement),
			ActionStatement: strings.TrimSpace(statement.ActionStatement),
		})
	}
	return replayedVEX{Author: strings.TrimSpace(doc.Author), StatementCount: len(doc.Statements), StatusSummary: summary, Statements: statements}, nil
}

func parseReplayedCycloneDXVEX(raw []byte) (replayedVEX, error) {
	var doc struct {
		BOMFormat       string `json:"bomFormat"`
		SpecVersion     string `json:"specVersion"`
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects,omitempty"`
			Analysis struct {
				State         string   `json:"state"`
				Justification string   `json:"justification"`
				Detail        string   `json:"detail"`
				Response      []string `json:"response"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := strictDecodeWorker(raw, &doc); err != nil || !strings.EqualFold(strings.TrimSpace(doc.BOMFormat), "cyclonedx") || len(doc.Vulnerabilities) == 0 {
		return replayedVEX{}, errors.New("replayed vex payload is invalid")
	}
	summary := map[string]int{}
	statements := make([]replayedVEXStatement, 0, len(doc.Vulnerabilities))
	for _, vuln := range doc.Vulnerabilities {
		status := workerCycloneDXAnalysisStatus(vuln.Analysis.State)
		if strings.TrimSpace(vuln.ID) == "" || status == "" {
			continue
		}
		products := map[string]struct{}{}
		for _, affect := range vuln.Affects {
			if ref := strings.TrimSpace(affect.Ref); ref != "" {
				products[ref] = struct{}{}
			}
		}
		summary[status]++
		statements = append(statements, replayedVEXStatement{
			Vulnerability:   strings.TrimSpace(vuln.ID),
			Products:        products,
			Status:          status,
			Justification:   nonEmptyWorker(strings.TrimSpace(vuln.Analysis.Justification), "cyclonedx_vex"),
			ImpactStatement: strings.TrimSpace(vuln.Analysis.Detail),
			ActionStatement: strings.Join(vuln.Analysis.Response, ","),
		})
	}
	if len(statements) == 0 {
		return replayedVEX{}, errors.New("replayed vex payload is invalid")
	}
	return replayedVEX{Author: "cyclonedx", StatementCount: len(doc.Vulnerabilities), StatusSummary: summary, Statements: statements}, nil
}

func workerCycloneDXAnalysisStatus(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "resolved", "fixed":
		return "fixed"
	case "not_affected":
		return "not_affected"
	case "exploitable", "affected":
		return "affected"
	case "in_triage", "under_investigation":
		return "under_investigation"
	default:
		return ""
	}
}

func replayedVEXProductIDs(products []map[string]any) map[string]struct{} {
	out := map[string]struct{}{}
	var walk func([]map[string]any)
	walk = func(items []map[string]any) {
		for _, item := range items {
			if id, ok := item["@id"].(string); ok {
				if id = strings.TrimSpace(id); id != "" {
					out[id] = struct{}{}
				}
			}
			if children, ok := item["subcomponents"].([]any); ok {
				mapped := make([]map[string]any, 0, len(children))
				for _, child := range children {
					if childMap, ok := child.(map[string]any); ok {
						mapped = append(mapped, childMap)
					}
				}
				walk(mapped)
			}
		}
	}
	walk(products)
	return out
}

func applyReplayedVEXDecisions(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, parsed replayedVEX, payloadHash string) (int, int, []domain.VEXImportIssue, error) {
	if state.Decisions == nil {
		state.Decisions = map[string]domain.VulnerabilityDecision{}
	}
	actorType := nonEmptyWorker(payloadString(job, "actor_type"), "worker")
	actorID := nonEmptyWorker(payloadString(job, "actor_id"), job.ID)
	evidenceID := payloadString(job, "evidence_id")
	now := time.Now().UTC()
	created := 0
	superseded := 0
	mappingFailures := []domain.VEXImportIssue{}
	scanIDs := make([]string, 0, len(state.Scans))
	for id, scan := range state.Scans {
		if scan.TenantID == job.TenantID && scan.ReleaseID == vex.ReleaseID {
			scanIDs = append(scanIDs, id)
		}
	}
	sort.Strings(scanIDs)
	for index, statement := range parsed.Statements {
		statementMatched := false
		for _, scanID := range scanIDs {
			scan := state.Scans[scanID]
			for _, finding := range scan.Findings {
				if finding.Vulnerability != statement.Vulnerability {
					continue
				}
				if len(statement.Products) > 0 && finding.Component != "" {
					if _, ok := statement.Products[finding.Component]; !ok {
						continue
					}
				}
				statementMatched = true
				if replayedVEXDecisionExists(state.Decisions, job.TenantID, vex.ID, finding.ID) {
					continue
				}
				decisionID := replayedVEXDecisionID(vex.ID, finding.ID, statement.Status)
				if _, exists := state.Decisions[decisionID]; exists {
					continue
				}
				supersedes := ""
				for id, existing := range state.Decisions {
					if existing.TenantID == job.TenantID && existing.FindingID == finding.ID && existing.SupersededBy == "" {
						supersedes = existing.ID
						existing.SupersededBy = decisionID
						state.Decisions[id] = existing
					}
				}
				state.Decisions[decisionID] = domain.VulnerabilityDecision{
					ID:              decisionID,
					TenantID:        job.TenantID,
					FindingID:       finding.ID,
					ScanID:          scan.ID,
					ReleaseID:       scan.ReleaseID,
					Vulnerability:   finding.Vulnerability,
					Component:       finding.Component,
					Status:          statement.Status,
					Justification:   statement.Justification,
					ImpactStatement: statement.ImpactStatement,
					ActionStatement: statement.ActionStatement,
					CustomerVisible: strings.TrimSpace(statement.ImpactStatement) != "",
					Source:          "vex",
					EvidenceID:      evidenceID,
					EvidenceIDs:     workerDecisionEvidenceIDs(evidenceID),
					VEXDocumentID:   vex.ID,
					Supersedes:      supersedes,
					ApprovedBy:      actorID,
					SchemaVersion:   domain.VulnerabilityDecisionVersion,
					CreatedAt:       now,
				}
				if supersedes != "" {
					superseded++
					if _, err := app.AppendPersistedChainEntry(state, now, job.TenantID, "vulnerability_decision.superseded", "vulnerability_decision", supersedes, actorType, actorID, payloadHash, ""); err != nil {
						return created, superseded, mappingFailures, errors.New("append replayed vex decision supersession audit entry")
					}
				}
				if _, err := app.AppendPersistedChainEntry(state, now, job.TenantID, "vulnerability_decision.created", "vulnerability_finding", finding.ID, actorType, actorID, payloadHash, ""); err != nil {
					return created, superseded, mappingFailures, errors.New("append replayed vex decision audit entry")
				}
				created++
			}
		}
		if !statementMatched {
			mappingFailures = append(mappingFailures, domain.VEXImportIssue{
				StatementIndex: index + 1,
				Code:           "finding_not_found",
				Detail:         "No matching vulnerability scan finding was found for this VEX statement.",
			})
		}
	}
	return created, superseded, mappingFailures, nil
}

func replayedVEXDecisionExists(decisions map[string]domain.VulnerabilityDecision, tenantID, vexID, findingID string) bool {
	for _, decision := range decisions {
		if decision.TenantID == tenantID && decision.VEXDocumentID == vexID && decision.FindingID == findingID {
			return true
		}
	}
	return false
}

func updateVEXImportReport(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, parsed replayedVEX, created, superseded int, mappingFailures []domain.VEXImportIssue) bool {
	reportID := payloadString(job, "import_report_id")
	if reportID == "" {
		for id, report := range state.VEXImportReports {
			if report.TenantID == job.TenantID && report.VEXDocumentID == vex.ID {
				reportID = id
				break
			}
		}
	}
	if reportID == "" {
		return false
	}
	if state.VEXImportReports == nil {
		state.VEXImportReports = map[string]domain.VEXImportReport{}
	}
	report, ok := state.VEXImportReports[reportID]
	if !ok || report.TenantID != job.TenantID || report.VEXDocumentID != vex.ID {
		return false
	}
	updated := report
	changed := false
	if updated.Status != "parsed" {
		updated.Status = "parsed"
		changed = true
	}
	if updated.FailureCode != "" || updated.FailureDetail != "" {
		updated.FailureCode = ""
		updated.FailureDetail = ""
		changed = true
	}
	if updated.StatementCount != parsed.StatementCount {
		updated.StatementCount = parsed.StatementCount
		changed = true
	}
	if created > updated.DecisionsCreated {
		updated.DecisionsCreated = created
		changed = true
	}
	if superseded > updated.DecisionsSuperseded {
		updated.DecisionsSuperseded = superseded
		changed = true
	}
	if !vexImportIssuesEqual(updated.MappingFailures, mappingFailures) {
		updated.MappingFailures = append([]domain.VEXImportIssue(nil), mappingFailures...)
		changed = true
	}
	if updated.SchemaVersion == "" {
		updated.SchemaVersion = domain.VEXImportReportSchemaVersion
		changed = true
	}
	if !changed {
		return false
	}
	updated.UpdatedAt = time.Now().UTC()
	state.VEXImportReports[reportID] = updated
	return true
}

func failVEXImportReportWithSnapshot(ctx context.Context, state jobStateLoader, snapshot *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, cause error) error {
	if updateVEXImportReportFailure(snapshot, job, vex, cause) {
		if err := persistParserSideEffects(ctx, state, *snapshot, job.Kind); err != nil {
			return err
		}
	}
	return cause
}

func recordVEXImportReportFailure(ctx context.Context, state jobStateLoader, job postgres.ClaimedJob, cause error) {
	if job.Kind != "parse_vex" || state == nil {
		return
	}
	snapshot, ok, err := state.LoadState(ctx)
	if err != nil || !ok {
		return
	}
	vex, ok := snapshot.VEXDocuments[job.SubjectID]
	if !ok || vex.TenantID != job.TenantID {
		return
	}
	if !updateVEXImportReportFailure(&snapshot, job, vex, cause) {
		return
	}
	_ = persistParserSideEffects(ctx, state, snapshot, job.Kind)
}

func updateVEXImportReportFailure(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, cause error) bool {
	reportID := payloadString(job, "import_report_id")
	if reportID == "" {
		for id, report := range state.VEXImportReports {
			if report.TenantID == job.TenantID && report.VEXDocumentID == vex.ID {
				reportID = id
				break
			}
		}
	}
	if reportID == "" {
		return false
	}
	if state.VEXImportReports == nil {
		state.VEXImportReports = map[string]domain.VEXImportReport{}
	}
	report, ok := state.VEXImportReports[reportID]
	if !ok || report.TenantID != job.TenantID || report.VEXDocumentID != vex.ID {
		return false
	}
	code := safeVEXParserFailureCode(cause)
	detail := safeVEXParserFailureDetail(code)
	updated := report
	changed := false
	if updated.Status != "failed" {
		updated.Status = "failed"
		changed = true
	}
	if updated.FailureCode != code {
		updated.FailureCode = code
		changed = true
	}
	if updated.FailureDetail != detail {
		updated.FailureDetail = detail
		changed = true
	}
	if updated.SchemaVersion == "" {
		updated.SchemaVersion = domain.VEXImportReportSchemaVersion
		changed = true
	}
	if !changed {
		return false
	}
	updated.UpdatedAt = time.Now().UTC()
	state.VEXImportReports[reportID] = updated
	return true
}

func safeVEXParserFailureCode(cause error) string {
	if cause == nil {
		return "parser_failed"
	}
	message := cause.Error()
	switch {
	case strings.Contains(message, "read outbox payload object"):
		return "payload_read_failed"
	case strings.Contains(message, "tenant-prefixed"):
		return "payload_ref_invalid"
	case strings.Contains(message, "tenant mismatch"):
		return "payload_tenant_mismatch"
	case strings.Contains(message, "digest mismatch"), strings.Contains(message, "payload hash"):
		return "payload_digest_mismatch"
	case strings.Contains(message, "size limit"):
		return "payload_too_large"
	case strings.Contains(message, "unsupported outbox parser version"):
		return "unsupported_parser_version"
	case strings.Contains(message, "durable state"), strings.Contains(message, "not available"):
		return "durable_state_mismatch"
	case strings.Contains(message, "replayed vex payload is invalid"):
		return "payload_invalid"
	default:
		return "parser_failed"
	}
}

func safeVEXParserFailureDetail(code string) string {
	switch code {
	case "payload_read_failed":
		return "The worker could not read the referenced VEX payload object."
	case "payload_ref_invalid":
		return "The VEX payload reference was not tenant-prefixed."
	case "payload_tenant_mismatch":
		return "The VEX payload object tenant did not match the job tenant."
	case "payload_digest_mismatch":
		return "The VEX payload digest did not match the expected digest."
	case "payload_too_large":
		return "The VEX payload exceeded the worker replay size limit."
	case "unsupported_parser_version":
		return "The VEX parser version is not supported by this worker."
	case "durable_state_mismatch":
		return "The replayed VEX payload did not match durable state for the job."
	case "payload_invalid":
		return "The VEX payload could not be parsed as a supported VEX document."
	default:
		return "The worker could not parse or verify the VEX payload."
	}
}

func vexImportIssuesEqual(a, b []domain.VEXImportIssue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func replayedVEXDecisionID(vexID, findingID, status string) string {
	sum := strings.TrimPrefix(digestBytes([]byte(vexID+"\n"+findingID+"\n"+status)), "sha256:")
	if len(sum) > 32 {
		sum = sum[:32]
	}
	return "vd_" + sum
}

func workerDecisionEvidenceIDs(evidenceID string) []string {
	evidenceID = strings.TrimSpace(evidenceID)
	if evidenceID == "" {
		return nil
	}
	return []string{evidenceID}
}

func verifyReplayedAttestation(raw []byte, parsed replayedAttestation, attestation domain.BuildAttestation) error {
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
	PayloadType    string
	SignatureCount int
	BuilderID      string
	BuildType      string
	MaterialsCount int
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
	builderID, _ := nestedString(statement.Predicate, "builder", "id")
	buildType, _ := statement.Predicate["buildType"].(string)
	materialsCount := 0
	if materials, ok := statement.Predicate["materials"].([]any); ok {
		materialsCount = len(materials)
	}
	return replayedAttestation{
		PayloadType:    strings.TrimSpace(envelope.PayloadType),
		PredicateType:  strings.TrimSpace(statement.PredicateType),
		SubjectDigests: digests,
		SignatureCount: len(envelope.Signatures),
		BuilderID:      strings.TrimSpace(builderID),
		BuildType:      strings.TrimSpace(buildType),
		MaterialsCount: materialsCount,
	}, nil
}

func mergeReplayedAttestation(attestation domain.BuildAttestation, parsed replayedAttestation, raw []byte) (domain.BuildAttestation, bool) {
	changed := false
	if attestation.PayloadHash == "" {
		attestation.PayloadHash = digestBytes(raw)
		changed = true
	}
	if attestation.PayloadSize == 0 {
		attestation.PayloadSize = int64(len(raw))
		changed = true
	}
	if attestation.PayloadType == "" && parsed.PayloadType != "" {
		attestation.PayloadType = parsed.PayloadType
		changed = true
	}
	if attestation.PredicateType == "" && parsed.PredicateType != "" {
		attestation.PredicateType = parsed.PredicateType
		changed = true
	}
	if len(attestation.SubjectDigests) == 0 && len(parsed.SubjectDigests) != 0 {
		attestation.SubjectDigests = append([]string(nil), parsed.SubjectDigests...)
		changed = true
	}
	if attestation.SignatureCount == 0 && parsed.SignatureCount != 0 {
		attestation.SignatureCount = parsed.SignatureCount
		changed = true
	}
	if attestation.BuilderID == "" && parsed.BuilderID != "" {
		attestation.BuilderID = parsed.BuilderID
		changed = true
	}
	if attestation.BuildType == "" && parsed.BuildType != "" {
		attestation.BuildType = parsed.BuildType
		changed = true
	}
	if attestation.MaterialsCount == 0 && parsed.MaterialsCount != 0 {
		attestation.MaterialsCount = parsed.MaterialsCount
		changed = true
	}
	if attestation.VerificationStatus == "" || attestation.VerificationStatus == "accepted" {
		attestation.VerificationStatus = "structurally_valid"
		changed = true
	}
	return attestation, changed
}

func operationForMethod(item *openapi3.PathItem, method string) *openapi3.Operation {
	switch method {
	case "get":
		return item.Get
	case "put":
		return item.Put
	case "post":
		return item.Post
	case "delete":
		return item.Delete
	case "options":
		return item.Options
	case "head":
		return item.Head
	case "patch":
		return item.Patch
	case "trace":
		return item.Trace
	default:
		return nil
	}
}

func cloneIntMap(in map[string]int) map[string]int {
	if in == nil {
		return nil
	}
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func nonEmptyWorker(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func nestedString(in map[string]any, outer, inner string) (string, bool) {
	rawOuter, ok := in[outer].(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := rawOuter[inner].(string)
	return value, ok
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

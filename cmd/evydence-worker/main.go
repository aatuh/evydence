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
	scannerparser "github.com/aatuh/evydence/internal/app/parsers/scanners"
	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	"github.com/aatuh/evydence/internal/platform/redaction"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const defaultMaxWorkerPayloadBytes = 20 << 20

var (
	errParserPayloadReferenceMissing    = errors.New("parser payload reference is missing")
	errVEXDecisionDependenciesPending   = errors.New("vex decision prerequisites are pending")
	errVEXDecisionDependencyJobTerminal = errors.New("vex decision prerequisite parser job is terminal")
)

var expectedParserVersions = map[string]string{
	"parse_sbom":               app.ParserVersionCycloneDXJSON,
	"parse_vulnerability_scan": app.ParserVersionScannerAdaptersJSON,
	"parse_openapi_contract":   app.ParserVersionOpenAPIJSON,
	"parse_vex":                app.ParserVersionOpenVEXJSON,
	"verify_attestation":       app.ParserVersionDSSEInTotoJSON,
}

type parserReplayStore interface {
	Close()
	ApplyMigrations(context.Context, string) (int, error)
	RequireNoPendingMigrations(context.Context, string) error
	LoadState(context.Context) (app.PersistedState, bool, error)
	ApplyParserReplay(context.Context, app.ParserReplayRequest, app.ReleaseLedgerMutation) (string, bool, error)
}

var openParserReplayStore = func(ctx context.Context, databaseURL string, options postgres.StoreOptions) (parserReplayStore, error) {
	return postgres.OpenWithOptions(ctx, databaseURL, options)
}

var openParserReplayObjects = openObjectStore

func main() {
	if err := runWithArgs(os.Args[1:]); err != nil {
		log.Fatal(redaction.Error(err)) // #nosec G706 -- redaction.Error removes credentials and line breaks before logging.
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
		case "parser-replay":
			return runParserReplay(args[1:])
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
				if failure.Class == postgres.JobFailureTransient && failure.Code == "dependency_pending" {
					if deferErr := store.DeferJob(ctx, job.ID, job.LeaseToken, failure); deferErr != nil {
						log.Printf("record outbox deferral failed id=%s", job.ID)
					}
				} else if failErr := store.FailJob(ctx, job.ID, job.LeaseToken, failure); failErr != nil {
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

// runParserReplay is an explicit operator command that appends a derived
// normalization record. It cannot edit the source evidence or provider object.
func runParserReplay(args []string) error {
	request, err := parseParserReplayArgs(args)
	if err != nil {
		return err
	}
	production := strings.EqualFold(os.Getenv("ENV"), "production")
	databaseURL := strings.TrimSpace(os.Getenv("EVYDENCE_DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("parser-replay requires EVYDENCE_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), durationEnv("EVYDENCE_PARSER_REPLAY_TIMEOUT", 2*time.Minute))
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
	store, err := openParserReplayStore(ctx, databaseURL, postgres.StoreOptions{LoadMode: loadMode, DisableSnapshotWrites: production})
	if err != nil {
		return errors.New("parser-replay could not open durable storage")
	}
	defer store.Close()
	migrationsDir := envDefault("EVYDENCE_MIGRATIONS_DIR", "migrations")
	if !strings.EqualFold(os.Getenv("EVYDENCE_SKIP_MIGRATIONS"), "true") {
		if _, err := store.ApplyMigrations(ctx, migrationsDir); err != nil {
			return errors.New("parser-replay could not apply migrations")
		}
	} else if err := store.RequireNoPendingMigrations(ctx, migrationsDir); err != nil {
		return errors.New("parser-replay requires current migrations")
	}
	state, ok, err := store.LoadState(ctx)
	if err != nil || !ok {
		return errors.New("parser-replay could not load durable state")
	}
	replayRequest := app.ParserReplayRequest{
		TenantID:      request.TenantID,
		EvidenceID:    request.EvidenceID,
		ParserVersion: request.ParserVersion,
		ActorID:       request.ActorID,
		Now:           time.Now().UTC(),
	}
	key, err := app.ParserReplayPayloadKey(&state, replayRequest)
	if err != nil {
		return errors.New("parser-replay source evidence not found")
	}
	objects, _, err := openParserReplayObjects(ctx)
	if err != nil {
		return errors.New("parser-replay could not open object storage")
	}
	object, err := objects.Get(ctx, key)
	if err != nil {
		return errors.New("parser-replay source payload verification failed")
	}
	result, err := app.ReplayStoredParserEvidence(&state, object, replayRequest)
	if err != nil {
		return errors.New("parser-replay rejected requested interpretation")
	}
	mutation, err := app.ParserReplayMutation(&state, replayRequest, result)
	if err != nil {
		return errors.New("parser-replay rejected derived persistence mutation")
	}
	persistedID, created, err := store.ApplyParserReplay(ctx, replayRequest, mutation)
	if err != nil {
		return errors.New("parser-replay could not persist derived record")
	}
	result.EvidenceID = persistedID
	result.Created = created
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"evidence_id": result.EvidenceID, "created": result.Created, "parser_version": result.Parser.Version})
}

type parserReplayArgs struct {
	TenantID, EvidenceID, ParserVersion, ActorID string
}

func parseParserReplayArgs(args []string) (parserReplayArgs, error) {
	flags := flag.NewFlagSet("parser-replay", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	tenantID := flags.String("tenant", "", "tenant ID")
	evidenceID := flags.String("evidence", "", "source evidence ID")
	parserVersion := flags.String("parser-version", "", "installed parser version")
	actorID := flags.String("actor", "", "operator actor ID")
	apply := flags.Bool("apply", false, "append the derived replay record")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !*apply || strings.TrimSpace(*tenantID) == "" || strings.TrimSpace(*evidenceID) == "" || strings.TrimSpace(*parserVersion) == "" || strings.TrimSpace(*actorID) == "" {
		return parserReplayArgs{}, errors.New("parser-replay requires --tenant, --evidence, --parser-version, --actor, and --apply")
	}
	return parserReplayArgs{TenantID: strings.TrimSpace(*tenantID), EvidenceID: strings.TrimSpace(*evidenceID), ParserVersion: strings.TrimSpace(*parserVersion), ActorID: strings.TrimSpace(*actorID)}, nil
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
	if errors.Is(err, errParserPayloadReferenceMissing) {
		return postgres.JobFailure{Class: postgres.JobFailurePoisoned, Code: "payload_invariant_failed"}
	}
	if errors.Is(err, errVEXDecisionDependenciesPending) {
		return postgres.JobFailure{Class: postgres.JobFailureTransient, Code: "dependency_pending"}
	}
	if errors.Is(err, errVEXDecisionDependencyJobTerminal) {
		return postgres.JobFailure{Class: postgres.JobFailurePoisoned, Code: "dependency_failed"}
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "unsupported outbox job kind"), strings.Contains(message, "unsupported outbox parser version"), strings.Contains(message, "unsupported payload lifecycle version"), strings.Contains(message, "tenant-prefixed"), strings.Contains(message, "tenant mismatch"), strings.Contains(message, "digest mismatch"), strings.Contains(message, "payload hash"), strings.Contains(message, "durable state"), strings.Contains(message, "payload lifecycle state is not available"), strings.Contains(message, "payload is invalid"), strings.Contains(message, "normalized vex decision request"), strings.Contains(message, "vex decision job"):
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

type jobDependencyInspector interface {
	HasActiveJobDependency(context.Context, string, string, string, string) (bool, error)
}

type jobStateStore interface {
	jobStateLoader
	SaveState(context.Context, app.PersistedState) error
}

type jobReleaseLedgerMutationStore interface {
	jobStateLoader
	ApplyReleaseLedgerMutation(context.Context, app.ReleaseLedgerMutation) error
}

type jobClaimedReleaseLedgerMutationStore interface {
	jobStateLoader
	ApplyClaimedReleaseLedgerMutation(context.Context, string, string, app.ReleaseLedgerMutation) error
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

func completedVEXDecisionJob(ctx context.Context, state jobStateLoader, job postgres.ClaimedJob) (bool, error) {
	if job.Kind != "parse_vex" || !payloadBool(job, "worker_create_decisions") {
		return false, nil
	}
	snapshot, ok, err := state.LoadState(ctx)
	if err != nil {
		return false, errors.New("load durable state for vex decision job")
	}
	if !ok {
		return false, errors.New("durable state is not initialized")
	}
	vex, ok := snapshot.VEXDocuments[job.SubjectID]
	if !ok || vex.TenantID != job.TenantID {
		return false, errors.New("parsed vex document is not available in durable state")
	}
	_, report, err := requireVEXDecisionJobLinkage(snapshot, job, vex)
	if err != nil {
		return false, err
	}
	if err := requireParserVersion(job); err != nil {
		return false, failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
	}
	if err := requireVEXParserFormat(job, vex.Format, ""); err != nil {
		return false, failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
	}
	if report.Status == "parsed" {
		return true, nil
	}
	if err := vexDecisionDependencyError(ctx, state, &snapshot, job.TenantID, vex.ReleaseID); err != nil {
		if errors.Is(err, errVEXDecisionDependencyJobTerminal) {
			return false, failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
		}
		return false, err
	}
	return false, nil
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
	if completed, err := completedVEXDecisionJob(ctx, state, job); err != nil {
		return err
	} else if completed {
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
	if requireObjectReplay && !hasReplayedObject {
		if err := requireParserPayloadReference(job, snapshot); err != nil {
			return err
		}
	}
	if err := requireParserVersion(job); err != nil {
		if job.Kind == "parse_vex" {
			if vex, ok := snapshot.VEXDocuments[job.SubjectID]; ok && vex.TenantID == job.TenantID {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
		}
		return err
	}
	sideEffects := app.ReleaseLedgerMutation{}
	stateChanged := false
	switch job.Kind {
	case "parse_sbom":
		sbom, ok := snapshot.SBOMs[job.SubjectID]
		if !ok || sbom.TenantID != job.TenantID {
			return errors.New("parsed sbom is not available in durable state")
		}
		if hasReplayedObject {
			parsed, err := parseReplayedSBOM(replayed.Bytes, payloadString(job, "parser_version"))
			if err != nil {
				return err
			}
			if err := verifyReplayedSBOM(parsed, sbom); err != nil {
				return err
			}
			if updated, changed := mergeReplayedSBOM(sbom, parsed); changed {
				snapshot.SBOMs[job.SubjectID] = updated
				sideEffects.SBOMs = append(sideEffects.SBOMs, updated)
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
				sideEffects.Scans = append(sideEffects.Scans, updated)
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
				sideEffects.Contracts = append(sideEffects.Contracts, updated)
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
		var importReport domain.VEXImportReport
		if payloadBool(job, "worker_create_decisions") {
			var err error
			_, importReport, err = requireVEXDecisionJobLinkage(snapshot, job, vex)
			if err != nil {
				return err
			}
		}
		if err := requireVEXParserFormat(job, vex.Format, ""); err != nil {
			return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
		}
		if importReport.Status == "parsed" {
			return nil
		}
		if payloadBool(job, "worker_create_decisions") {
			if err := vexDecisionDependencyError(ctx, state, &snapshot, job.TenantID, vex.ReleaseID); err != nil {
				if errors.Is(err, errVEXDecisionDependencyJobTerminal) {
					return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
				}
				return err
			}
		}
		var parsed replayedVEX
		parsedAvailable := false
		if hasReplayedObject {
			parsed, err = parseReplayedVEX(replayed.Bytes)
			if err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			parsedAvailable = true
			if err := verifyReplayedVEX(parsed, vex); err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			if err := requireVEXParserFormat(job, vex.Format, parsed.Format); err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			// A legacy report count is acceptance-time durable state. Reconcile it
			// before hydrating the VEX projection or creating any decisions.
			if payloadBool(job, "worker_create_decisions") && payloadString(job, "decision_request_schema") == "" &&
				importReport.StatementCount > 0 && parsed.StatementCount != importReport.StatementCount {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, errors.New("replayed vex statement count does not match durable state"))
			}
			if updated, changed := mergeReplayedVEX(vex, parsed); changed {
				snapshot.VEXDocuments[job.SubjectID] = updated
				sideEffects.VEXDocuments = append(sideEffects.VEXDocuments, updated)
				stateChanged = true
			}
		}
		if payloadBool(job, "worker_create_decisions") {
			normalized, hasNormalized, err := normalizedVEXDecisionRequest(job, vex)
			if err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			if parsedAvailable && hasNormalized && !sameVEXDecisionStatements(parsed, normalized) {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, errors.New("normalized vex decision request does not match replayed payload"))
			}
			if !parsedAvailable {
				if !hasNormalized {
					return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, errors.New("normalized vex decision request is missing"))
				}
				parsed = normalized
			}
			decisionsBefore := snapshot.Decisions
			chainBefore := append([]domain.AuditChainEntry(nil), snapshot.Chain[job.TenantID]...)
			decisionPayloadHash := replayed.Digest
			if decisionPayloadHash == "" {
				decisionPayloadHash = payloadString(job, "payload_hash")
			}
			created, superseded, mappingFailures, duplicateStatements, err := applyReplayedVEXDecisions(&snapshot, job, vex, parsed, decisionPayloadHash)
			if err != nil {
				return failVEXImportReportWithSnapshot(ctx, state, &snapshot, job, vex, err)
			}
			appendReplayedVEXDecisionSideEffects(&sideEffects, decisionsBefore, chainBefore, snapshot, job.TenantID)
			if created > 0 {
				stateChanged = true
			}
			if updateVEXImportReport(&snapshot, job, vex, parsed, created, superseded, mappingFailures, duplicateStatements) {
				if _, report, ok := vexImportReportForJob(snapshot, job, vex); ok {
					sideEffects.VEXImportReports = append(sideEffects.VEXImportReports, report)
				}
				stateChanged = true
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
				sideEffects.BuildAttestations = append(sideEffects.BuildAttestations, updated)
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
		return persistParserSideEffects(ctx, state, snapshot, job, sideEffects)
	}
	return nil
}

func requireParserPayloadReference(job postgres.ClaimedJob, snapshot app.PersistedState) error {
	if payloadObjectKey(job) != "" {
		return nil
	}
	switch job.Kind {
	case "parse_sbom":
		value, ok := snapshot.SBOMs[job.SubjectID]
		if ok && value.TenantID == job.TenantID && strings.TrimSpace(value.SpecVersion) == "" {
			return errParserPayloadReferenceMissing
		}
	case "parse_vulnerability_scan":
		value, ok := snapshot.Scans[job.SubjectID]
		if ok && value.TenantID == job.TenantID && (strings.TrimSpace(value.Scanner) == "" || strings.TrimSpace(value.TargetRef) == "" || value.Summary == nil) {
			return errParserPayloadReferenceMissing
		}
	case "parse_openapi_contract":
		value, ok := snapshot.Contracts[job.SubjectID]
		if ok && value.TenantID == job.TenantID && value.PathCount == 0 && value.Operations == nil {
			return errParserPayloadReferenceMissing
		}
	case "verify_attestation":
		value, ok := snapshot.BuildAttestations[job.SubjectID]
		if ok && value.TenantID == job.TenantID && strings.EqualFold(strings.TrimSpace(value.VerificationStatus), "accepted") {
			return errParserPayloadReferenceMissing
		}
	}
	return nil
}

func persistParserSideEffects(ctx context.Context, state jobStateLoader, snapshot app.PersistedState, job postgres.ClaimedJob, sideEffects app.ReleaseLedgerMutation) error {
	if claimed, ok := state.(jobClaimedReleaseLedgerMutationStore); ok {
		if err := claimed.ApplyClaimedReleaseLedgerMutation(ctx, job.ID, job.LeaseToken, sideEffects); err != nil {
			return fmt.Errorf("persist claimed parser side effects: %w", err)
		}
		return nil
	}
	if focused, ok := state.(jobReleaseLedgerMutationStore); ok {
		if err := focused.ApplyReleaseLedgerMutation(ctx, sideEffects); err != nil {
			return fmt.Errorf("persist durable parser side effects: %w", err)
		}
		return nil
	}
	stateStore, ok := state.(jobStateStore)
	if !ok {
		return errors.New("durable parser side effects require writable state")
	}
	if err := stateStore.SaveState(ctx, snapshot); err != nil {
		return fmt.Errorf("persist durable parser side effects: %w", err)
	}
	return nil
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
	if job.Kind == "parse_sbom" && (got == app.ParserVersionCycloneDXJSON || got == app.ParserVersionSPDXJSON) {
		return nil
	}
	if job.Kind == "parse_vulnerability_scan" && (got == app.ParserVersionScannerAdaptersJSON || got == app.ParserVersionGenericVulnerabilityJSON) {
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

func parseReplayedSBOM(raw []byte, parserVersions ...string) (replayedSBOM, error) {
	parserVersion := ""
	if len(parserVersions) > 0 {
		parserVersion = parserVersions[0]
	}
	if parserVersion == "" || parserVersion == app.ParserVersionCycloneDXJSON {
		parsed, err := app.ParseCycloneDXReplayProjection(raw, defaultMaxWorkerPayloadBytes)
		if err != nil {
			return replayedSBOM{}, errors.New("replayed sbom payload is invalid")
		}
		return replayedSBOM{SpecVersion: parsed.SpecVersion, ComponentCount: len(parsed.Components), Components: append([]domain.SBOMComponent(nil), parsed.Components...)}, nil
	}
	parsed, err := app.ParseSPDXReplayProjection(raw, defaultMaxWorkerPayloadBytes)
	if err != nil {
		return replayedSBOM{}, errors.New("replayed sbom payload is invalid")
	}
	return replayedSBOM{SpecVersion: parsed.SpecVersion, ComponentCount: len(parsed.Components), Components: append([]domain.SBOMComponent(nil), parsed.Components...)}, nil
}

type replayedVulnerabilityScan struct {
	Scanner, Adapter, AdapterVersion, SourceSchema string
	TargetRef                                      string
	FindingCount                                   int
	Summary                                        map[string]int
	Findings                                       []domain.VulnerabilityFinding
}

func verifyReplayedVulnerabilityScan(parsed replayedVulnerabilityScan, scan domain.VulnerabilityScan) error {
	if scan.Scanner != "" && parsed.Scanner != scan.Scanner {
		return errors.New("replayed vulnerability scan payload does not match durable state")
	}
	if scan.TargetRef != "" && parsed.TargetRef != scan.TargetRef {
		return errors.New("replayed vulnerability scan payload does not match durable state")
	}
	if (scan.Adapter != "" && parsed.Adapter != scan.Adapter) || (scan.AdapterVersion != "" && parsed.AdapterVersion != scan.AdapterVersion) || (scan.SourceSchema != "" && parsed.SourceSchema != scan.SourceSchema) {
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
	if scan.Adapter == "" && parsed.Adapter != "" {
		scan.Adapter = parsed.Adapter
		changed = true
	}
	if scan.AdapterVersion == "" && parsed.AdapterVersion != "" {
		scan.AdapterVersion = parsed.AdapterVersion
		changed = true
	}
	if scan.SourceSchema == "" && parsed.SourceSchema != "" {
		scan.SourceSchema = parsed.SourceSchema
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
	doc, err := scannerparser.ParseBounded(raw, scannerparser.DefaultLimits(defaultMaxWorkerPayloadBytes))
	if err != nil {
		return replayedVulnerabilityScan{}, errors.New("replayed vulnerability scan payload is invalid")
	}
	summary := map[string]int{}
	findings := make([]domain.VulnerabilityFinding, 0, len(doc.Findings))
	for i, finding := range doc.Findings {
		summary[finding.Severity]++
		findings = append(findings, domain.VulnerabilityFinding{
			ID:            fmt.Sprintf("%s:finding:%d", strings.TrimSpace(subjectID), i+1),
			Vulnerability: finding.Vulnerability, Component: finding.Component, Severity: finding.Severity, State: finding.State, SeveritySource: finding.SeveritySource, FixVersion: finding.FixVersion,
			Identity: domain.VulnerabilityIdentity{CVE: finding.Identity.CVE, GHSA: finding.Identity.GHSA, OSV: finding.Identity.OSV, VendorAdvisory: finding.Identity.VendorAdvisory, PURL: finding.Identity.PURL, CPE: finding.Identity.CPE},
		})
	}
	return replayedVulnerabilityScan{Scanner: doc.Scanner, Adapter: doc.Adapter, AdapterVersion: doc.AdapterVersion, SourceSchema: doc.SourceSchema, TargetRef: doc.TargetRef, FindingCount: len(doc.Findings), Summary: summary, Findings: findings}, nil
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
	Format            string
	Author            string
	StatementCount    int
	StatusSummary     map[string]int
	Statements        []replayedVEXStatement
	Warnings          []string
	InvalidStatements []domain.VEXImportIssue
}

type replayedVEXStatement struct {
	StatementIndex  int
	Vulnerability   string
	Products        map[string]struct{}
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
}

func verifyReplayedVEX(parsed replayedVEX, vex domain.VEXDocument) error {
	if parsed.Format == "" || !strings.EqualFold(strings.TrimSpace(parsed.Format), strings.TrimSpace(vex.Format)) {
		return errors.New("replayed vex payload does not match durable state")
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

func requireVEXParserFormat(job postgres.ClaimedJob, durableFormat, replayedFormat string) error {
	parserVersion := payloadString(job, "parser_version")
	if parserVersion == "" {
		return nil
	}
	wantFormat := ""
	switch parserVersion {
	case app.ParserVersionOpenVEXJSON:
		wantFormat = "openvex"
	case app.ParserVersionCycloneDXVEXJSON:
		wantFormat = "cyclonedx"
	default:
		return errors.New("unsupported outbox parser version")
	}
	if !strings.EqualFold(strings.TrimSpace(durableFormat), wantFormat) {
		return errors.New("unsupported outbox parser version does not match durable vex format")
	}
	if replayedFormat != "" && !strings.EqualFold(strings.TrimSpace(replayedFormat), wantFormat) {
		return errors.New("unsupported outbox parser version does not match replayed vex format")
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
	doc, err := vexparser.ParseOpenVEX(raw, vexparser.DefaultLimits(defaultMaxWorkerPayloadBytes))
	if err != nil {
		return replayedVEX{}, errors.New("replayed vex payload is invalid")
	}
	return replayedVEXFromParsed(doc), nil
}

func parseReplayedCycloneDXVEX(raw []byte) (replayedVEX, error) {
	doc, err := vexparser.ParseCycloneDX(raw, vexparser.DefaultLimits(defaultMaxWorkerPayloadBytes))
	if err != nil {
		return replayedVEX{}, errors.New("replayed vex payload is invalid")
	}
	return replayedVEXFromParsed(doc), nil
}

func replayedVEXFromParsed(doc vexparser.Document) replayedVEX {
	summary := map[string]int{}
	statements := make([]replayedVEXStatement, 0, len(doc.Statements))
	invalidStatements := []domain.VEXImportIssue{}
	warnings := append([]string(nil), doc.Warnings...)
	decisionSource := replayedVEXDecisionSource(doc.Format)
	for index, statement := range doc.Statements {
		if statement.Vulnerability == "" {
			invalidStatements = append(invalidStatements, domain.VEXImportIssue{StatementIndex: index + 1, Code: "missing_vulnerability", Detail: "CycloneDX VEX vulnerability is missing an id."})
			continue
		}
		if statement.Status == "" {
			invalidStatements = append(invalidStatements, domain.VEXImportIssue{StatementIndex: index + 1, Code: "unsupported_analysis_state", Detail: "CycloneDX VEX vulnerability has an unsupported analysis state."})
			continue
		}
		products := map[string]struct{}{}
		for _, product := range statement.Products {
			products[product] = struct{}{}
		}
		summary[statement.Status]++
		statements = append(statements, replayedVEXStatement{StatementIndex: index + 1, Vulnerability: statement.Vulnerability, Products: products, Status: statement.Status, Justification: nonEmptyWorker(statement.Justification, decisionSource), ImpactStatement: statement.ImpactStatement, ActionStatement: statement.ActionStatement})
	}
	if len(invalidStatements) > 0 && strings.EqualFold(strings.TrimSpace(doc.Format), "cyclonedx") {
		warnings = append(warnings, "One or more CycloneDX VEX vulnerabilities were skipped because required analysis fields were missing or unsupported.")
	}
	return replayedVEX{Format: doc.Format, Author: doc.Author, StatementCount: len(doc.Statements), StatusSummary: summary, Statements: statements, Warnings: warnings, InvalidStatements: invalidStatements}
}

func normalizedVEXDecisionRequest(job postgres.ClaimedJob, vex domain.VEXDocument) (replayedVEX, bool, error) {
	schema := payloadString(job, "decision_request_schema")
	if schema == "" {
		return replayedVEX{}, false, nil
	}
	if schema != evidenceapp.VEXDecisionRequestSchemaVersion {
		return replayedVEX{}, false, errors.New("normalized vex decision request schema is unsupported")
	}
	rows, ok := normalizedVEXRows(job.Payload["decision_statements"])
	limits := vexparser.DefaultLimits(defaultMaxWorkerPayloadBytes)
	if !ok || len(rows) == 0 || len(rows) > limits.MaxStatements || vex.StatementCount <= 0 || len(rows) > vex.StatementCount {
		return replayedVEX{}, false, errors.New("normalized vex decision request is invalid")
	}
	format := strings.ToLower(strings.TrimSpace(vex.Format))
	if format != "openvex" && format != "cyclonedx" {
		return replayedVEX{}, false, errors.New("normalized vex decision request format is invalid")
	}
	result := replayedVEX{
		Format: format, Author: vex.Author, StatementCount: vex.StatementCount,
		StatusSummary: map[string]int{}, Statements: make([]replayedVEXStatement, 0, len(rows)),
	}
	seenIndexes := map[int]struct{}{}
	valueCount := 0
	textBytes := int64(0)
	for _, row := range rows {
		if !normalizedVEXKeysValid(row) {
			return replayedVEX{}, false, errors.New("normalized vex decision request is invalid")
		}
		index, ok := normalizedVEXInteger(row["statement_index"])
		vulnerability, vulnerabilityOK := normalizedVEXString(row["vulnerability"], limits.MaxStringBytes)
		status, statusOK := normalizedVEXString(row["status"], limits.MaxStringBytes)
		justification, justificationOK := normalizedVEXOptionalString(row["justification"], limits.MaxStringBytes)
		impact, impactOK := normalizedVEXOptionalString(row["impact_statement"], limits.MaxStringBytes)
		action, actionOK := normalizedVEXOptionalString(row["action_statement"], limits.MaxStringBytes)
		products, productsOK := normalizedVEXProducts(row["products"], limits.MaxStatements, limits.MaxStringBytes)
		if !ok || !vulnerabilityOK || !statusOK || !justificationOK || !impactOK || !actionOK || !productsOK || index <= 0 || index > vex.StatementCount || !normalizedVEXStatus(status) {
			return replayedVEX{}, false, errors.New("normalized vex decision request is invalid")
		}
		if _, duplicate := seenIndexes[index]; duplicate {
			return replayedVEX{}, false, errors.New("normalized vex decision request is invalid")
		}
		seenIndexes[index] = struct{}{}
		valueCount += 7 + len(products)
		statementBytes := int64(len(vulnerability) + len(status) + len(justification) + len(impact) + len(action))
		for _, product := range products {
			statementBytes += int64(len(product))
		}
		if valueCount > limits.MaxValues || statementBytes > limits.MaxBytes || textBytes > limits.MaxBytes-statementBytes || (format == "openvex" && len(products) == 0) {
			return replayedVEX{}, false, errors.New("normalized vex decision request is invalid")
		}
		textBytes += statementBytes
		productSet := make(map[string]struct{}, len(products))
		for _, product := range products {
			productSet[product] = struct{}{}
		}
		justification = nonEmptyWorker(justification, replayedVEXDecisionSource(format))
		result.StatusSummary[status]++
		result.Statements = append(result.Statements, replayedVEXStatement{
			StatementIndex: index, Vulnerability: vulnerability, Products: productSet, Status: status,
			Justification: justification, ImpactStatement: impact, ActionStatement: action,
		})
	}
	if len(result.StatusSummary) != len(vex.StatusSummary) {
		return replayedVEX{}, false, errors.New("normalized vex decision request does not match durable state")
	}
	for status, count := range result.StatusSummary {
		if vex.StatusSummary[status] != count {
			return replayedVEX{}, false, errors.New("normalized vex decision request does not match durable state")
		}
	}
	if err := verifyReplayedVEX(result, vex); err != nil {
		return replayedVEX{}, false, errors.New("normalized vex decision request does not match durable state")
	}
	return result, true, nil
}

func normalizedVEXRows(value any) ([]map[string]any, bool) {
	switch rows := value.(type) {
	case []map[string]any:
		return rows, true
	case []any:
		result := make([]map[string]any, 0, len(rows))
		for _, value := range rows {
			row, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			result = append(result, row)
		}
		return result, true
	default:
		return nil, false
	}
}

func normalizedVEXKeysValid(row map[string]any) bool {
	allowed := map[string]struct{}{
		"statement_index": {}, "vulnerability": {}, "products": {}, "status": {},
		"justification": {}, "impact_statement": {}, "action_statement": {},
	}
	for key := range row {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	for _, required := range []string{"statement_index", "vulnerability", "products", "status"} {
		if _, ok := row[required]; !ok {
			return false
		}
	}
	return true
}

func normalizedVEXInteger(value any) (int, bool) {
	maxInt := int(^uint(0) >> 1)
	switch value := value.(type) {
	case int:
		return value, value > 0
	case int64:
		if value > 0 && uint64(value) <= uint64(maxInt) {
			return int(value), true
		}
	case float64:
		if value >= 1 && value <= float64(maxInt) {
			converted := int(value)
			if value == float64(converted) {
				return converted, true
			}
		}
	case json.Number:
		parsed, err := strconv.Atoi(value.String())
		return parsed, err == nil && parsed > 0
	}
	return 0, false
}

func normalizedVEXString(value any, maxBytes int64) (string, bool) {
	text, ok := value.(string)
	text = strings.TrimSpace(text)
	return text, ok && text != "" && int64(len(text)) <= maxBytes
}

func normalizedVEXOptionalString(value any, maxBytes int64) (string, bool) {
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	text = strings.TrimSpace(text)
	return text, ok && int64(len(text)) <= maxBytes
}

func normalizedVEXProducts(value any, maxItems int, maxBytes int64) ([]string, bool) {
	var values []any
	switch products := value.(type) {
	case []string:
		values = make([]any, 0, len(products))
		for _, product := range products {
			values = append(values, product)
		}
	case []any:
		values = products
	default:
		return nil, false
	}
	if len(values) > maxItems {
		return nil, false
	}
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		product, ok := normalizedVEXString(value, maxBytes)
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[product]; duplicate {
			return nil, false
		}
		seen[product] = struct{}{}
		result = append(result, product)
	}
	return result, true
}

func normalizedVEXStatus(status string) bool {
	switch status {
	case "affected", "not_affected", "fixed", "under_investigation":
		return true
	default:
		return false
	}
}

func sameVEXDecisionStatements(first, second replayedVEX) bool {
	if first.Format != second.Format || len(first.Statements) != len(second.Statements) {
		return false
	}
	for index := range first.Statements {
		a, b := first.Statements[index], second.Statements[index]
		if a.StatementIndex != b.StatementIndex || a.Vulnerability != b.Vulnerability || a.Status != b.Status || a.Justification != b.Justification || a.ImpactStatement != b.ImpactStatement || a.ActionStatement != b.ActionStatement || len(a.Products) != len(b.Products) {
			return false
		}
		for product := range a.Products {
			if _, ok := b.Products[product]; !ok {
				return false
			}
		}
	}
	return true
}

func applyReplayedVEXDecisions(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, parsed replayedVEX, payloadHash string) (int, int, []domain.VEXImportIssue, bool, error) {
	appendChainEntry := func(state *app.PersistedState, now time.Time, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef string) (domain.AuditChainEntry, error) {
		entry, err := app.AppendPersistedChainEntry(state, now, tenantID, entryType, subjectType, subjectID, actorType, actorID, payloadHash, signatureRef)
		if err != nil {
			return domain.AuditChainEntry{}, err
		}
		entries := state.Chain[tenantID]
		if len(entries) == 0 {
			return domain.AuditChainEntry{}, errors.New("replayed vex audit entry was not appended")
		}
		entry.ID = replayedVEXAuditEntryID(job.ID, vex.ID, entryType, subjectType, subjectID, payloadHash)
		if err := app.RehashAuditChainEntry(&entry); err != nil {
			return domain.AuditChainEntry{}, err
		}
		entries[len(entries)-1] = entry
		state.Chain[tenantID] = entries
		return entry, nil
	}
	return applyReplayedVEXDecisionsWithAppender(state, job, vex, parsed, payloadHash, appendChainEntry)
}

type replayedVEXChainAppender func(*app.PersistedState, time.Time, string, string, string, string, string, string, string, string) (domain.AuditChainEntry, error)

func applyReplayedVEXDecisionsWithAppender(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, parsed replayedVEX, payloadHash string, appendChainEntry replayedVEXChainAppender) (int, int, []domain.VEXImportIssue, bool, error) {
	working := cloneReplayedVEXDecisionState(*state)
	actorType := nonEmptyWorker(payloadString(job, "actor_type"), "worker")
	actorID := nonEmptyWorker(payloadString(job, "actor_id"), job.ID)
	evidenceID := payloadString(job, "evidence_id")
	now := time.Now().UTC()
	mappingInput := riskapp.VEXMappingInput{
		TenantID: job.TenantID, ReleaseID: vex.ReleaseID, VEXDocumentID: vex.ID, EvidenceID: evidenceID,
		ActorID: actorID, Source: replayedVEXDecisionSource(parsed.Format), CreatedAt: now,
	}
	scanIDs := make([]string, 0, len(working.Scans))
	for id, scan := range working.Scans {
		if scan.TenantID == job.TenantID && scan.ReleaseID == vex.ReleaseID {
			scanIDs = append(scanIDs, id)
		}
	}
	sort.Strings(scanIDs)
	for index, statement := range parsed.Statements {
		statementIndex := statement.StatementIndex
		if statementIndex <= 0 {
			statementIndex = index + 1
		}
		products := make([]string, 0, len(statement.Products))
		for product := range statement.Products {
			products = append(products, product)
		}
		mappingInput.Statements = append(mappingInput.Statements, riskapp.VEXStatement{
			Index: statementIndex, Vulnerability: statement.Vulnerability, Products: products,
			Status: statement.Status, Justification: statement.Justification,
			ImpactStatement: statement.ImpactStatement, ActionStatement: statement.ActionStatement,
		})
	}
	findingIDs := map[string]struct{}{}
	for _, scanID := range scanIDs {
		scan := working.Scans[scanID]
		for _, finding := range scan.Findings {
			findingIDs[finding.ID] = struct{}{}
			mappingInput.Findings = append(mappingInput.Findings, riskapp.VEXFinding{
				ID: finding.ID, ScanID: scan.ID, TenantID: scan.TenantID, ReleaseID: scan.ReleaseID,
				Vulnerability: finding.Vulnerability, Component: finding.Component,
			})
		}
	}
	for _, decision := range working.Decisions {
		if decision.TenantID != job.TenantID {
			continue
		}
		if _, relevant := findingIDs[decision.FindingID]; !relevant {
			continue
		}
		status, err := riskdomain.ParseDecisionStatus(decision.Status)
		if err != nil {
			status, _ = riskdomain.ParseDecisionStatus(riskdomain.DecisionStatusAffectedValue)
		}
		mappingInput.ExistingDecisions = append(mappingInput.ExistingDecisions, riskdomain.VulnerabilityDecision{
			ID: decision.ID, TenantID: decision.TenantID, ReleaseID: decision.ReleaseID, FindingID: decision.FindingID,
			Status: status, VEXDocumentID: decision.VEXDocumentID, SupersededBy: decision.SupersededBy,
		})
	}
	mapping, err := riskapp.MapVEXDecisions(mappingInput, riskapp.VEXDecisionIDFunc(replayedVEXDecisionID))
	if err != nil {
		return 0, 0, nil, false, errors.New("map replayed vex decisions")
	}
	mappingFailures := make([]domain.VEXImportIssue, 0, len(mapping.Failures))
	for _, failure := range mapping.Failures {
		mappingFailures = append(mappingFailures, domain.VEXImportIssue{StatementIndex: failure.StatementIndex, Code: failure.Code, Detail: failure.Detail})
	}
	created, superseded := 0, 0
	for _, decision := range mapping.Created {
		for _, prior := range mapping.Superseded {
			if prior.SupersededBy != decision.ID {
				continue
			}
			legacy := working.Decisions[prior.ID]
			legacy.SupersededBy = prior.SupersededBy
			working.Decisions[legacy.ID] = legacy
			superseded++
			if _, err := appendChainEntry(&working, now, job.TenantID, "vulnerability_decision.superseded", "vulnerability_decision", legacy.ID, actorType, actorID, payloadHash, ""); err != nil {
				return created, superseded, mappingFailures, mapping.HadDuplicate, errors.New("append replayed vex decision supersession audit entry")
			}
		}
		legacy := domain.VulnerabilityDecisionFromContextModel(decision)
		working.Decisions[legacy.ID] = legacy
		if _, err := appendChainEntry(&working, now, job.TenantID, "vulnerability_decision.created", "vulnerability_finding", legacy.FindingID, actorType, actorID, payloadHash, ""); err != nil {
			return created, superseded, mappingFailures, mapping.HadDuplicate, errors.New("append replayed vex decision audit entry")
		}
		created++
	}
	state.Decisions = working.Decisions
	state.Chain = working.Chain
	return created, superseded, mappingFailures, mapping.HadDuplicate, nil
}

func cloneReplayedVEXDecisionState(state app.PersistedState) app.PersistedState {
	cloned := state
	cloned.Decisions = make(map[string]domain.VulnerabilityDecision, len(state.Decisions))
	for id, decision := range state.Decisions {
		cloned.Decisions[id] = decision
	}
	if state.Chain != nil {
		cloned.Chain = make(map[string][]domain.AuditChainEntry, len(state.Chain))
		for tenantID, entries := range state.Chain {
			cloned.Chain[tenantID] = append([]domain.AuditChainEntry(nil), entries...)
		}
	}
	return cloned
}

func replayedVEXDecisionSource(format string) string {
	if strings.EqualFold(strings.TrimSpace(format), "cyclonedx") {
		return "cyclonedx_vex"
	}
	return "vex"
}

func workerVEXStatementUnambiguous(state *app.PersistedState, scanIDs []string, statement replayedVEXStatement) bool {
	matchCount := 0
	components := map[string]struct{}{}
	hasUnstableComponent := false
	hasDuplicateComponent := false
	for _, scanID := range scanIDs {
		for _, finding := range state.Scans[scanID].Findings {
			if finding.Vulnerability != statement.Vulnerability {
				continue
			}
			if len(statement.Products) > 0 && finding.Component != "" {
				if _, ok := statement.Products[finding.Component]; !ok {
					continue
				}
			}
			matchCount++
			component := strings.TrimSpace(finding.Component)
			if component == "" {
				hasUnstableComponent = true
				continue
			}
			if _, duplicate := components[component]; duplicate {
				hasDuplicateComponent = true
				continue
			}
			components[component] = struct{}{}
		}
	}
	if matchCount < 2 {
		return true
	}
	return len(statement.Products) > 0 && matchCount <= len(statement.Products) && !hasUnstableComponent && !hasDuplicateComponent
}

func appendReplayedVEXDecisionSideEffects(mutation *app.ReleaseLedgerMutation, beforeDecisions map[string]domain.VulnerabilityDecision, beforeChain []domain.AuditChainEntry, after app.PersistedState, tenantID string) {
	changedDecisionIDs := make([]string, 0)
	for id, decision := range after.Decisions {
		before, existed := beforeDecisions[id]
		if !existed || before.SupersededBy != decision.SupersededBy {
			changedDecisionIDs = append(changedDecisionIDs, id)
		}
	}
	sort.Strings(changedDecisionIDs)
	for _, id := range changedDecisionIDs {
		mutation.VulnerabilityDecisions = append(mutation.VulnerabilityDecisions, after.Decisions[id])
	}

	priorEntries := make(map[string]struct{}, len(beforeChain))
	for _, entry := range beforeChain {
		priorEntries[entry.ID] = struct{}{}
	}
	for _, entry := range after.Chain[tenantID] {
		if _, existed := priorEntries[entry.ID]; !existed {
			mutation.AuditChainEntries = append(mutation.AuditChainEntries, entry)
		}
	}
}

func requireVEXDecisionJobLinkage(state app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument) (string, domain.VEXImportReport, error) {
	reportID := payloadString(job, "import_report_id")
	report, ok := state.VEXImportReports[reportID]
	if reportID == "" || !ok || report.ID != reportID || vex.ID == "" || vex.ID != job.SubjectID {
		return "", domain.VEXImportReport{}, errors.New("vex decision job durable report linkage is invalid")
	}
	requestSchema := payloadString(job, "decision_request_schema")
	strict := requestSchema != ""
	evidenceID := payloadString(job, "evidence_id")
	// Jobs queued before normalized decision requests stored the parsed count on
	// the import report while leaving the VEX projection at its zero placeholder.
	// Only that placeholder may defer equality until the raw payload is replayed.
	if evidenceID == "" || vex.EvidenceID == "" || evidenceID != vex.EvidenceID ||
		report.TenantID != job.TenantID || report.VEXDocumentID != vex.ID || report.EvidenceID != vex.EvidenceID ||
		report.ReleaseID != vex.ReleaseID || report.ArtifactID != vex.ArtifactID || report.StatementCount < 0 || vex.StatementCount < 0 ||
		(strict && report.StatementCount != vex.StatementCount) || (!strict && vex.StatementCount != 0 && report.StatementCount != vex.StatementCount) {
		return "", domain.VEXImportReport{}, errors.New("vex decision job durable report linkage is invalid")
	}
	switch report.Status {
	case "accepted", "failed", "parsed":
	default:
		return "", domain.VEXImportReport{}, errors.New("vex decision job durable report state is invalid")
	}
	expectedParserVersion, ok := expectedVEXParserVersion(vex.Format)
	if !ok {
		return "", domain.VEXImportReport{}, errors.New("vex decision job durable format is invalid")
	}
	jobParserVersion := payloadString(job, "parser_version")
	if (jobParserVersion != "" && jobParserVersion != expectedParserVersion) ||
		(report.ParserVersion != "" && report.ParserVersion != expectedParserVersion) ||
		(strict && (jobParserVersion == "" || report.ParserVersion == "")) {
		return "", domain.VEXImportReport{}, errors.New("vex decision job parser linkage is invalid")
	}
	if !validWorkerDigest(payloadString(job, "payload_hash")) {
		return "", domain.VEXImportReport{}, errors.New("vex decision job payload hash is invalid")
	}
	if job.SubjectType != "" && job.SubjectType != "vex_document" {
		return "", domain.VEXImportReport{}, errors.New("vex decision job subject linkage is invalid")
	}
	if strict {
		if job.SubjectType != "vex_document" || vex.ReleaseID == "" || payloadString(job, "release_id") != vex.ReleaseID || payloadString(job, "artifact_id") != vex.ArtifactID ||
			vex.SchemaVersion != domain.VEXDocumentSchemaVersion || report.SchemaVersion != domain.VEXImportReportSchemaVersion || vex.StatementCount <= 0 {
			return "", domain.VEXImportReport{}, errors.New("vex decision job durable schema linkage is invalid")
		}
		evidence, ok := state.Evidence[vex.EvidenceID]
		if !ok || evidence.ID != vex.EvidenceID || evidence.TenantID != job.TenantID || evidence.ReleaseID != vex.ReleaseID ||
			evidence.Type != "vex" || evidence.Subtype != strings.ToLower(strings.TrimSpace(vex.Format)) ||
			evidence.PayloadHash != payloadString(job, "payload_hash") || evidence.PayloadRef != payloadString(job, "payload_ref") ||
			!evidenceHasOnlyArtifactSubject(evidence, vex.ArtifactID) {
			return "", domain.VEXImportReport{}, errors.New("vex decision job durable evidence linkage is invalid")
		}
		actorType := payloadString(job, "actor_type")
		actorID := payloadString(job, "actor_id")
		if !validVEXDecisionActor(actorType, actorID) || !vexAcceptedAuditMatches(state, job, vex, actorType, actorID) ||
			(actorType == "api_key" && evidence.UploadedBy != actorID) ||
			(actorType == "collector" && evidence.CollectorID != actorID) {
			return "", domain.VEXImportReport{}, errors.New("vex decision job durable actor linkage is invalid")
		}
	}
	return reportID, report, nil
}

func expectedVEXParserVersion(format string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "openvex":
		return app.ParserVersionOpenVEXJSON, true
	case "cyclonedx":
		return app.ParserVersionCycloneDXVEXJSON, true
	default:
		return "", false
	}
}

func evidenceHasOnlyArtifactSubject(evidence domain.EvidenceItem, artifactID string) bool {
	artifactID = strings.TrimSpace(artifactID)
	found := false
	for _, subject := range evidence.SubjectRefs {
		if strings.TrimSpace(subject.Type) != "artifact" {
			continue
		}
		if artifactID == "" {
			return false
		}
		if strings.TrimSpace(subject.ID) != artifactID {
			return false
		}
		found = true
	}
	return found == (artifactID != "")
}

func validVEXDecisionActor(actorType, actorID string) bool {
	if strings.TrimSpace(actorID) == "" {
		return false
	}
	switch strings.TrimSpace(actorType) {
	case "api_key", "collector", "human_user":
		return true
	default:
		return false
	}
}

func vexDecisionDependencyError(ctx context.Context, loader jobStateLoader, state *app.PersistedState, tenantID, releaseID string) error {
	if state == nil {
		return errVEXDecisionDependencyJobTerminal
	}
	pendingScanIDs := make([]string, 0)
	for id, scan := range state.Scans {
		if scan.TenantID != tenantID || scan.ReleaseID != releaseID {
			continue
		}
		if pendingVulnerabilityScanProjection(scan) {
			if strings.TrimSpace(id) == "" || scan.ID != id {
				return errVEXDecisionDependencyJobTerminal
			}
			pendingScanIDs = append(pendingScanIDs, id)
		}
	}
	if len(pendingScanIDs) == 0 {
		return nil
	}
	inspector, ok := loader.(jobDependencyInspector)
	if !ok {
		return errVEXDecisionDependenciesPending
	}
	sort.Strings(pendingScanIDs)
	for _, scanID := range pendingScanIDs {
		scan, exists := state.Scans[scanID]
		if !exists || scan.TenantID != tenantID || scan.ReleaseID != releaseID || scan.ID != scanID {
			return errVEXDecisionDependencyJobTerminal
		}
		if !pendingVulnerabilityScanProjection(scan) {
			continue
		}
		active, err := inspector.HasActiveJobDependency(ctx, tenantID, "parse_vulnerability_scan", "vulnerability_scan", scanID)
		if err != nil {
			return errors.New("inspect vex decision prerequisite job")
		}
		if !active {
			refreshed, ok, err := loader.LoadState(ctx)
			if err != nil || !ok {
				return errors.New("recheck vex decision prerequisite projection")
			}
			refreshedScan, exists := refreshed.Scans[scanID]
			if !exists || refreshedScan.TenantID != tenantID || refreshedScan.ReleaseID != releaseID || refreshedScan.ID != scanID {
				return errVEXDecisionDependencyJobTerminal
			}
			*state = refreshed
			if !pendingVulnerabilityScanProjection(refreshedScan) {
				continue
			}
			// A terminal job may be replayed between the first status check and
			// the durable projection reload. Recheck before concluding that the
			// still-empty projection can no longer be published.
			active, err = inspector.HasActiveJobDependency(ctx, tenantID, "parse_vulnerability_scan", "vulnerability_scan", scanID)
			if err != nil {
				return errors.New("recheck vex decision prerequisite job")
			}
			if !active {
				return errVEXDecisionDependencyJobTerminal
			}
		}
	}
	for _, scanID := range pendingScanIDs {
		if scan, ok := state.Scans[scanID]; ok && pendingVulnerabilityScanProjection(scan) {
			return errVEXDecisionDependenciesPending
		}
	}
	return nil
}

func pendingVulnerabilityScanProjection(scan domain.VulnerabilityScan) bool {
	return scan.Findings == nil && scan.Summary == nil && strings.TrimSpace(scan.Scanner) == "" &&
		strings.TrimSpace(scan.Adapter) == "" && strings.TrimSpace(scan.AdapterVersion) == "" &&
		strings.TrimSpace(scan.SourceSchema) == "" && strings.TrimSpace(scan.TargetRef) == ""
}

func vexAcceptedAuditMatches(state app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, actorType, actorID string) bool {
	payloadHash := payloadString(job, "payload_hash")
	for _, entry := range state.Chain[job.TenantID] {
		if entry.TenantID == job.TenantID && entry.EntryType == "vex.accepted" && entry.SubjectType == "vex_document" && entry.SubjectID == vex.ID &&
			entry.ActorType == actorType && entry.ActorID == actorID && entry.PayloadHash == payloadHash {
			return true
		}
	}
	return false
}

func vexImportReportForJob(state app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument) (string, domain.VEXImportReport, bool) {
	reportID := payloadString(job, "import_report_id")
	if reportID != "" {
		report, ok := state.VEXImportReports[reportID]
		if !ok || report.TenantID != job.TenantID || report.VEXDocumentID != vex.ID {
			return "", domain.VEXImportReport{}, false
		}
		return reportID, report, true
	}
	reportIDs := make([]string, 0, len(state.VEXImportReports))
	for id, report := range state.VEXImportReports {
		if report.TenantID == job.TenantID && report.VEXDocumentID == vex.ID {
			reportIDs = append(reportIDs, id)
		}
	}
	if len(reportIDs) == 0 {
		return "", domain.VEXImportReport{}, false
	}
	sort.Strings(reportIDs)
	reportID = reportIDs[0]
	return reportID, state.VEXImportReports[reportID], true
}

func updateVEXImportReport(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, parsed replayedVEX, created, superseded int, mappingFailures []domain.VEXImportIssue, duplicateStatements bool) bool {
	if state.VEXImportReports == nil {
		state.VEXImportReports = map[string]domain.VEXImportReport{}
	}
	reportID, report, ok := vexImportReportForJob(*state, job, vex)
	if !ok {
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
	warnings := append([]string(nil), parsed.Warnings...)
	if duplicateStatements {
		if strings.EqualFold(strings.TrimSpace(parsed.Format), "cyclonedx") {
			warnings = append(warnings, "Duplicate CycloneDX VEX vulnerabilities for an already mapped finding were ignored.")
		} else {
			warnings = append(warnings, "Duplicate VEX statements for an already mapped finding were ignored.")
		}
	}
	if merged, appended := appendUniqueWorkerStrings(updated.Warnings, warnings); appended {
		updated.Warnings = merged
		changed = true
	}
	if merged, appended := appendUniqueVEXImportIssues(updated.InvalidStatements, parsed.InvalidStatements); appended {
		updated.InvalidStatements = merged
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

func appendUniqueWorkerStrings(existing, additions []string) ([]string, bool) {
	seen := make(map[string]struct{}, len(existing)+len(additions))
	for _, value := range existing {
		seen[value] = struct{}{}
	}
	merged := append([]string(nil), existing...)
	changed := false
	for _, value := range additions {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
		changed = true
	}
	return merged, changed
}

func appendUniqueVEXImportIssues(existing, additions []domain.VEXImportIssue) ([]domain.VEXImportIssue, bool) {
	seen := make(map[domain.VEXImportIssue]struct{}, len(existing)+len(additions))
	for _, issue := range existing {
		seen[issue] = struct{}{}
	}
	merged := append([]domain.VEXImportIssue(nil), existing...)
	changed := false
	for _, issue := range additions {
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		merged = append(merged, issue)
		changed = true
	}
	return merged, changed
}

func failVEXImportReportWithSnapshot(ctx context.Context, state jobStateLoader, snapshot *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, cause error) error {
	if updateVEXImportReportFailure(snapshot, job, vex, cause) {
		_, report, ok := vexImportReportForJob(*snapshot, job, vex)
		if !ok {
			return cause
		}
		sideEffects := app.ReleaseLedgerMutation{VEXImportReports: []domain.VEXImportReport{report}}
		if err := persistParserSideEffects(ctx, state, *snapshot, job, sideEffects); err != nil {
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
	_, report, ok := vexImportReportForJob(snapshot, job, vex)
	if !ok {
		return
	}
	sideEffects := app.ReleaseLedgerMutation{VEXImportReports: []domain.VEXImportReport{report}}
	_ = persistParserSideEffects(ctx, state, snapshot, job, sideEffects)
}

func updateVEXImportReportFailure(state *app.PersistedState, job postgres.ClaimedJob, vex domain.VEXDocument, cause error) bool {
	if state.VEXImportReports == nil {
		state.VEXImportReports = map[string]domain.VEXImportReport{}
	}
	reportID, report, ok := vexImportReportForJob(*state, job, vex)
	if !ok {
		return false
	}
	// Decision, audit, and report effects commit atomically. Once the report is
	// parsed, a reclaimed job is already complete and must never regress that
	// durable success because a replay object later becomes unavailable.
	if report.Status == "parsed" {
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
	if errors.Is(cause, errVEXDecisionDependencyJobTerminal) {
		return "dependency_failed"
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
	case strings.Contains(message, "normalized vex decision request"):
		return "durable_state_mismatch"
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
	case "dependency_failed":
		return "A required vulnerability-scan parser job reached a terminal state before publishing its projection."
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

func replayedVEXAuditEntryID(jobID, vexID, entryType, subjectType, subjectID, payloadHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{jobID, vexID, entryType, subjectType, subjectID, payloadHash}, "\x00")))
	return "ace_vex_" + hex.EncodeToString(sum[:])
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

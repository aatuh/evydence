package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
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

type jobStateStore interface {
	jobStateLoader
	SaveState(context.Context, app.PersistedState) error
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
	if err := requireParserVersion(job); err != nil {
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
				return err
			}
			if err := verifyReplayedVEX(parsed, vex); err != nil {
				return err
			}
			if updated, changed := mergeReplayedVEX(vex, parsed); changed {
				snapshot.VEXDocuments[job.SubjectID] = updated
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
		stateStore, ok := state.(jobStateStore)
		if !ok {
			return errors.New("durable parser side effects require writable state")
		}
		if err := stateStore.SaveState(ctx, snapshot); err != nil {
			return errors.New("persist durable parser side effects")
		}
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
	if got != expected {
		return errors.New("unsupported outbox parser version")
	}
	return nil
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

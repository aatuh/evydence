package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

type memoryAnomalyPorts interface {
	experimentalapp.AnomalyScopeReader
	experimentalapp.AnomalyReleaseFactsReader
	InsertFocusedAnomalyReport(context.Context, experimentaldomain.AnomalyReport) error
}

func memoryAnomalyFixture(t *testing.T) (*memoryUnitOfWork, memoryAnomalyPorts) {
	t.Helper()
	_, tx := memoryQuestionnaireFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	tx.state.Artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: "tenant", Digest: digest}
	e := tx.state.Evidence["tenant-evidence"]
	e.SubjectRefs = []domain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: "opaque-untrusted"}}
	tx.state.Evidence[e.ID] = e
	tx.state.BuildRuns["build"] = domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "tenant-project", ReleaseID: "tenant-release", Status: "passed", Outputs: []domain.BuildOutput{{ArtifactID: "artifact", Digest: digest}}, SourceIdentity: map[string]any{"private": strings.Repeat("private", 10000)}}
	tx.state.BuildAttestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: "tenant", BuildID: "build", EvidenceID: "attestation-source", PayloadHash: digest, PayloadSize: 42, PayloadRef: "private-payload", SubjectDigests: []string{digest}}
	tx.state.Evidence["attestation-source"] = domain.EvidenceItem{ID: "attestation-source", TenantID: "tenant", ProductID: "tenant-product", ProjectID: "tenant-project", ReleaseID: "tenant-release", BuildID: "build", Type: "build_attestation", PayloadHash: digest, PayloadSize: 42, PayloadRef: "private-payload"}
	tx.state.VerificationResults["receipt"] = domain.VerificationResult{ID: "receipt", TenantID: "tenant", SubjectType: "build_attestation", SubjectID: "attestation", Result: "passed", Profile: domain.VerificationProfile{ID: domain.VerificationProfileDSSEAttestationSignature}, SchemaVersion: domain.VerificationResultSchemaVersion, Checks: []domain.VerifyCheck{{Detail: strings.Repeat("private", 10000)}}}
	tx.state.Evidence["scan-source"] = domain.EvidenceItem{ID: "scan-source", TenantID: "tenant", ProductID: "tenant-product", ReleaseID: "tenant-release", Type: "vulnerability_scan"}
	tx.state.VulnerabilityScans["scan"] = domain.VulnerabilityScan{ID: "scan", TenantID: "tenant", ReleaseID: "tenant-release", EvidenceID: "scan-source", Findings: []domain.VulnerabilityFinding{{ID: "finding", Vulnerability: "CVE-fixture", Component: "component", Severity: "critical", State: "open"}}}
	r, ok := tx.Repositories().Future.(memoryAnomalyPorts)
	if !ok {
		t.Fatal("memory future repository lacks native anomaly ports")
	}
	return tx, r
}

func TestMemoryAnomalyFactsUseCoherentSourcesAndBoundedProjection(t *testing.T) {
	tx, r := memoryAnomalyFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	want := experimentalapp.AnomalyReleaseFacts{TenantID: "tenant", ReleaseID: "tenant-release", HasPassedBuild: true, HasVerifiedBuildAttestation: true, UnhandledCritical: true}
	got, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "tenant-release", fixedNow())
	if err != nil || got != want {
		t.Fatal("native facts lost exact recorded trust predicates", got, err)
	}
	for _, root := range []struct{ kind, id string }{{"tenant", "tenant"}, {"product", "tenant-product"}, {"release", "tenant-release"}, {"evidence", "tenant-evidence"}, {"build", "build"}, {"customer_package", "tenant-package"}} {
		s, err := r.ReadAnomalyScope(t.Context(), "tenant", root.kind, root.id)
		if err != nil || s.TenantID != "tenant" || s.SubjectType != root.kind || s.SubjectID != root.id {
			t.Fatal("anomaly scope lost owned coordinates", s, err)
		}
	}
	scope, err := r.ReadAnomalyScope(t.Context(), "tenant", "release", "tenant-release")
	if err != nil || scope.Resources != (application.ResourceReferences{ProductID: "tenant-product", ReleaseID: "tenant-release"}) {
		t.Fatal("release scope lost current parent", scope, err)
	}
	for _, foreign := range []struct{ kind, id string }{{"tenant", "foreign"}, {"product", "foreign-product"}, {"release", "foreign-release"}, {"evidence", "foreign-evidence"}, {"customer_package", "foreign-package"}} {
		if _, err := r.ReadAnomalyScope(t.Context(), "tenant", foreign.kind, foreign.id); !errors.Is(err, ErrNotFound) {
			t.Fatal("anomaly scope crossed tenant", foreign, err)
		}
	}
	if got, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "foreign-release", fixedNow()); !errors.Is(err, ErrNotFound) || got != (experimentalapp.AnomalyReleaseFacts{}) {
		t.Fatal("foreign facts escaped", got, err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("anomaly reads mutated evidence or audit state")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadAnomalyReleaseFacts(ctx, "tenant", "tenant-release", fixedNow()); !errors.Is(err, context.Canceled) {
		t.Fatal("facts ignored cancellation", err)
	}
	if _, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "tenant-release", time.Time{}); !errors.Is(err, ErrValidation) {
		t.Fatal("facts accepted zero clock", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadAnomalyScope(t.Context(), "tenant", "tenant", "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("scope used closed transaction", err)
	}
}

func TestMemoryAnomalyFactsRejectFalseTrustAndForeignHandling(t *testing.T) {
	cases := []struct {
		name                         string
		edit                         func(*MemoryUnitOfWorkSnapshot)
		build, attestation, critical bool
		invalid                      bool
	}{
		{"unregistered artifact", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Artifacts, "artifact") }, false, false, true, false},
		{"foreign artifact", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Artifacts["artifact"]
			v.TenantID = "foreign"
			s.Artifacts[v.ID] = v
		}, false, false, true, false},
		{"opaque digest only", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.SubjectRefs[0].ID = "missing"
			v.SubjectRefs[0].Digest = s.Artifacts["artifact"].Digest
			s.Evidence[v.ID] = v
		}, false, false, true, false},
		{"foreign evidence parent", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["tenant-evidence"]
			v.ProjectID = "foreign-project"
			s.Evidence[v.ID] = v
		}, false, false, true, false},
		{"foreign build project", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["build"]
			v.ProjectID = "foreign-project"
			s.BuildRuns[v.ID] = v
		}, false, false, true, false},
		{"foreign collector", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["build"]
			v.CollectorID = "foreign-collector"
			s.Collectors["foreign-collector"] = domain.Collector{ID: "foreign-collector", TenantID: "foreign"}
			s.BuildRuns[v.ID] = v
		}, false, false, true, false},
		{"wrong output binding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["build"]
			v.Outputs[0].ArtifactID = "missing"
			s.BuildRuns[v.ID] = v
		}, false, false, true, false},
		{"too many outputs", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["build"]
			v.Outputs = make([]domain.BuildOutput, 4097)
			s.BuildRuns[v.ID] = v
		}, false, false, true, false},
		{"failed build independent receipt", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildRuns["build"]
			v.Status = "failed"
			s.BuildRuns[v.ID] = v
		}, false, true, true, false},
		{"wrong attestation payload", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.BuildAttestations["attestation"]
			v.PayloadSize++
			s.BuildAttestations[v.ID] = v
		}, true, false, true, false},
		{"missing attestation source", func(s *MemoryUnitOfWorkSnapshot) { delete(s.Evidence, "attestation-source") }, true, false, true, false},
		{"wrong attestation source kind", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["attestation-source"]
			v.Type = "build"
			s.Evidence[v.ID] = v
		}, true, false, true, false},
		{"wrong attestation source build", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["attestation-source"]
			v.BuildID = "missing"
			s.Evidence[v.ID] = v
		}, true, false, true, false},
		{"foreign receipt", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VerificationResults["receipt"]
			v.TenantID = "foreign"
			s.VerificationResults[v.ID] = v
		}, true, false, true, false},
		{"wrong receipt profile", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VerificationResults["receipt"]
			v.Profile.ID = "metadata-only"
			s.VerificationResults[v.ID] = v
		}, true, false, true, false},
		{"wrong receipt schema", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VerificationResults["receipt"]
			v.SchemaVersion = "old"
			s.VerificationResults[v.ID] = v
		}, true, false, true, false},
		{"failed receipt", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VerificationResults["receipt"]
			v.Result = "failed"
			s.VerificationResults[v.ID] = v
		}, true, false, true, false},
		{"scan foreign source", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["scan-source"]
			v.TenantID = "foreign"
			s.Evidence[v.ID] = v
		}, true, true, false, false},
		{"scan wrong source type", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Evidence["scan-source"]
			v.Type = "build"
			s.Evidence[v.ID] = v
		}, true, true, false, false},
		{"malformed selected finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["scan"]
			v.Findings[0].ID = ""
			s.VulnerabilityScans[v.ID] = v
		}, false, false, false, true},
		{"closed finding", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["scan"]
			v.Findings[0].State = "fixed"
			s.VulnerabilityScans[v.ID] = v
		}, true, true, false, false},
		{"high only", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["scan"]
			v.Findings[0].Severity = "high"
			s.VulnerabilityScans[v.ID] = v
		}, true, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, r := memoryAnomalyFixture(t)
			tc.edit(&tx.state)
			got, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "tenant-release", fixedNow())
			if tc.invalid {
				if !errors.Is(err, ErrValidation) || got != (experimentalapp.AnomalyReleaseFacts{}) {
					t.Fatal("invalid selected facts escaped", got, err)
				}
				return
			}
			want := experimentalapp.AnomalyReleaseFacts{TenantID: "tenant", ReleaseID: "tenant-release", HasPassedBuild: tc.build, HasVerifiedBuildAttestation: tc.attestation, UnhandledCritical: tc.critical}
			if err != nil || got != want {
				t.Fatal("incoherent or foreign metadata granted trust", got, want, err)
			}
		})
	}
}

func TestMemoryAnomalyCriticalHandlingBindsDecisionIdentityAndCurrentExceptions(t *testing.T) {
	cases := []struct {
		name    string
		edit    func(*MemoryUnitOfWorkSnapshot)
		handled bool
	}{
		{"exact active decision", func(s *MemoryUnitOfWorkSnapshot) {}, true},
		{"foreign decision", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.TenantID = "foreign"
			s.Decisions[v.ID] = v
		}, false},
		{"wrong scan", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.ScanID = "missing"
			s.Decisions[v.ID] = v
		}, false},
		{"wrong vulnerability", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.Vulnerability = "CVE-other"
			s.Decisions[v.ID] = v
		}, false},
		{"wrong component", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.Component = "other"
			s.Decisions[v.ID] = v
		}, false},
		{"superseded decision", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.SupersededBy = "new"
			s.Decisions[v.ID] = v
		}, false},
		{"open decision", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Decisions["decision"]
			v.Status = "affected"
			s.Decisions[v.ID] = v
		}, false},
		{"ambiguous finding id", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.VulnerabilityScans["scan"]
			v.Findings = append(v.Findings, v.Findings[0])
			s.VulnerabilityScans[v.ID] = v
		}, false},
		{"approved finding exception", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Decisions, "decision")
			s.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", FindingID: "finding", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
		}, true},
		{"approved release exception", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Decisions, "decision")
			s.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
		}, true},
		{"expired exception", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Decisions, "decision")
			s.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", Approved: true, ExpiresAt: fixedNow()}
		}, false},
		{"foreign control exception", func(s *MemoryUnitOfWorkSnapshot) {
			delete(s.Decisions, "decision")
			s.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", ControlID: "foreign-control", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, r := memoryAnomalyFixture(t)
			tx.state.Decisions["decision"] = domain.VulnerabilityDecision{ID: "decision", TenantID: "tenant", ReleaseID: "tenant-release", ScanID: "scan", FindingID: "finding", Vulnerability: "CVE-fixture", Component: "component", Status: "not_affected", InternalNotes: strings.Repeat("private", 10000)}
			tc.edit(&tx.state)
			got, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "tenant-release", fixedNow())
			if err != nil || got.UnhandledCritical == tc.handled {
				t.Fatal("critical handling lost scope/identity/expiry", got, err)
			}
		})
	}
}

func TestMemoryFocusedAnomalyInsertKeepsCompleteDetachedReport(t *testing.T) {
	tx, r := memoryAnomalyFixture(t)
	facts := experimentalapp.AnomalyReleaseFacts{TenantID: "tenant", ReleaseID: "tenant-release", UnhandledCritical: true}
	v := experimentalapp.BuildAnomalyReport("anomaly", "tenant", experimentalapp.AnomalyReportInput{SubjectType: "release", SubjectID: "tenant-release"}, fixedNow(), facts)
	if err := r.InsertFocusedAnomalyReport(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	expected := domain.AnomalyReport{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Result: v.Result, Signals: []domain.AnomalySignal{}, Assumptions: v.Assumptions, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
	for _, signal := range v.Signals {
		expected.Signals = append(expected.Signals, domain.AnomalySignal{Name: signal.Name, Severity: signal.Severity, Detail: signal.Detail})
	}
	if !reflect.DeepEqual(tx.state.AnomalyReports[v.ID], expected) {
		t.Fatal("anomaly mapper lost record fields")
	}
	v.Signals[0].Detail, v.Assumptions[0], v.Limitations[0] = "mutated", "mutated", "mutated"
	if tx.state.AnomalyReports[v.ID].Signals[0].Detail == "mutated" || tx.state.AnomalyReports[v.ID].Assumptions[0] == "mutated" || tx.state.AnomalyReports[v.ID].Limitations[0] == "mutated" {
		t.Fatal("anomaly mapper aliased caller metadata")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v.ID, v.SubjectID = "foreign-root", "foreign-release"
	if err := r.InsertFocusedAnomalyReport(t.Context(), v); !errors.Is(err, ErrNotFound) {
		t.Fatal("anomaly insert accepted foreign root", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("failed insert published a report")
	}
}

func TestMemoryAnomalyClearReportPreservesEmptySignalsAcrossTransactions(t *testing.T) {
	factory, tx := memoryQuestionnaireFixture(t)
	r := tx.Repositories().Future.(memoryAnomalyPorts)
	v := experimentalapp.BuildAnomalyReport("clear", "tenant", experimentalapp.AnomalyReportInput{SubjectType: "product", SubjectID: "tenant-product"}, fixedNow(), experimentalapp.AnomalyReleaseFacts{})
	if err := r.InsertFocusedAnomalyReport(t.Context(), v); err != nil {
		t.Fatal("empty clear report was rejected", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	saved, err := factory.Snapshot()
	if err != nil || saved.AnomalyReports[v.ID].Signals == nil || len(saved.AnomalyReports[v.ID].Signals) != 0 {
		t.Fatal("snapshot collapsed empty signal list", err)
	}
	next, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := next.Rollback(t.Context()); err != nil {
			t.Error(err)
		}
	}()
	w := next.Repositories().Future.(memoryAnomalyPorts)
	v.ID, v.Signals = "invalid-nil", nil
	if err := w.InsertFocusedAnomalyReport(t.Context(), v); !errors.Is(err, ErrValidation) {
		t.Fatal("nil signals bypassed report invariant", err)
	}
}

func TestMemoryAnomalyForeignRowsCannotGrantBuildAttestationOrExceptionTrust(t *testing.T) {
	for _, kind := range []string{"build", "attestation", "exception", "control-framework", "owned-control-exception"} {
		t.Run(kind, func(t *testing.T) {
			tx, r := memoryAnomalyFixture(t)
			want := experimentalapp.AnomalyReleaseFacts{TenantID: "tenant", ReleaseID: "tenant-release", HasPassedBuild: true, HasVerifiedBuildAttestation: true, UnhandledCritical: true}
			switch kind {
			case "build":
				v := tx.state.BuildRuns["build"]
				v.TenantID = "foreign"
				tx.state.BuildRuns[v.ID] = v
				want.HasPassedBuild, want.HasVerifiedBuildAttestation = false, false
			case "attestation":
				v := tx.state.BuildAttestations["attestation"]
				v.TenantID = "foreign"
				tx.state.BuildAttestations[v.ID] = v
				want.HasVerifiedBuildAttestation = false
			case "exception":
				tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "foreign", ReleaseID: "tenant-release", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
			case "control-framework", "owned-control-exception":
				tx.state.Exceptions["exception"] = domain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "tenant-release", ControlID: "tenant-control", Approved: true, ExpiresAt: fixedNow().Add(time.Hour)}
				if kind == "control-framework" {
					v := tx.state.SecurityControls["tenant-control"]
					v.FrameworkID = "foreign-framework"
					tx.state.SecurityControls[v.ID] = v
				} else {
					want.UnhandledCritical = false
				}
			}
			got, err := r.ReadAnomalyReleaseFacts(t.Context(), "tenant", "tenant-release", fixedNow())
			if err != nil || got != want {
				t.Fatal("foreign row or parent granted recorded trust", got, want, err)
			}
		})
	}
}

package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type packageObserverFixture struct {
	events []telemetry.Event
	active int
}

type measurementPackageSigner func(context.Context, PackageSigningRequest) (PackageSignature, error)

func (s measurementPackageSigner) SignPackage(ctx context.Context, request PackageSigningRequest) (PackageSignature, error) {
	return s(ctx, request)
}

func TestBundleMeasurementsSeparateSigningFromCommittedGeneration(t *testing.T) {
	for _, kind := range []string{"release", "evidence"} {
		for _, phase := range []string{"success", "commit", "signer"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				state := newPackageTestState()
				state.releaseBundleSnapshot = ReleaseBundleSnapshot{SnapshotVersion: ReleaseBundleSnapshotVersion, TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", ReleaseVersion: "1", ReleaseState: "draft", EvidenceIDs: []string{"ev_1"}, ChainSequence: 3, ChainHeadHash: "PRIVATE_HASH"}
				state.evidenceBundleSnapshot = EvidenceBundleSnapshot{SnapshotVersion: EvidenceBundleSnapshotVersion, TenantID: "ten_1", Evidence: []EvidenceBundleEvidence{{ID: "ev_1", Resources: application.ResourceReferences{ProductID: "prod_1"}}}, AuditChainHead: "PRIVATE_HASH"}
				local := newPackageTestService(t, state)
				signer := local.signer
				if phase == "signer" {
					signer = measurementPackageSigner(func(context.Context, PackageSigningRequest) (PackageSignature, error) {
						return PackageSignature{}, errPackageTestFailure
					})
				}
				if phase == "commit" {
					state.auditErr = errPackageTestFailure
				}
				o := &packageObserverFixture{}
				ctx := telemetry.WithObserver(t.Context(), o)
				var err error
				if kind == "release" {
					var c *ReleaseBundleCommands
					c, err = NewReleaseBundleCommands(ReleaseBundleCommandConfig{Reader: serviceReleaseBundleReader{local}, Transactions: serviceReleaseBundleTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Signer: signer, Clock: local.clock, IDs: local.ids})
					if err == nil {
						_, err = c.CreateReleaseBundle(ctx, packageTestActor(), "rel_1")
					}
				} else {
					var c *ExportCommands
					c, err = NewExportCommands(ExportCommandConfig{Reader: serviceExportReader{local}, Transactions: serviceExportTransactions{state}, Authorizer: local.authorizer, Hasher: local.canonicalizer, Signer: signer, Clock: local.clock, IDs: local.ids})
					if err == nil {
						_, err = c.ExportEvidenceBundle(ctx, packageTestActor(), "", []string{"ev_1"})
					}
				}
				if (err == nil) != (phase == "success") {
					t.Fatal("bundle acceptance changed", err)
				}
				if phase != "success" && len(state.releaseBundles)+len(state.evidenceBundles)+len(state.audit)+len(state.signatures) != 0 {
					t.Fatal("failed bundle generation published effects")
				}
				found := map[telemetry.Operation]telemetry.Event{}
				for _, event := range o.events {
					found[event.Operation] = event
				}
				signingOutcome := telemetry.OutcomeSucceeded
				if phase == "signer" {
					signingOutcome = telemetry.OutcomeFailed
				}
				if len(o.events) != 2 || found[telemetry.OperationPackageSign].Outcome != signingOutcome || found[telemetry.OperationPackageGeneration].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
					t.Fatal("signer result and committed bundle outcome were conflated", o.events)
				}
				encoded, _ := json.Marshal(o.events)
				if strings.Contains(string(encoded), "PRIVATE") {
					t.Fatal("bundle metrics disclosed manifest or signing material")
				}
			})
		}
	}
}

func (f *packageObserverFixture) Observe(_ context.Context, event telemetry.Event) {
	f.events = append(f.events, event)
}
func (f *packageObserverFixture) Begin(telemetry.Operation) func() {
	f.active++
	return func() { f.active-- }
}

func TestPackageGenerationMeasurementPreservesRedactionHashAndRollback(t *testing.T) {
	for _, failure := range []bool{false, true} {
		s, f, in := customerCreationFixture(t)
		if failure {
			f.commitErr = errors.New("PRIVATE_COMMIT_ERROR")
		}
		o := &packageObserverFixture{}
		ctx := telemetry.WithObserver(t.Context(), o)
		pkg, err := s.CreateCustomerSecurityPackage(ctx, packageTestActor(), in)
		if (err != nil) != failure {
			t.Fatal("package generation acceptance changed", err)
		}
		if !failure {
			assertNoSensitivePackageKeys(t, pkg.Manifest)
			if pkg.ManifestHash == "" || len(f.packages) != 1 {
				t.Fatal("generated package was not hashed and committed")
			}
		}
		if failure && (pkg.ID != "" || len(f.packages)+len(f.audit) != 0) {
			t.Fatal("measured failed generation published package/audit")
		}
		if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationPackageGeneration || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
			t.Fatal("package measurement lost actual committed outcome", o.events)
		}
		encoded, _ := json.Marshal(o.events)
		if strings.Contains(string(encoded), "PRIVATE") {
			t.Fatal("package measurement disclosed customer/commit details")
		}
	}
}

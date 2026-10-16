package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type verificationObserverFixture struct {
	events []telemetry.Event
	active int
}

func (f *verificationObserverFixture) Observe(_ context.Context, event telemetry.Event) {
	f.events = append(f.events, event)
}
func (f *verificationObserverFixture) Begin(telemetry.Operation) func() {
	f.active++
	return func() { f.active-- }
}

func TestSigningMeasurementPreservesCommittedAndFailedReceipts(t *testing.T) {
	for _, phase := range []string{"", "commit", "signer"} {
		c, f, actor, in := signingOperationCommandFixture(t)
		f.phase = phase
		o := &verificationObserverFixture{}
		ctx := telemetry.WithObserver(t.Context(), o)
		result, err := c.CreateSigningOperation(ctx, actor, in)
		if (err == nil) != (phase == "") {
			t.Fatal("signing result changed", phase, err)
		}
		if phase == "" && result.ID == "" {
			t.Fatal("successful signing receipt missing")
		}
		if phase != "" && (result.ID != "" || len(f.records)+len(f.audits) != 0) {
			t.Fatal("measurement published rolled-back signing effects")
		}
		if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationSigning || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
			t.Fatal("signing observation changed its actual outcome", o.events)
		}
	}
}

func TestVerificationMeasurementPreservesVerdictsAndCommitFailures(t *testing.T) {
	for _, phase := range []string{"", "commit", "mismatch"} {
		c, f := evidenceVerificationFixture(t)
		if phase == "commit" {
			f.fail = phase
		}
		if phase == "mismatch" {
			f.snapshot.Item.CanonicalHash = "PRIVATE_INVALID_HASH"
		}
		o := &verificationObserverFixture{}
		ctx := telemetry.WithObserver(t.Context(), o)
		result, err := c.VerifyEvidence(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "evidence")
		if phase == "" && (err != nil || result.Result.String() != "passed") {
			t.Fatal("verification success changed", err)
		}
		if phase == "commit" && (!errors.Is(err, errVerificationTestFailure) || len(f.results)+len(f.audits)+len(f.jobs) != 0) {
			t.Fatal("verification commit failure published effects", err)
		}
		if phase == "mismatch" && (!errors.Is(err, ErrVerificationFailed) || result.Result.String() != "failed") {
			t.Fatal("verification mismatch verdict changed", err)
		}
		if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationVerification || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
			t.Fatal("verification observation lost error/verdict outcome", o.events)
		}
		encoded, _ := json.Marshal(o.events)
		if strings.Contains(string(encoded), "PRIVATE") {
			t.Fatal("verification metric disclosed hashes or detail")
		}
	}
}

func TestMerkleSigningMeasurementIncludesCommitOutcome(t *testing.T) {
	for _, phase := range []string{"", "commit", "sign"} {
		c, f := merkleCreationFixture(t)
		f.fail = phase
		o := &verificationObserverFixture{}
		result, err := c.CreateMerkleBatch(telemetry.WithObserver(t.Context(), o), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{})
		if (err == nil) != (phase == "") || f.signs != 1 {
			t.Fatal("Merkle signing behavior changed", err)
		}
		if phase != "" && (result.ID != "" || len(f.sigs)+len(f.batches)+len(f.audits) != 0) {
			t.Fatal("failed Merkle signing published effects")
		}
		if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationSigning || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
			t.Fatal("Merkle signing lost its committed outcome", o.events)
		}
	}
}

func TestVerificationMeasurementPreservesLimitedAssuranceAndDispatchCounts(t *testing.T) {
	c, _ := signatureMetadataFixture(t)
	o := &verificationObserverFixture{}
	ctx := telemetry.WithObserver(t.Context(), o)
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	r, err := c.VerifyArtifactSignature(ctx, actor, "signature")
	if err != nil || r.Result.String() != "limited" || len(o.events) != 1 || o.events[0].Outcome != telemetry.OutcomeSucceeded || o.active != 0 {
		t.Fatal("operational completion changed limited assurance", r, err, o.events)
	}
	dispatch, _ := subjectDispatchFixture(t)
	evidence, _ := evidenceVerificationFixture(t)
	dispatch.config.Evidence = evidence
	o.events = nil
	r, err = dispatch.VerifySubject(ctx, actor, "evidence_item", "evidence")
	if err != nil || r.Result.String() != "passed" || len(o.events) != 1 || o.events[0].Operation != telemetry.OperationVerification || o.active != 0 {
		t.Fatal("dispatch duplicated or changed actual verification", err, o.events)
	}
}

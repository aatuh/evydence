package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestAuditNativeFixtureUsesCurrentCanonicalPagesWithoutAggregateClockAndCommitsAtomically(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	batch, err := createMerkleBatchFixture(t.Context(), ledger, owner.actor, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := createReleaseBundleFixture(t.Context(), ledger, owner.actor, owner.release.ID, owner.release.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	failure := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture", UnitOfWork: failure, Now: func() time.Time { panic("audit verification used aggregate clock") }})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	for _, tc := range []struct{ kind, id string }{{"audit_chain", ""}, {"audit_chain_checkpoint", batch.ID}, {"audit_chain_release_manifest", bundle.ID}} {
		before, err := base.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if tc.id != "" {
			if v, err := f.VerifySubject(t.Context(), foreign.actor, tc.kind, tc.id); !errors.Is(err, app.ErrNotFound) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
				t.Fatal("foreign audit checkpoint exposed", tc.kind, err)
			}
		}
		v, err := f.VerifySubject(t.Context(), owner.actor, tc.kind, tc.id)
		if err != nil || v.ID == "" || v.Result.String() != "passed" || v.SubjectType != tc.kind || v.SubjectID != tc.id || v.Profile.TransparencyProof != "not_evaluated" {
			t.Fatal("current audit profile verification failed", tc.kind, v, err)
		}
		after, err := base.Snapshot()
		if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
			t.Fatal("audit verification receipt/audit/job not atomic", err)
		}
		failure.failAt = failure.begins + 1
		if v, err := f.VerifySubject(t.Context(), owner.actor, tc.kind, tc.id); err == nil || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) || failure.begins != failure.failAt {
			t.Fatal("audit commit failure not exercised or exposed receipt", tc.kind, err)
		}
		failed, err := base.Snapshot()
		if err != nil || !reflect.DeepEqual(after, failed) {
			t.Fatal("audit commit failure published partial effects", err)
		}
		failure.failAt = 0
	}
	human := owner.actor
	human.KeyID, human.UserID = "", "human"
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"verify:read"}}}
	if err := f.AuthorizeSubjectVerification(t.Context(), human, "audit_chain_release_manifest", bundle.ID); !errors.Is(err, app.ErrForbidden) {
		t.Fatal("release grant became tenant-wide chain access", err)
	}
	if v, err := f.VerifySubject(t.Context(), human, "audit_chain_release_manifest", bundle.ID); !errors.Is(err, app.ErrForbidden) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
		t.Fatal("release grant allowed full-chain content read", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := f.VerifySubject(ctx, owner.actor, "audit_chain", ""); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) {
		t.Fatal("cancelled audit returned receipt", err)
	}
}

func TestAuditNativeFixtureHTTPReplayRechecksGrantsAndFailedPOSTRollsBack(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	batch, err := createMerkleBatchFixture(t.Context(), ledger, owner.actor, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := createReleaseBundleFixture(t.Context(), ledger, owner.actor, owner.release.ID, owner.release.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := owner.actor
	human.KeyID, human.UserID = "", "human"
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"verify:read"}}}
	auth := &configuredAuthenticator{actor: human}
	s.authn = auth
	const secret = "fixture-authentication"
	for _, tc := range []struct{ kind, id string }{{"audit_chain", ""}, {"audit_chain_checkpoint", batch.ID}, {"audit_chain_release_manifest", bundle.ID}} {
		body := fmt.Sprintf(`{"subject_type":%q,"subject_id":%q}`, tc.kind, tc.id)
		one := postRaw(t, s, secret, "/v1/verify", tc.kind, []byte(body), 200)
		if !strings.Contains(one, `"result":"passed"`) || !strings.Contains(one, `"transparency_proof":"not_evaluated"`) {
			t.Fatal("audit HTTP assurance profile changed", tc.kind)
		}
		before, err := base.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, one, postRaw(t, s, secret, "/v1/verify", tc.kind, []byte(body), 200))
		after, err := base.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("audit replay repeated receipt/audit/job", err)
		}
		auth.actor.ResourceGrants = nil
		postRaw(t, s, secret, "/v1/verify", tc.kind, []byte(body), 403)
		after, err = base.Snapshot()
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("removed audit grant left effects", err)
		}
		auth.actor = human
	}
	// Canonical integrity is not a substitute for referenced-signature trust.
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		_, err := r.Audit.Append(ctx, domain.AuditChainEntry{ID: "missing-signature-entry", TenantID: human.TenantID, EntryType: "recorded", SubjectType: "merkle_batch", SubjectID: batch.ID, ActorType: "api_key", ActorID: owner.actor.KeyID, OccurredAt: time.Now().UTC(), SignatureRef: "missing-signature", Metadata: map[string]any{"private": "private-audit-marker"}, SchemaVersion: domain.AuditChainEntrySchemaVersion})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	beforeGET, err := base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	get := getJSON(t, s, secret, "/v1/audit-chain/verify", 200)
	if !strings.Contains(get, `"result":"failed"`) || strings.Contains(get, "private-audit-marker") {
		t.Fatal("failed audit GET lost negative receipt or leaked metadata")
	}
	beforePOST, err := base.Snapshot()
	if err != nil || len(beforePOST.VerificationResults) != len(beforeGET.VerificationResults)+1 || len(beforePOST.OutboxJobs) != len(beforeGET.OutboxJobs)+1 || len(beforePOST.AuditEntries[human.TenantID]) != len(beforeGET.AuditEntries[human.TenantID])+1 {
		t.Fatal("failed audit GET did not commit receipt/audit/job", err)
	}
	postRaw(t, s, secret, "/v1/verify", "failed-audit-chain", []byte(`{"subject_type":"audit_chain"}`), 422)
	afterPOST, err := base.Snapshot()
	if err != nil || len(afterPOST.Idempotency) != len(beforePOST.Idempotency)+1 {
		t.Fatal("failed audit POST lost failed reservation", err)
	}
	for key, record := range afterPOST.Idempotency {
		if _, existed := beforePOST.Idempotency[key]; !existed && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
			t.Fatal("failed audit POST retained partial success response")
		}
	}
	afterPOST.Idempotency = beforePOST.Idempotency
	if !reflect.DeepEqual(beforePOST, afterPOST) {
		t.Fatal("failed audit POST published receipt/audit/job effects")
	}
}

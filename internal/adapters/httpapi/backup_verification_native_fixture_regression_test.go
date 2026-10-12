package httpapi

import (
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

func TestBackupVerificationNativeFixtureHTTPReplayRechecksGrantsAndNegativePOSTRollsBack(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	positive := seedBackupVerificationFixture(t, factory, owner.actor.TenantID, "positive-backup", "passed")
	negative := seedBackupVerificationFixture(t, factory, owner.actor.TenantID, "negative-backup", "failed")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	a := owner.actor
	a.KeyID, a.UserID = "", "human"
	a.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"verify:read"}}}
	auth := &configuredAuthenticator{actor: a}
	server.authn = auth
	body := fmt.Sprintf(`{"subject_type":"backup_manifest","subject_id":%q}`, positive.ID)
	one := postRaw(t, server, owner.secret, "/v1/verify", "positive-replay", []byte(body), 200)
	if !strings.Contains(one, `"result":"passed"`) {
		t.Fatal("focused backup POST did not return a passed recorded-check receipt")
	}
	beforeReplay, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, one, postRaw(t, server, owner.secret, "/v1/verify", "positive-replay", []byte(body), 200))
	afterReplay, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(beforeReplay, afterReplay) {
		t.Fatal("backup replay repeated receipt, audit or job effects", err)
	}
	auth.actor.ResourceGrants = nil
	postRaw(t, server, owner.secret, "/v1/verify", "positive-replay", []byte(body), 403)
	afterDenied, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(beforeReplay, afterDenied) {
		t.Fatal("removed tenant grant left replay effects", err)
	}
	auth.actor = a
	get := getJSON(t, server, owner.secret, "/v1/backup-manifests/"+negative.ID+"/verify", 200)
	if !strings.Contains(get, `"result":"failed"`) {
		t.Fatal("dedicated backup GET lost negative checks")
	}
	beforeFailedPOST, err := factory.Snapshot()
	if err != nil || len(beforeFailedPOST.VerificationResults) != len(beforeReplay.VerificationResults)+1 || len(beforeFailedPOST.OutboxJobs) != len(beforeReplay.OutboxJobs)+1 || len(beforeFailedPOST.AuditEntries[a.TenantID]) != len(beforeReplay.AuditEntries[a.TenantID])+1 {
		t.Fatal("dedicated failed GET did not persist receipt/audit/job", err)
	}
	body = fmt.Sprintf(`{"subject_type":"backup_manifest","subject_id":%q}`, negative.ID)
	postRaw(t, server, owner.secret, "/v1/verify", "negative-rollback", []byte(body), 422)
	afterFailedPOST, err := factory.Snapshot()
	if err != nil || len(afterFailedPOST.Idempotency) != len(beforeFailedPOST.Idempotency)+1 {
		t.Fatal("failed generic POST did not record its failed reservation", err)
	}
	for key, receipt := range afterFailedPOST.Idempotency {
		if _, existed := beforeFailedPOST.Idempotency[key]; !existed && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
			t.Fatal("failed backup POST retained a partial success response")
		}
	}
	afterFailedPOST.Idempotency = beforeFailedPOST.Idempotency
	if !reflect.DeepEqual(beforeFailedPOST, afterFailedPOST) {
		t.Fatal("failed backup POST committed partial receipt, audit or job")
	}
}

func seedBackupVerificationFixture(t *testing.T, factory app.UnitOfWorkFactory, tenant, id, result string) domain.BackupManifest {
	t.Helper()
	tx, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	v := domain.BackupManifest{ID: id, TenantID: tenant, StateHash: "sha256:recorded", ResourceCounts: map[string]int{"evidence": 0}, ConsistencyChecks: []domain.VerifyCheck{{Name: "recorded_chain", Result: result, Detail: "recorded fact only"}}, SchemaVersion: domain.BackupManifestSchemaVersion, CreatedAt: time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC)}
	if err := tx.Repositories().Integrity.InsertBackupManifest(t.Context(), v); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBackupVerificationNativeFixtureReadsCurrentRecordedFactsWithoutAggregateCache(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	backup := seedBackupVerificationFixture(t, factory, owner.actor.TenantID, "backup", "passed")
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory, Now: func() time.Time { panic("backup verification used aggregate clock") }})
	f := verificationReadFixtureCommands{catalogFixtureCommands{ledger: rebound}}
	v, err := f.VerifyBackupManifest(t.Context(), owner.actor, backup.ID)
	if err != nil || v.ID == "" || v.Result.String() != "passed" || len(v.Checks) != 2 || v.Checks[0].Name != "recorded_chain" || v.Checks[1].Name != "backup_manifest_present" || v.Profile.PayloadDigest != backup.StateHash || v.Profile.TransparencyProof != "not_evaluated" || len(v.Profile.Limitations) == 0 {
		t.Fatal("focused backup verification lost recorded profile or overclaimed restore", err)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.VerificationResults) != len(before.VerificationResults)+1 || len(after.OutboxJobs) != len(before.OutboxJobs)+1 || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || !reflect.DeepEqual(before.BackupManifests, after.BackupManifests) {
		t.Fatal("backup verification did not atomically record receipt/audit/job only", err)
	}
}

func TestBackupVerificationNativeFixtureRetainsNegativeReceiptsAndCommitRollback(t *testing.T) {
	ledger, base := integrationRegressionLedger()
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	backup := seedBackupVerificationFixture(t, base, owner.actor.TenantID, "backup", "failed")
	factory := &bundleWriteFailureFactory{base: base}
	rebound := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "fixture", UnitOfWork: factory})
	f := verificationCommandFixture{catalogFixtureCommands: catalogFixtureCommands{ledger: rebound}}
	v, err := f.VerifySubject(t.Context(), owner.actor, "backup_manifest", backup.ID)
	if !errors.Is(err, app.ErrVerificationFailed) || v.Result.String() != "failed" || len(v.Checks) != 2 || v.Checks[0].Result != "failed" || v.Profile.TransparencyProof != "not_evaluated" {
		t.Fatal("negative recorded fact lost its receipt", err)
	}
	before, err := base.Snapshot()
	if err != nil || len(before.VerificationResults) != 1 {
		t.Fatal("negative receipt was not committed", err)
	}
	factory.failAt = factory.begins + 1
	if v, err := (verificationReadFixtureCommands{f.catalogFixtureCommands}).VerifyBackupManifest(t.Context(), owner.actor, backup.ID); err == nil || !reflect.DeepEqual(v, verificationdomain.VerificationResult{}) || factory.begins != factory.failAt {
		t.Fatal("backup verification commit failure not exercised or returned data", err)
	}
	after, err := base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed backup commit left receipt, audit or job", err)
	}
}

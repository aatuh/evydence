package httpapi

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func TestGovernanceNativeFixturesPreserveResourcesCompleteRowsAndOnlyIntendedEffects(t *testing.T) {
	for _, kind := range []string{"waiver-create", "waiver-approve", "exception-create", "exception-approve", "approval"} {
		t.Run(kind, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner := seedControlFixtureScope(t, ledger, "Owner")
			at, expires := owner.release.CreatedAt.Add(time.Hour), owner.release.CreatedAt.Add(3*time.Hour)
			waiver := domain.Waiver{ID: "seed-waiver", TenantID: owner.actor.TenantID, ScopeType: "release", ScopeID: owner.release.ID, Owner: "security", Risk: "low", Reason: "Seed", ExpiresAt: expires, SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: owner.release.CreatedAt}
			exception := domain.Exception{ID: "seed-exception", TenantID: owner.actor.TenantID, ReleaseID: owner.release.ID, Owner: "security", Reason: "Seed", ExpiresAt: expires, CreatedAt: owner.release.CreatedAt}
			if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
				if err := r.Governance.InsertWaiver(ctx, waiver); err != nil {
					return err
				}
				return r.Decisions.InsertException(ctx, exception)
			}); err != nil {
				t.Fatal(err)
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			clock := &evidenceFlowFixtureClock{at: at}
			idCalls := 0
			ids := application.IDGeneratorFunc(func(prefix string) string { idCalls++; return fmt.Sprintf("%s-native-%d", prefix, idCalls) })
			server.bindGovernanceFixtureResources(clock, ids)
			rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, Now: func() time.Time { panic("native governance consulted aggregate clock") }})
			server.bindLegacyLedgerFixture(rebound)
			human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "reviewer", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			var changedID, auditKind, subject string
			wantIDs := 2
			switch kind {
			case "waiver-create":
				v, callErr := server.waiverCommands.CreateWaiver(t.Context(), human, riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: owner.release.ID, Owner: " security ", Risk: " low ", Reason: " Reviewed ", ExpiresAt: expires, Supersedes: waiver.ID})
				got, err = v, callErr
				changedID, auditKind, subject = "wv-native-1", "waiver.created", "waiver"
				want = riskdomain.Waiver{ID: changedID, TenantID: human.TenantID, ScopeType: "release", ScopeID: owner.release.ID, Owner: "security", Risk: "low", Reason: "Reviewed", ExpiresAt: expires, Supersedes: waiver.ID, SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: at}
			case "waiver-approve":
				v, callErr := server.waiverCommands.ApproveWaiver(t.Context(), human, waiver.ID)
				got, err = v, callErr
				changedID, auditKind, subject, wantIDs = waiver.ID, "waiver.approved", "waiver", 1
				waiver.Approved, waiver.ApprovedBy, waiver.ApprovedAt = true, human.UserID, &at
				want = riskdomain.Waiver(waiver)
			case "exception-create":
				v, callErr := server.exceptionCommands.CreateException(t.Context(), human, riskapp.CreateExceptionInput{ReleaseID: owner.release.ID, Owner: " security ", Reason: " Reviewed ", ExpiresAt: expires})
				got, err = v, callErr
				changedID, auditKind, subject = "ex-native-1", "exception.created", "exception"
				want = riskdomain.Exception{ID: changedID, TenantID: human.TenantID, ReleaseID: owner.release.ID, Owner: "security", Reason: "Reviewed", ExpiresAt: expires, CreatedAt: at}
			case "exception-approve":
				v, callErr := server.exceptionCommands.ApproveException(t.Context(), human, exception.ID)
				got, err = v, callErr
				changedID, auditKind, subject, wantIDs = exception.ID, "exception.approved", "exception", 1
				exception.Approved, exception.ApprovedBy, exception.ApprovedAt = true, human.UserID, &at
				want = riskdomain.Exception(exception)
			case "approval":
				v, callErr := server.approvalCommands.CreateApprovalRecord(t.Context(), human, riskapp.CreateApprovalInput{SubjectType: "waiver", SubjectID: waiver.ID, Decision: "accepted", Reason: " Reviewed ", EvidenceID: owner.evidence.ID})
				got, err = v, callErr
				changedID, auditKind, subject = "apr-native-1", "approval.created", "approval"
				want = riskdomain.ApprovalRecord{ID: changedID, TenantID: human.TenantID, SubjectType: "waiver", SubjectID: waiver.ID, Decision: "accepted", Reason: "Reviewed", ApproverID: human.UserID, EvidenceID: owner.evidence.ID, SchemaVersion: riskdomain.ApprovalRecordSchemaVersion, CreatedAt: at}
			}
			if err != nil || !reflect.DeepEqual(got, want) || clock.calls != 1 || idCalls != wantIDs {
				t.Fatal("native governance lost complete DTO or explicit resources", got, want, err)
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			entries := after.AuditEntries[human.TenantID]
			if len(entries) != len(before.AuditEntries[human.TenantID])+1 {
				t.Fatal("governance did not append exactly one audit entry")
			}
			entry := entries[len(entries)-1]
			if entry.ID != fmt.Sprintf("ace-native-%d", wantIDs) || entry.EntryType != auditKind || entry.SubjectType != subject || entry.SubjectID != changedID || entry.ActorID != human.UserID || entry.ActorType != "human_user" || entry.PayloadHash != "" || !entry.OccurredAt.Equal(at) {
				t.Fatal("governance audit lost owned subject, actor or time", entry)
			}
			var persisted any
			switch kind {
			case "waiver-create":
				persisted = riskdomain.Waiver(after.Waivers[changedID])
				delete(after.Waivers, changedID)
				prior := after.Waivers[waiver.ID]
				if prior.SupersededBy != changedID {
					t.Fatal("waiver supersession was not recorded atomically")
				}
				prior.SupersededBy = ""
				after.Waivers[waiver.ID] = prior
			case "waiver-approve":
				persisted = riskdomain.Waiver(after.Waivers[changedID])
				after.Waivers[changedID] = before.Waivers[changedID]
			case "exception-create":
				persisted = riskdomain.Exception(after.Exceptions[changedID])
				delete(after.Exceptions, changedID)
			case "exception-approve":
				persisted = riskdomain.Exception(after.Exceptions[changedID])
				after.Exceptions[changedID] = before.Exceptions[changedID]
			case "approval":
				persisted = riskdomain.ApprovalRecord(after.Approvals[changedID])
				delete(after.Approvals, changedID)
			}
			if !reflect.DeepEqual(persisted, want) {
				t.Fatal("governance response and committed complete row diverged", persisted, want)
			}
			after.AuditEntries[human.TenantID] = before.AuditEntries[human.TenantID]
			if !reflect.DeepEqual(before, after) {
				t.Fatal("governance changed unrelated rows, enqueued work or implicitly approved a subject")
			}
		})
	}
}

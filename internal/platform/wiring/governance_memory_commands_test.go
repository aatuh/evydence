package wiring

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
)

func TestMemoryGovernanceCommandsUseRealCurrentAuthorityGuardsWithoutLedger(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	created := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	expired := created.AddDate(1, 0, 0)
	if err := app.ExecuteUnitOfWork(t.Context(), factory, func(ctx context.Context, repos app.Repositories) error {
		for _, tenant := range []string{"tenant", "foreign"} {
			if err := repos.Identity.InsertTenant(ctx, domain.Tenant{ID: tenant, Name: tenant, CreatedAt: created}); err != nil {
				return err
			}
			if err := repos.ReleaseCatalog.InsertProduct(ctx, domain.Product{ID: tenant + "-product", TenantID: tenant, Name: tenant, Slug: tenant, CreatedAt: created}); err != nil {
				return err
			}
			if err := repos.ReleaseCatalog.InsertRelease(ctx, domain.Release{ID: tenant + "-release", TenantID: tenant, ProductID: tenant + "-product", Version: "1.0.0", State: "draft", Revision: 1, CreatedAt: created}); err != nil {
				return err
			}
			// Historical records intentionally contain reasons beyond fresh
			// read budgets. Replay guards need coordinates, not reason bodies.
			if err := repos.Governance.InsertWaiver(ctx, domain.Waiver{ID: tenant + "-waiver", TenantID: tenant, ScopeType: "release", ScopeID: tenant + "-release", Owner: "security", Risk: "reviewed", Reason: strings.Repeat("r", 65537), ExpiresAt: expired, Approved: true, ApprovedBy: "historical", ApprovedAt: &created, SchemaVersion: domain.WaiverSchemaVersion, CreatedAt: created}); err != nil {
				return err
			}
			exception := domain.Exception{ID: tenant + "-exception", TenantID: tenant, ReleaseID: tenant + "-release", Reason: strings.Repeat("r", 65537), Owner: "security", ExpiresAt: expired, CreatedAt: created}
			if err := repos.Decisions.InsertException(ctx, exception); err != nil {
				return err
			}
			exception.Approved, exception.ApprovedBy, exception.ApprovedAt = true, "historical", &created
			if err := repos.Decisions.ApproveException(ctx, exception); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	waivers, err := BuildWaiverCommands(factory)
	if err != nil {
		t.Fatal(err)
	}
	exceptions, err := BuildExceptionCommands(factory)
	if err != nil {
		t.Fatal(err)
	}
	approvals, err := BuildApprovalCommands(factory)
	if err != nil {
		t.Fatal(err)
	}
	actor := domain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: "tenant-product", Scopes: []string{"*"}}}}
	checks := []struct {
		name string
		run  func(context.Context, domain.Actor, string) error
	}{
		{"waiver-create", func(ctx context.Context, actor domain.Actor, prefix string) error {
			return waivers.AuthorizeCreateWaiver(ctx, actor, riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: prefix + "-release", Owner: "security", Risk: "reviewed", Reason: "reviewed", ExpiresAt: expired})
		}},
		{"waiver-approve", func(ctx context.Context, actor domain.Actor, prefix string) error {
			return waivers.AuthorizeApproveWaiver(ctx, actor, prefix+"-waiver")
		}},
		{"exception-create", func(ctx context.Context, actor domain.Actor, prefix string) error {
			return exceptions.AuthorizeCreateException(ctx, actor, riskapp.CreateExceptionInput{ReleaseID: prefix + "-release", Owner: "security", Reason: "reviewed", ExpiresAt: expired})
		}},
		{"exception-approve", func(ctx context.Context, actor domain.Actor, prefix string) error {
			return exceptions.AuthorizeApproveException(ctx, actor, prefix+"-exception")
		}},
		{"approval", func(ctx context.Context, actor domain.Actor, prefix string) error {
			return approvals.AuthorizeApproval(ctx, actor, riskapp.CreateApprovalInput{SubjectType: "waiver", SubjectID: prefix + "-waiver", Decision: "accepted", Reason: "reviewed"})
		}},
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t.Context(), actor, "tenant"); err != nil {
				t.Fatal("real guard reapplied expiry/approval rules or rejected current ownership", err)
			}
			if err := tc.run(t.Context(), actor, "foreign"); !errors.Is(err, riskapp.ErrNotFound) {
				t.Fatal("real guard accepted foreign resource coordinates", err)
			}
			denied := actor
			denied.Scopes = []string{"evidence:read"}
			if err := tc.run(t.Context(), denied, "tenant"); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("real guard ignored effective write authority", err)
			}
			denied = actor
			denied.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "foreign-product", Scopes: []string{"*"}}}
			if err := tc.run(t.Context(), denied, "tenant"); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("real guard promoted a nonmatching human grant", err)
			}
			denied.ResourceGrants = nil
			if err := tc.run(t.Context(), denied, "tenant"); !errors.Is(err, application.ErrForbidden) {
				t.Fatal("removed resource authority remained usable", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.run(ctx, actor, "tenant"); !errors.Is(err, context.Canceled) {
				t.Fatal("real guard ignored request cancellation", err)
			}
		})
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("governance preflight wrote records, approvals, audits, jobs or replay state", err)
	}
	// The same focused services can perform real fresh mutations and audits;
	// they are not backed by guard-only placeholder transactions.
	future := time.Now().UTC().Add(time.Hour)
	waiver, err := waivers.CreateWaiver(t.Context(), actor, riskapp.CreateWaiverInput{ScopeType: "release", ScopeID: "tenant-release", Owner: "security", Risk: "reviewed", Reason: "fresh", ExpiresAt: future})
	if err != nil || waiver.ID == "" || waiver.TenantID != actor.TenantID {
		t.Fatal("focused waiver creation could not use the memory repository", err)
	}
	waiver, err = waivers.ApproveWaiver(t.Context(), actor, waiver.ID)
	if err != nil || !waiver.Approved || waiver.ApprovedBy != actor.UserID || waiver.ApprovedAt == nil {
		t.Fatal("focused waiver approval lost principal/lifecycle metadata", err)
	}
	exception, err := exceptions.CreateException(t.Context(), actor, riskapp.CreateExceptionInput{ReleaseID: "tenant-release", Owner: "security", Reason: "fresh", ExpiresAt: future})
	if err != nil || exception.ID == "" || exception.TenantID != actor.TenantID {
		t.Fatal("focused exception creation could not use the memory repository", err)
	}
	exception, err = exceptions.ApproveException(t.Context(), actor, exception.ID)
	if err != nil || !exception.Approved || exception.ApprovedBy != actor.UserID || exception.ApprovedAt == nil {
		t.Fatal("focused exception approval lost principal/lifecycle metadata", err)
	}
	approval, err := approvals.CreateApprovalRecord(t.Context(), actor, riskapp.CreateApprovalInput{SubjectType: "waiver", SubjectID: waiver.ID, Decision: "accepted", Reason: "fresh"})
	if err != nil || approval.ID == "" || approval.ApproverID != actor.UserID || approval.SubjectID != waiver.ID {
		t.Fatal("focused approval creation lost subject/principal metadata", err)
	}
	after, err = factory.Snapshot()
	if err != nil || len(after.Waivers) != len(before.Waivers)+1 || len(after.Exceptions) != len(before.Exceptions)+1 || len(after.Approvals) != len(before.Approvals)+1 || len(after.AuditEntries[actor.TenantID]) != 5 || len(after.Idempotency) != 0 || len(after.OutboxJobs) != 0 || !after.Waivers[waiver.ID].Approved || !after.Exceptions[exception.ID].Approved || after.Approvals[approval.ID].ApproverID != actor.UserID {
		t.Fatal("focused governance mutations lost atomic records or one audit per command", err)
	}
}

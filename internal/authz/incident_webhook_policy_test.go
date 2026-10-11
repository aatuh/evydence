package authz

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var signedWebhookCases = []Action{"incident_webhooks.record"}

func webhookPolicyFixture() (IncidentWebhookBinding, IncidentWebhookRequest) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	binding := IncidentWebhookBinding{TenantID: "tenant", ReceiverID: "receiver", IncidentID: "incident", Status: "active", Provider: "pager"}
	request := IncidentWebhookRequest{Action: ActionSignedIncidentWebhookRecord, Incident: IncidentWebhookSubject{ID: "incident", TenantID: "tenant", Kind: "incident", Resources: ResourceReferences{ProductID: "product", ReleaseID: "release"}}, Evidence: IncidentWebhookSubject{ID: "evidence", TenantID: "tenant", Kind: "evidence", Resources: ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", DeploymentID: "deployment"}}, Timestamp: now, Now: now}
	return binding, request
}

func TestSignedWebhookPolicyRequiresBoundActiveReceiverAndConcreteAction(t *testing.T) {
	binding, request := webhookPolicyFixture()
	beforeBinding, beforeRequest := binding, request
	if err := AuthorizeIncidentWebhook(t.Context(), binding, request); err != nil || binding != beforeBinding || request != beforeRequest {
		t.Fatal("valid signed receiver denied or inputs mutated", err)
	}
	for _, edit := range []func(*IncidentWebhookBinding){
		func(b *IncidentWebhookBinding) { b.TenantID = "" }, func(b *IncidentWebhookBinding) { b.ReceiverID = "" }, func(b *IncidentWebhookBinding) { b.IncidentID = "" },
		func(b *IncidentWebhookBinding) { b.Status = "revoked" }, func(b *IncidentWebhookBinding) { b.Status = " active " },
		func(b *IncidentWebhookBinding) { b.Provider = " " }, func(b *IncidentWebhookBinding) { b.Provider = "provider\x00" }, func(b *IncidentWebhookBinding) { b.Provider = strings.Repeat("x", 65537) },
	} {
		bad := binding
		edit(&bad)
		if err := CheckIncidentWebhookBinding(t.Context(), bad, binding.TenantID, binding.ReceiverID); !errors.Is(err, ErrNotFound) {
			t.Fatal("inactive or malformed receiver authority not hidden", err)
		}
	}
	for _, pair := range [][2]string{{"foreign", binding.ReceiverID}, {binding.TenantID, "foreign"}} {
		if err := CheckIncidentWebhookBinding(t.Context(), binding, pair[0], pair[1]); !errors.Is(err, ErrNotFound) {
			t.Fatal("receiver escaped routed tenant/identity", err)
		}
	}
	for _, action := range []Action{"unregistered", ActionIncidentsManage, ActionPortalPackagesRead, ActionInstanceSnapshotRead} {
		bad := request
		bad.Action = action
		if err := AuthorizeIncidentWebhook(t.Context(), binding, bad); !errors.Is(err, ErrForbidden) {
			t.Fatal("receiver promoted its action authority", action, err)
		}
	}
	for _, actor := range []identitydomain.Actor{{TenantID: "tenant", KeyID: "key", Scopes: []string{"*", "admin", "incident:write"}}, {TenantID: "tenant", KeyID: "key", CollectorID: "collector", Scopes: []string{"*"}}, {TenantID: "tenant", UserID: "user", Scopes: []string{"*"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"*"}}}}} {
		for _, phase := range []Evaluation{ResolvedEvaluation, ScopeEvaluation, TenantEvaluation} {
			if err := Authorize(t.Context(), actor, Request{Action: request.Action, Evaluation: phase}); !errors.Is(err, ErrForbidden) {
				t.Fatal("API actor minted signed receiver authority", phase, err)
			}
		}
	}
}

func TestSignedWebhookPolicyHidesForeignIncoherentAndExpandedSubjects(t *testing.T) {
	binding, request := webhookPolicyFixture()
	for _, edit := range []func(*IncidentWebhookRequest){
		func(r *IncidentWebhookRequest) { r.Incident.ID = "other" }, func(r *IncidentWebhookRequest) { r.Incident.TenantID = "foreign" }, func(r *IncidentWebhookRequest) { r.Incident.Kind = "product" },
		func(r *IncidentWebhookRequest) { r.Evidence.ID = "" }, func(r *IncidentWebhookRequest) { r.Evidence.TenantID = "foreign" }, func(r *IncidentWebhookRequest) { r.Evidence.Kind = "incident" },
		func(r *IncidentWebhookRequest) { r.Evidence.Resources.ProductID = "other" }, func(r *IncidentWebhookRequest) { r.Evidence.Resources.ReleaseID = "other" },
		func(r *IncidentWebhookRequest) { r.Incident.Resources.ProductID = "" }, func(r *IncidentWebhookRequest) { r.Evidence.Resources.ProjectID = " padded " },
	} {
		bad := request
		edit(&bad)
		if err := AuthorizeIncidentWebhook(t.Context(), binding, bad); !errors.Is(err, ErrNotFound) {
			t.Fatal("wrong incident/evidence ownership not hidden", err)
		}
	}
	for _, which := range []string{"incident", "evidence"} {
		for i := 0; i < reflect.TypeOf(request.Incident.Resources).NumField(); i++ {
			field := reflect.TypeOf(request.Incident.Resources).Field(i).Name
			if field == "ProductID" || field == "ReleaseID" || which == "evidence" && (field == "ProjectID" || field == "BuildID" || field == "DeploymentID") {
				continue // Permitted current coordinates are covered above.
			}
			bad := request
			refs := &bad.Incident.Resources
			if which == "evidence" {
				refs = &bad.Evidence.Resources
			}
			reflect.ValueOf(refs).Elem().Field(i).SetString("foreign")
			if err := AuthorizeIncidentWebhook(t.Context(), binding, bad); !errors.Is(err, ErrNotFound) {
				t.Fatal("signed receiver broadened its resource shape", which, field, err)
			}
		}
	}
	request.Evidence.Resources.ReleaseID = ""
	if err := AuthorizeIncidentWebhook(t.Context(), binding, request); err != nil {
		t.Fatal("product-wide evidence lost compatibility", err)
	}
	request.Evidence = IncidentWebhookSubject{}
	if err := AuthorizeIncidentWebhook(t.Context(), binding, request); err != nil {
		t.Fatal("optional evidence made mandatory", err)
	}
}

func TestSignedWebhookPolicyPreservesInclusiveWindowAndRejectsCanceledAuthority(t *testing.T) {
	binding, request := webhookPolicyFixture()
	for _, delta := range []time.Duration{-5 * time.Minute, 5 * time.Minute, -5*time.Minute - time.Nanosecond, 5*time.Minute + time.Nanosecond} {
		bad := request
		bad.Timestamp = request.Now.Add(delta)
		err := AuthorizeIncidentWebhook(t.Context(), binding, bad)
		if delta < -5*time.Minute || delta > 5*time.Minute {
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatal("expired/future signed timestamp allowed", delta, err)
			}
		} else if err != nil {
			t.Fatal("inclusive freshness boundary changed", delta, err)
		}
	}
	request.Timestamp = time.Time{}
	if err := AuthorizeIncidentWebhook(t.Context(), binding, request); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("missing signed time acquired authority", err)
	}
	binding, request = webhookPolicyFixture()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, check := range []func(context.Context) error{
		func(ctx context.Context) error {
			return CheckIncidentWebhookTimestamp(ctx, request.Timestamp, request.Now)
		},
		func(ctx context.Context) error {
			return CheckIncidentWebhookBinding(ctx, binding, binding.TenantID, binding.ReceiverID)
		},
		func(ctx context.Context) error { return AuthorizeIncidentWebhook(ctx, binding, request) },
	} {
		if err := check(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled receiver policy acquired authority", err)
		}
		var missing context.Context
		if err := check(missing); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("missing context acquired receiver authority", err)
		}
	}
}

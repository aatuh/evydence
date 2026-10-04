package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestLocalDSSEReplayGuardPreservesScopedGrantsWithoutInspection(t *testing.T) {
	l := NewLedger(Config{})
	a, release, _ := setupReleaseRiskFixture(t, l)
	l.projects["project"] = domain.Project{ID: "project", TenantID: a.TenantID, ProductID: release.ProductID}
	l.buildRuns["build"] = domain.BuildRun{ID: "build", TenantID: a.TenantID, ProjectID: "project", ReleaseID: release.ID}
	l.attestations["attestation"] = domain.BuildAttestation{ID: "attestation", TenantID: a.TenantID, BuildID: "build", EvidenceID: "evidence", PayloadRef: strings.Repeat("private-location", 700000)}
	l.evidence["evidence"] = domain.EvidenceItem{ID: "evidence", TenantID: a.TenantID, ProductID: release.ProductID, ProjectID: "project", ReleaseID: release.ID, BuildID: "build"}
	beforeAudits := len(l.chain[a.TenantID])
	l.verificationCommands = nil
	l.now = func() time.Time { panic("replay guard consulted clock") }
	guard, ok := any(l).(interface {
		AuthorizeDSSEVerification(context.Context, domain.Actor, string) error
	})
	if !ok {
		t.Fatal("missing local-only DSSE replay guard")
	}
	for _, grant := range []domain.ResourceGrant{
		{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeVerifyRead}},
		{ResourceType: "product", ResourceID: release.ProductID, Scopes: []string{ScopeVerifyRead}},
		{ResourceType: "project", ResourceID: "project", Scopes: []string{ScopeVerifyRead}},
		{ResourceType: "release", ResourceID: release.ID, Scopes: []string{ScopeVerifyRead}},
	} {
		human := domain.Actor{TenantID: a.TenantID, UserID: "user", Scopes: []string{ScopeVerifyRead}, ResourceGrants: []domain.ResourceGrant{grant}}
		if err := guard.AuthorizeDSSEVerification(t.Context(), human, " attestation "); err != nil {
			t.Fatal("valid scoped replay denied", grant, err)
		}
		human.ResourceGrants[0].ResourceID = "unrelated"
		if err := guard.AuthorizeDSSEVerification(t.Context(), human, "attestation"); !errors.Is(err, ErrForbidden) {
			t.Fatal("wrong resource grant accepted", grant, err)
		}
		human.ResourceGrants = nil
		if err := guard.AuthorizeDSSEVerification(t.Context(), human, "attestation"); !errors.Is(err, ErrForbidden) {
			t.Fatal("removed grant accepted", err)
		}
	}
	for _, id := range []string{"missing", "foreign"} {
		l.attestations["foreign"] = domain.BuildAttestation{ID: "foreign", TenantID: "other", BuildID: "build"}
		if err := guard.AuthorizeDSSEVerification(t.Context(), a, id); !errors.Is(err, ErrNotFound) {
			t.Fatal("missing/foreign replay subject accepted", err)
		}
	}
	if err := guard.AuthorizeDSSEVerification(t.Context(), a, strings.Repeat(" ", 1024)+"attestation"); !errors.Is(err, ErrValidation) {
		t.Fatal("raw ID bound bypassed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := guard.AuthorizeDSSEVerification(ctx, a, "attestation"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled guard succeeded", err)
	}
	for _, mutate := range []func(){
		func() { v := l.buildRuns["build"]; v.TenantID = "other"; l.buildRuns["build"] = v },
		func() { v := l.projects["project"]; v.TenantID = "other"; l.projects["project"] = v },
		func() { v := l.releases[release.ID]; v.TenantID = "other"; l.releases[release.ID] = v },
		func() { v := l.products[release.ProductID]; v.TenantID = "other"; l.products[release.ProductID] = v },
	} {
		build, project, releaseRow, product := l.buildRuns["build"], l.projects["project"], l.releases[release.ID], l.products[release.ProductID]
		mutate()
		if err := guard.AuthorizeDSSEVerification(t.Context(), a, "attestation"); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign current parent accepted by key replay", err)
		}
		l.buildRuns["build"], l.projects["project"], l.releases[release.ID], l.products[release.ProductID] = build, project, releaseRow, product
	}
	for _, mutate := range []func(*domain.EvidenceItem){
		func(e *domain.EvidenceItem) { e.TenantID = "other" },
		func(e *domain.EvidenceItem) { e.BuildID = "other-build" },
		func(e *domain.EvidenceItem) { e.ProjectID = "other-project" },
		func(e *domain.EvidenceItem) { e.ReleaseID = "other-release" },
		func(e *domain.EvidenceItem) { e.ProductID = "other-product" },
	} {
		original := l.evidence["evidence"]
		value := original
		mutate(&value)
		l.evidence["evidence"] = value
		if err := guard.AuthorizeDSSEVerification(t.Context(), a, "attestation"); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/inconsistent current source evidence accepted", err)
		}
		l.evidence["evidence"] = original
	}
	if len(l.verifications) != 0 || len(l.chain[a.TenantID]) != beforeAudits {
		// Guards must add neither a verification receipt nor an audit entry.
		t.Fatal("local guard wrote durable effects", len(l.verifications), len(l.chain[a.TenantID]))
	}
}

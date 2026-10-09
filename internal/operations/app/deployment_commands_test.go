package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type deploymentCommandFake struct {
	environment  DeploymentEnvironmentIdentity
	release      DeploymentReleaseIdentity
	rollback     DeploymentRollbackIdentity
	failure      string
	transactions int
	artifacts    []string
	evidence     []DeploymentEvidenceInput
	events       []operationsdomain.DeploymentEvent
	audit        []application.AuditEvent
}

func (f *deploymentCommandFake) LockDeploymentTenant(context.Context, string) error { return nil }

func (f *deploymentCommandFake) ExecuteDeployment(ctx context.Context, fn func(context.Context, DeploymentTransaction) error) error {
	f.transactions++
	c := *f
	c.evidence = append([]DeploymentEvidenceInput(nil), f.evidence...)
	c.events = append([]operationsdomain.DeploymentEvent(nil), f.events...)
	c.audit = append([]application.AuditEvent(nil), f.audit...)
	if err := fn(ctx, &c); err != nil {
		return err
	}
	if f.failure == "commit" {
		return errors.New("commit failed")
	}
	f.evidence, f.events, f.audit = c.evidence, c.events, c.audit
	return nil
}
func (f *deploymentCommandFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.failure == "scope" && r.ScopeOnly || f.failure == "grant" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	if r.Scope != "deployment:write" {
		return errors.New("hidden scope")
	}
	return nil
}
func (f *deploymentCommandFake) LockDeploymentEnvironment(context.Context, string, string) (DeploymentEnvironmentIdentity, error) {
	if f.failure == "environment" {
		return DeploymentEnvironmentIdentity{}, ErrNotFound
	}
	return f.environment, nil
}
func (f *deploymentCommandFake) LockDeploymentRelease(context.Context, string, string) (DeploymentReleaseIdentity, error) {
	if f.failure == "release" {
		return DeploymentReleaseIdentity{}, ErrNotFound
	}
	return f.release, nil
}
func (f *deploymentCommandFake) CheckDeploymentArtifacts(_ context.Context, _ string, ids []string) error {
	f.artifacts = append([]string(nil), ids...)
	if f.failure == "artifacts" {
		return ErrNotFound
	}
	return nil
}
func (f *deploymentCommandFake) LockDeploymentRollback(context.Context, string, string) (DeploymentRollbackIdentity, error) {
	if f.failure == "rollback" {
		return DeploymentRollbackIdentity{}, ErrNotFound
	}
	return f.rollback, nil
}
func (f *deploymentCommandFake) WriteDeploymentEvidence(_ context.Context, _ identitydomain.Actor, in DeploymentEvidenceInput) (string, error) {
	if f.failure == "evidence" {
		return "", errors.New("evidence failed")
	}
	f.evidence = append(f.evidence, in)
	return "ev_id", nil
}
func (f *deploymentCommandFake) InsertDeployment(_ context.Context, v operationsdomain.DeploymentEvent) error {
	if f.failure == "insert" {
		return errors.New("insert failed")
	}
	f.events = append(f.events, v)
	return nil
}
func (f *deploymentCommandFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errors.New("audit failed")
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func deploymentFixture(t *testing.T) (*DeploymentCommands, *deploymentCommandFake, identitydomain.Actor, RecordDeploymentInput) {
	t.Helper()
	f := &deploymentCommandFake{environment: DeploymentEnvironmentIdentity{ID: "env", TenantID: "tenant", ProductID: "product"}, release: DeploymentReleaseIdentity{ID: "release", TenantID: "tenant", ProductID: "product"}, rollback: DeploymentRollbackIdentity{ID: "prior", TenantID: "tenant", EnvironmentID: "env"}}
	c, err := NewDeploymentCommands(DeploymentConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}, RecordDeploymentInput{EnvironmentID: " env ", ReleaseID: " release ", Status: " succeeded ", ArtifactIDs: []string{"b", " a ", "b"}, RollbackOf: " prior "}
}
func TestDeploymentRecordingCommitsFixedEvidenceAndEventTogether(t *testing.T) {
	c, f, a, in := deploymentFixture(t)
	finished := time.Date(2026, 10, 2, 3, 0, 0, 0, time.FixedZone("offset", 3600))
	in.FinishedAt = &finished
	v, err := c.RecordDeployment(t.Context(), a, in)
	if err != nil || v.ID != "dep_id" || v.EvidenceID != "ev_id" || v.EnvironmentID != "env" || v.ReleaseID != "release" || v.Status != "succeeded" || v.SchemaVersion != operationsdomain.DeploymentEventSchemaVersion || !reflect.DeepEqual(v.ArtifactIDs, []string{"a", "b", "b"}) || v.StartedAt != v.CreatedAt || len(f.events) != 1 || len(f.evidence) != 1 || len(f.audit) != 1 {
		t.Fatal(v, f, err)
	}
	if v.FinishedAt == in.FinishedAt || !v.FinishedAt.Equal(finished) || v.FinishedAt.Location() != time.UTC {
		t.Fatal("finished timestamp not independently normalized", v)
	}
	if f.evidence[0].DeploymentID != v.ID || f.evidence[0].EnvironmentID != v.EnvironmentID || f.evidence[0].ProductID != "product" || f.evidence[0].CreatedAt != v.CreatedAt || f.audit[0].EntryType != "deployment.recorded" {
		t.Fatal(f)
	}
	in.ArtifactIDs[0] = "changed"
	if v.ArtifactIDs[1] != "b" {
		t.Fatal("input aliased output")
	}
}
func TestDeploymentRecordingRollsBackEveryEffectAndRejectsForeignReferences(t *testing.T) {
	for _, failure := range []string{"scope", "grant", "environment", "release", "artifacts", "rollback", "evidence", "audit", "insert", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := deploymentFixture(t)
			f.failure = failure
			v, err := c.RecordDeployment(t.Context(), a, in)
			if err == nil || v.ID != "" || len(f.events)+len(f.evidence)+len(f.audit) != 0 {
				t.Fatal(v, f, err)
			}
			if failure == "scope" && f.transactions != 0 {
				t.Fatal("scope reached transaction")
			}
		})
	}
	for _, mutate := range []func(*deploymentCommandFake){func(f *deploymentCommandFake) { f.environment.TenantID = "other" }, func(f *deploymentCommandFake) { f.release.ProductID = "other" }, func(f *deploymentCommandFake) { f.release.TenantID = "other" }, func(f *deploymentCommandFake) { f.rollback.EnvironmentID = "other" }, func(f *deploymentCommandFake) { f.rollback.TenantID = "other" }} {
		c, f, a, in := deploymentFixture(t)
		mutate(f)
		if v, err := c.RecordDeployment(t.Context(), a, in); !errors.Is(err, ErrNotFound) || v.ID != "" || len(f.evidence) != 0 {
			t.Fatal(v, err)
		}
	}
}
func TestDeploymentRecordingValidatesBeforeTransactions(t *testing.T) {
	for _, mutate := range []func(*RecordDeploymentInput){func(in *RecordDeploymentInput) { in.Status = "unknown" }, func(in *RecordDeploymentInput) { in.EnvironmentID = "bad\x00" }, func(in *RecordDeploymentInput) { in.ArtifactIDs = []string{" "} }, func(in *RecordDeploymentInput) { in.ArtifactIDs = []string{string([]byte{0xff})} }, func(in *RecordDeploymentInput) { in.ArtifactIDs = make([]string, 1025) }, func(in *RecordDeploymentInput) { in.RollbackOf = strings.Repeat("r", 1025) }, func(in *RecordDeploymentInput) { in.StartedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }} {
		c, f, a, in := deploymentFixture(t)
		mutate(&in)
		if _, err := c.RecordDeployment(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f.transactions)
		}
	}
	c, f, a, in := deploymentFixture(t)
	var absent context.Context
	if _, err := c.RecordDeployment(absent, a, in); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.RecordDeployment(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
}

func TestDeploymentRecordingUsesDurableTimestampPrecision(t *testing.T) {
	c, f, a, in := deploymentFixture(t)
	at := time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC)
	c.config.Clock = application.ClockFunc(func() time.Time { return at })
	in.StartedAt = at
	in.FinishedAt = &at
	v, err := c.RecordDeployment(t.Context(), a, in)
	if err != nil || v.CreatedAt != at.Truncate(time.Microsecond) || v.StartedAt != v.CreatedAt || *v.FinishedAt != v.CreatedAt || f.evidence[0].ObservedAt != v.StartedAt {
		t.Fatal("deployment and evidence timestamps do not round trip", v, err)
	}
}

func TestDeploymentRecordingPreservesStatusesAndTimestampOrderCompatibility(t *testing.T) {
	for _, status := range []string{"started", "succeeded", "failed", "rolled_back"} {
		c, _, a, in := deploymentFixture(t)
		in.Status = status
		in.StartedAt = time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
		before := in.StartedAt.Add(-time.Hour)
		in.FinishedAt = &before
		if v, err := c.RecordDeployment(t.Context(), a, in); err != nil || v.Status != status || !v.FinishedAt.Before(v.StartedAt) {
			t.Fatal("legacy metadata ordering changed", v, err)
		}
	}
}

func TestDeploymentRecordingRequiresAllDependencies(t *testing.T) {
	for _, mutate := range []func(*DeploymentConfig){func(c *DeploymentConfig) { c.Transactions = nil }, func(c *DeploymentConfig) { c.Authorizer = nil }, func(c *DeploymentConfig) { c.Clock = nil }, func(c *DeploymentConfig) { c.IDs = nil }} {
		c, _, _, _ := deploymentFixture(t)
		config := c.config
		mutate(&config)
		if _, err := NewDeploymentCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
}

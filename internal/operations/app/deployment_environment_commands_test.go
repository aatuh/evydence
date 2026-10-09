package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type environmentCommandFake struct {
	product      EnvironmentProduct
	environment  operationsdomain.DeploymentEnvironment
	failure      string
	audit        []application.AuditEvent
	transactions int
}

var errEnvironmentCommandTest = errors.New("environment command failure")

func (f *environmentCommandFake) LockDeploymentTenant(context.Context, string) error { return nil }

func (f *environmentCommandFake) ExecuteEnvironment(ctx context.Context, fn func(context.Context, DeploymentEnvironmentTransaction) error) error {
	f.transactions++
	tx := *f
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if f.failure == "commit" {
		return errEnvironmentCommandTest
	}
	f.environment, f.audit = tx.environment, tx.audit
	return nil
}
func (f *environmentCommandFake) Authorize(_ context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if !a.HasScope("deployment:write") || f.failure == "scope" || !r.ScopeOnly && f.failure == "grant" {
		return application.ErrForbidden
	}
	if r.Scope != "deployment:write" || r.TenantWide || r.ScopeOnly && r.Resources != (application.ResourceReferences{}) || !r.ScopeOnly && r.Resources != (application.ResourceReferences{ProductID: "product"}) {
		return application.ErrForbidden
	}
	return nil
}
func (f *environmentCommandFake) LockEnvironmentProduct(context.Context, string, string) (EnvironmentProduct, error) {
	if f.failure == "product" {
		return EnvironmentProduct{}, errEnvironmentCommandTest
	}
	return f.product, nil
}
func (f *environmentCommandFake) EnvironmentByName(context.Context, string, string, string) (operationsdomain.DeploymentEnvironment, bool, error) {
	if f.failure == "read" {
		return operationsdomain.DeploymentEnvironment{}, false, errEnvironmentCommandTest
	}
	return f.environment, f.environment.ID != "", nil
}
func (f *environmentCommandFake) InsertEnvironment(_ context.Context, v operationsdomain.DeploymentEnvironment) error {
	if f.failure == "insert" {
		return errEnvironmentCommandTest
	}
	f.environment = v
	return nil
}
func (f *environmentCommandFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errEnvironmentCommandTest
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{}, nil
}
func environmentCommandFixture(t *testing.T) (*DeploymentEnvironmentCommands, *environmentCommandFake, identitydomain.Actor, CreateEnvironmentInput) {
	t.Helper()
	f := &environmentCommandFake{product: EnvironmentProduct{TenantID: "tenant", ID: "product"}}
	c, err := NewDeploymentEnvironmentCommands(DeploymentEnvironmentConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}, CreateEnvironmentInput{ProductID: " product ", Name: " Production ", Kind: " production "}
}
func TestDeploymentEnvironmentCreationReturnsDurableOriginalWithoutDuplicateAudit(t *testing.T) {
	c, f, a, in := environmentCommandFixture(t)
	v, err := c.CreateDeploymentEnvironment(t.Context(), a, in)
	if err != nil || v.ID != "env_id" || v.ProductID != "product" || v.TenantID != "tenant" || v.Name != "Production" || v.Kind != "production" || v.SchemaVersion != operationsdomain.DeploymentEnvironmentVersion || len(f.audit) != 1 || f.audit[0].EntryType != "deployment_environment.created" || f.audit[0].ActorID != "key" {
		t.Fatal(v, f, err)
	}
	in.Kind = "changed"
	if again, err := c.CreateDeploymentEnvironment(t.Context(), a, in); err != nil || again != v || len(f.audit) != 1 {
		t.Fatal("duplicate name changed existing environment", again, err)
	}
}
func TestDeploymentEnvironmentCreationRollsBackAndAuthorizesBeforeLookup(t *testing.T) {
	for _, failure := range []string{"scope", "grant", "product", "read", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			c, f, a, in := environmentCommandFixture(t)
			f.failure = failure
			v, err := c.CreateDeploymentEnvironment(t.Context(), a, in)
			if err == nil || v.ID != "" || f.environment.ID != "" || len(f.audit) != 0 {
				t.Fatal(v, f, err)
			}
			if failure == "scope" && f.transactions != 0 {
				t.Fatal("denied scope reached transaction")
			}
		})
	}
}
func TestDeploymentEnvironmentCreationRejectsBadInputAndForeignProjection(t *testing.T) {
	for _, in := range []CreateEnvironmentInput{{ProductID: "product", Name: " ", Kind: "production"}, {ProductID: "other\x00", Name: "Prod", Kind: "production"}, {ProductID: "product", Name: string([]byte{0xff}), Kind: "production"}, {ProductID: "product", Name: "Prod", Kind: strings.Repeat("k", MaxEnvironmentTextBytes+1)}} {
		c, f, a, _ := environmentCommandFixture(t)
		if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(err, f)
		}
	}
	for _, p := range []EnvironmentProduct{{ID: "product", TenantID: "other"}, {ID: "other", TenantID: "tenant"}} {
		c, f, a, in := environmentCommandFixture(t)
		f.product = p
		if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	c, f, a, in := environmentCommandFixture(t)
	f.environment = operationsdomain.DeploymentEnvironment{ID: "foreign", TenantID: "other", ProductID: "product", Name: "Production", Kind: "production"}
	if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestDeploymentEnvironmentCreationBoundsIndexedKeyBytes(t *testing.T) {
	for _, extra := range []int{0, 1} {
		c, f, a, in := environmentCommandFixture(t)
		in.ProductID = strings.TrimSpace(in.ProductID)
		in.Name = strings.Repeat("n", 2304-len(a.TenantID)-len(in.ProductID)+extra)
		v, err := c.CreateDeploymentEnvironment(t.Context(), a, in)
		if extra == 0 {
			if err != nil || v.Name != in.Name || len(f.audit) != 1 {
				t.Fatal("safe boundary rejected", err)
			}
		} else if !errors.Is(err, ErrValidation) || f.transactions != 0 || v.ID != "" {
			t.Fatal("oversized composite key reached persistence", err, f.transactions)
		}
	}
	c, f, a, in := environmentCommandFixture(t)
	in.Name = strings.Repeat("é", 1200)
	if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
		t.Fatal("key limit must count bytes, not characters", err)
	}
}

func TestDeploymentEnvironmentCreationUsesHumanAndCollectorAuditIdentity(t *testing.T) {
	for _, kind := range []string{"human_user", "collector"} {
		c, f, a, in := environmentCommandFixture(t)
		a.KeyID = ""
		want := "identity"
		if kind == "collector" {
			a.CollectorID = want
		} else {
			a.UserID = want
		}
		if _, err := c.CreateDeploymentEnvironment(t.Context(), a, in); err != nil || f.audit[0].ActorType != kind || f.audit[0].ActorID != want {
			t.Fatal(f.audit, err)
		}
	}
}

func TestDeploymentEnvironmentCreationRequiresDependenciesAndLiveContext(t *testing.T) {
	for _, mutate := range []func(*DeploymentEnvironmentConfig){func(c *DeploymentEnvironmentConfig) { c.Transactions = nil }, func(c *DeploymentEnvironmentConfig) { c.Authorizer = nil }, func(c *DeploymentEnvironmentConfig) { c.Clock = nil }, func(c *DeploymentEnvironmentConfig) { c.IDs = nil }} {
		c, _, _, _ := environmentCommandFixture(t)
		config := c.config
		mutate(&config)
		if _, err := NewDeploymentEnvironmentCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	c, f, a, in := environmentCommandFixture(t)
	var missingContext context.Context
	if _, err := c.CreateDeploymentEnvironment(missingContext, a, in); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateDeploymentEnvironment(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
}

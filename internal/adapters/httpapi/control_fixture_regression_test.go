package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type failingControlFixture struct {
	controlFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingControlFixture) failure(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private control fixture failure after write")
}
func (f *failingControlFixture) CreateControlFramework(ctx context.Context, a domain.Actor, in riskapp.CreateControlFrameworkInput) (riskdomain.ControlFramework, error) {
	v, err := f.controlFixtureCommands.CreateControlFramework(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingControlFixture) CreateSecurityControl(ctx context.Context, a domain.Actor, in riskapp.CreateSecurityControlInput) (riskdomain.SecurityControl, error) {
	v, err := f.controlFixtureCommands.CreateSecurityControl(ctx, a, in)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingControlFixture) InstallControlFrameworkTemplatePack(ctx context.Context, a domain.Actor, slug string) (riskdomain.ControlFramework, error) {
	v, err := f.controlFixtureCommands.InstallControlFrameworkTemplatePack(ctx, a, slug)
	return v, f.failure(ctx, v.ID, err)
}
func (f *failingControlFixture) LinkControlEvidence(ctx context.Context, a domain.Actor, id string, in riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error) {
	v, err := f.controlFixtureCommands.LinkControlEvidence(ctx, a, id, in)
	return v, f.failure(ctx, v.ID, err)
}

type controlFixtureScope struct {
	operationsFixtureScope
	framework domain.ControlFramework
	control   domain.SecurityControl
}

func seedControlFixtureScope(t *testing.T, ledger *app.Ledger, name string) controlFixtureScope {
	t.Helper()
	f := controlFixtureScope{operationsFixtureScope: seedOperationsFixtureScope(t, ledger, name)}
	var err error
	f.framework, err = ledger.CreateControlFramework(t.Context(), f.actor, app.CreateControlFrameworkInput{Name: name, Slug: strings.ToLower(name), Version: "1", Description: "Recorded framework"})
	if err != nil {
		t.Fatal("seed framework:", err)
	}
	f.control, err = ledger.CreateSecurityControl(t.Context(), f.actor, app.CreateSecurityControlInput{FrameworkID: f.framework.ID, Code: "REVIEW", Title: "Review", Objective: "Record reviewed evidence", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", FreshnessDays: 30, Required: false}}, Applicability: []string{"software"}, Limitations: []string{"Human review required"}})
	if err != nil {
		t.Fatal("seed control:", err)
	}
	return f
}

type controlFixtureRequest struct{ name, path, body string }

func controlFixtureRequests(f controlFixtureScope) []controlFixtureRequest {
	return []controlFixtureRequest{
		{"framework", "/v1/control-frameworks", `{"name":"New Framework","version":"2","description":"Recorded guidance"}`},
		{"control", "/v1/controls", fmt.Sprintf(`{"framework_id":%q,"code":"NEW","title":"New control","objective":"Record evidence","evidence_requirements":[{"type":"build","required":false,"freshness_days":30}],"applicability":["software"],"limitations":["Human review required"]}`, f.framework.ID)},
		{"template", "/v1/control-framework-template-packs/evydence-cra-readiness/install", `{}`},
		{"link", "/v1/controls/" + f.control.ID + "/evidence", fmt.Sprintf(`{"evidence_type":"build","subject_type":"evidence","subject_id":%q,"product_id":%q,"release_id":%q,"confidence":"high","notes":"Reviewed"}`, f.evidence.ID, f.product.ID, f.release.ID)},
	}
}
func TestControlFixturesRollBackFrameworkControlTemplateLinkAndAuditEffects(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedControlFixtureScope(t, ledger, "Owner")
		request := controlFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingControlFixture{controlFixtureCommands: controlFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.controlCommands, server.controlTemplateCommands, server.controlEvidenceCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, "private control") {
				t.Fatal("failed control command bypassed isolation or exposed partial metadata")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("failed receipt missing", err)
			}
			for key, record := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil) {
					t.Fatal("partial control success cached")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed control write published framework, template children, link, audit or outbox effects")
			}
		})
	}
}
func TestControlFixturesReplayRechecksCurrentAdministrationAndSubjectAuthority(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedControlFixtureScope(t, ledger, "Owner")
	foreign := seedControlFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"controls:admin", "controls:write"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: owner.actor.TenantID, Scopes: []string{"controls:admin"}}, {ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"controls:write"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range controlFixtureRequests(owner) {
		t.Run(request.name, func(t *testing.T) {
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201))
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"controls:admin", "controls:write"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			}
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			if request.name == "control" || request.name == "link" {
				auth.actor.TenantID = foreign.actor.TenantID
				auth.actor.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"*"}}}
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 404)
				auth.actor = human
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("completed/rejected control replay added effects", err)
			}
		})
	}
}

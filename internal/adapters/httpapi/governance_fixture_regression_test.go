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
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type failingGovernanceFixtureCommands struct {
	governanceFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingGovernanceFixtureCommands) failAfterWrite(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private governance fixture failure")
}
func (f *failingGovernanceFixtureCommands) CreateWaiver(ctx context.Context, a domain.Actor, in riskapp.CreateWaiverInput) (riskdomain.Waiver, error) {
	v, err := f.governanceFixtureCommands.CreateWaiver(ctx, a, in)
	return v, f.failAfterWrite(ctx, v.ID, err)
}
func (f *failingGovernanceFixtureCommands) ApproveWaiver(ctx context.Context, a domain.Actor, id string) (riskdomain.Waiver, error) {
	v, err := f.governanceFixtureCommands.ApproveWaiver(ctx, a, id)
	return v, f.failAfterWrite(ctx, v.ID, err)
}
func (f *failingGovernanceFixtureCommands) CreateException(ctx context.Context, a domain.Actor, in riskapp.CreateExceptionInput) (riskdomain.Exception, error) {
	v, err := f.governanceFixtureCommands.CreateException(ctx, a, in)
	return v, f.failAfterWrite(ctx, v.ID, err)
}
func (f *failingGovernanceFixtureCommands) ApproveException(ctx context.Context, a domain.Actor, id string) (riskdomain.Exception, error) {
	v, err := f.governanceFixtureCommands.ApproveException(ctx, a, id)
	return v, f.failAfterWrite(ctx, v.ID, err)
}
func (f *failingGovernanceFixtureCommands) CreateApprovalRecord(ctx context.Context, a domain.Actor, in riskapp.CreateApprovalInput) (riskdomain.ApprovalRecord, error) {
	v, err := f.governanceFixtureCommands.CreateApprovalRecord(ctx, a, in)
	return v, f.failAfterWrite(ctx, v.ID, err)
}

func TestGovernanceFixtureCommandsRollBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, action := range []string{"waiver-create", "waiver-approve", "exception-create", "exception-approve", "approval"} {
		t.Run(action, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
			release, err := ledger.CreateRelease(t.Context(), scope.actor, scope.product.ID, "1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			expires := time.Now().UTC().Add(time.Hour)
			waiver, err := ledger.CreateWaiver(t.Context(), scope.actor, app.CreateWaiverInput{ScopeType: "release", ScopeID: release.ID, Owner: "security", Risk: "low", Reason: "reviewed", ExpiresAt: expires})
			if err != nil {
				t.Fatal(err)
			}
			exception, err := ledger.CreateException(t.Context(), scope.actor, app.CreateExceptionInput{ReleaseID: release.ID, Owner: "security", Reason: "reviewed", ExpiresAt: expires})
			if err != nil {
				t.Fatal(err)
			}
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: scope.actor}
			commands := &failingGovernanceFixtureCommands{governanceFixtureCommands: governanceFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.waiverCommands, server.exceptionCommands, server.approvalCommands = commands, commands, commands
			path, body := "/v1/waivers", fmt.Sprintf(`{"scope_type":"release","scope_id":%q,"owner":"security","risk":"low","reason":"supersession","expires_at":%q,"supersedes":%q}`, release.ID, expires.Format(time.RFC3339Nano), waiver.ID)
			switch action {
			case "waiver-approve":
				path, body = "/v1/waivers/"+waiver.ID+"/approve", `{}`
			case "exception-create":
				path, body = "/v1/exceptions", fmt.Sprintf(`{"release_id":%q,"owner":"security","reason":"reviewed","expires_at":%q}`, release.ID, expires.Format(time.RFC3339Nano))
			case "exception-approve":
				path, body = "/v1/exceptions/"+exception.ID+"/approve", `{}`
			case "approval":
				path, body = "/v1/approvals", fmt.Sprintf(`{"subject_type":"waiver","subject_id":%q,"decision":"accepted","reason":"reviewed","evidence_id":%q}`, waiver.ID, scope.original.ID)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, scope.secret, path, "fixture-governance-failure", []byte(body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, "private governance") {
				t.Fatal("failed governance command bypassed isolation or disclosed partial effects")
			}
			if !strings.HasSuffix(action, "approve") && strings.Contains(out, commands.changedID) {
				t.Fatal("failed governance command disclosed a new ID")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed command lost its replay failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Status != 0 || record.Response != nil {
					t.Fatal("failed command stored a partial replay result")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed governance command committed creation, approval, supersession, audit or job effects")
			}
		})
	}
}

func TestGovernanceFixtureReplaysRequireCurrentGrantsWithoutReapplyingTransitions(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	release, err := ledger.CreateRelease(t.Context(), owner.actor, owner.product.ID, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	waiverBody := fmt.Sprintf(`{"scope_type":"release","scope_id":%q,"owner":"security","risk":"low","reason":"reviewed","expires_at":%q}`, release.ID, expires)
	exceptionBody := fmt.Sprintf(`{"release_id":%q,"owner":"security","reason":"reviewed","expires_at":%q}`, release.ID, expires)
	waiver := postRaw(t, server, owner.secret, "/v1/waivers", "create-waiver", []byte(waiverBody), 201)
	waiverID := dataField(t, waiver, "id")
	waiverPath := "/v1/waivers/" + waiverID + "/approve"
	approvedWaiver := postRaw(t, server, owner.secret, waiverPath, "approve-waiver", []byte(`{}`), 200)
	exception := postRaw(t, server, owner.secret, "/v1/exceptions", "create-exception", []byte(exceptionBody), 201)
	exceptionPath := "/v1/exceptions/" + dataField(t, exception, "id") + "/approve"
	approvedException := postRaw(t, server, owner.secret, exceptionPath, "approve-exception", []byte(`{}`), 200)
	approvalBody := fmt.Sprintf(`{"subject_type":"waiver","subject_id":%q,"decision":"accepted","reason":"reviewed"}`, waiverID)
	approval := postRaw(t, server, owner.secret, "/v1/approvals", "approval", []byte(approvalBody), 201)
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, key, body, original string
		status                    int
	}{
		{"/v1/waivers", "create-waiver", waiverBody, waiver, 201},
		{waiverPath, "approve-waiver", `{}`, approvedWaiver, 200},
		{"/v1/exceptions", "create-exception", exceptionBody, exception, 201},
		{exceptionPath, "approve-exception", `{}`, approvedException, 200},
		{"/v1/approvals", "approval", approvalBody, approval, 201},
	} {
		assertTrustHTTPReplay(t, tc.original, postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body), tc.status))
		auth.actor.ResourceGrants = nil
		postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body), 403)
		auth.actor = human
		postRaw(t, server, owner.secret, tc.path, tc.key, []byte(tc.body+" "), 409)
	}
	guard := governanceFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if err := guard.AuthorizeApproveWaiver(t.Context(), foreign.actor, waiverID); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign tenant could replay waiver authority", err)
	}
	if err := guard.AuthorizeApproveException(t.Context(), foreign.actor, dataField(t, exception, "id")); !errors.Is(err, app.ErrNotFound) {
		t.Fatal("foreign tenant could replay exception authority", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := guard.AuthorizeApproval(ctx, human, riskapp.CreateApprovalInput{SubjectType: "waiver", SubjectID: waiverID, Decision: "accepted", Reason: "reviewed"}); !errors.Is(err, context.Canceled) {
		t.Fatal("governance guard ignored cancellation", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("completed/denied/conflicting governance retries changed repository state", err)
	}
}

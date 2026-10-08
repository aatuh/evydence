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
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidenceFixtureScope struct {
	actor                 domain.Actor
	secret                string
	product               domain.Product
	original, replacement domain.EvidenceItem
}

func seedEvidenceFixtureScope(t *testing.T, ledger *app.Ledger, name string) evidenceFixtureScope {
	t.Helper()
	var scope evidenceFixtureScope
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), name, "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	scope.secret = secret
	scope.actor, err = ledger.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	scope.product, err = ledger.CreateProduct(t.Context(), scope.actor, name, name)
	if err != nil {
		t.Fatal(err)
	}
	scope.original, err = ledger.CreateEvidence(t.Context(), scope.actor, app.CreateEvidenceInput{ProductID: scope.product.ID, Type: "manual", Title: "Original", PayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	scope.replacement, err = ledger.CreateEvidence(t.Context(), scope.actor, app.CreateEvidenceInput{ProductID: scope.product.ID, Type: "manual", Title: "Replacement", PayloadHash: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

type failingEvidenceFixtureCommands struct {
	evidenceFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingEvidenceFixtureCommands) failAfterWrite(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private evidence fixture failure")
}
func (f *failingEvidenceFixtureCommands) CreateEvidence(ctx context.Context, actor identitydomain.Actor, input evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error) {
	value, err := f.evidenceFixtureCommands.CreateEvidence(ctx, actor, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingEvidenceFixtureCommands) SupersedeEvidence(ctx context.Context, actor identitydomain.Actor, id, replacement, reason string) (evidencedomain.EvidenceItem, error) {
	value, err := f.evidenceFixtureCommands.SupersedeEvidence(ctx, actor, id, replacement, reason)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingEvidenceFixtureCommands) LinkEvidence(ctx context.Context, actor identitydomain.Actor, id, kind, target string) (evidencedomain.EvidenceItem, error) {
	value, err := f.evidenceFixtureCommands.LinkEvidence(ctx, actor, id, kind, target)
	return value, f.failAfterWrite(ctx, value.ID, err)
}
func (f *failingEvidenceFixtureCommands) RecordLifecycleEvent(ctx context.Context, actor identitydomain.Actor, id string, input evidenceapp.RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	value, err := f.evidenceFixtureCommands.RecordLifecycleEvent(ctx, actor, id, input)
	return value, f.failAfterWrite(ctx, value.ID, err)
}

func TestEvidenceFixtureCommandsRollBackAllEffectsAfterWriteFailure(t *testing.T) {
	for _, action := range []string{"create", "supersede", "link", "lifecycle"} {
		t.Run(action, func(t *testing.T) {
			factory := app.NewMemoryUnitOfWorkFactory()
			ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
			scope := seedEvidenceFixtureScope(t, ledger, "Fixture")
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			// Isolate command effects from unrelated authentication heartbeats.
			server.authn = &configuredAuthenticator{actor: scope.actor}
			commands := &failingEvidenceFixtureCommands{evidenceFixtureCommands: evidenceFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.evidenceCreationCommands, server.evidenceRelationshipCommands = commands, commands
			path := "/v1/evidence"
			body := `{"type":"manual","title":"Failed creation","payload_hash":"sha256:` + strings.Repeat("c", 64) + `"}`
			switch action {
			case "supersede":
				path += "/" + scope.original.ID + "/supersede"
				body = fmt.Sprintf(`{"replacement_evidence_id":%q,"reason":"reviewed"}`, scope.replacement.ID)
			case "link":
				path += "/" + scope.original.ID + "/link"
				body = fmt.Sprintf(`{"target_type":"product","target_id":%q}`, scope.product.ID)
			case "lifecycle":
				path += "/" + scope.original.ID + "/lifecycle-events"
				body = fmt.Sprintf(`{"action":"amendment","reason":"reviewed","replacement_id":%q,"details":{"sequence":9007199254740993}}`, scope.replacement.ID)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			original, err := readFixtureEvidence(t.Context(), ledger, scope.actor, scope.original.ID)
			if err != nil {
				t.Fatal(err)
			}
			replacement, err := readFixtureEvidence(t.Context(), ledger, scope.actor, scope.replacement.ID)
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, scope.secret, path, "fixture-evidence-failure", []byte(body), 500)
			// Supersession/link results reuse the input evidence ID, which is
			// legitimately present in the Problem Details instance URL. Reject
			// a result envelope or private effects, not that public request ID.
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, `"data"`) || strings.Contains(out, `"canonical_hash"`) || strings.Contains(out, "private evidence") {
				t.Fatal("failed evidence command bypassed isolation or exposed partial effects")
			}
			if (action == "create" || action == "lifecycle") && strings.Contains(out, commands.changedID) {
				t.Fatal("failed command exposed a newly created evidence/event ID")
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed evidence command lost its replay failure record")
			}
			for _, record := range after.Idempotency {
				if record.State != app.IdempotencyFailed || record.Response != nil || record.Status != 0 {
					t.Fatal("failed evidence command stored a partial response")
				}
			}
			// Check the intentional failed replay record above, then compare
			// every other repository effect, not just the primary evidence row.
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed evidence command committed repository effects")
			}
			for _, value := range []domain.EvidenceItem{original, replacement} {
				current, err := readFixtureEvidence(t.Context(), ledger, scope.actor, value.ID)
				if err != nil || !reflect.DeepEqual(value, current) {
					t.Fatal("failed command published a link, supersession or core mutation", err)
				}
			}
			if action == "create" {
				if _, err := readFixtureEvidence(t.Context(), ledger, scope.actor, commands.changedID); !errors.Is(err, app.ErrNotFound) {
					t.Fatal("failed creation was published to authoritative fixture reads", err)
				}
			}
		})
	}
}

func TestEvidenceFixtureGuardsEnforceTenantScopeAndCancellationWithoutWrites(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owner := seedEvidenceFixtureScope(t, ledger, "Owner")
	foreign := seedEvidenceFixtureScope(t, ledger, "Foreign")
	commands := evidenceFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	creation := evidenceapp.CreateEvidenceInput{ProductID: owner.product.ID, Type: "manual", Title: "Guard", PayloadHash: "sha256:" + strings.Repeat("c", 64)}
	lifecycle := evidenceapp.RecordLifecycleInput{Action: "amendment", Reason: "reviewed", ReplacementID: owner.replacement.ID}
	checks := []struct {
		name    string
		valid   func(context.Context, domain.Actor) error
		foreign func(context.Context, domain.Actor) error
	}{
		{"create", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeEvidenceCreation(ctx, a, creation)
		}, func(ctx context.Context, a domain.Actor) error {
			input := creation
			input.ProductID = foreign.product.ID
			return commands.AuthorizeEvidenceCreation(ctx, a, input)
		}},
		{"supersede", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeSupersedeEvidence(ctx, a, owner.original.ID, owner.replacement.ID, "reviewed")
		}, func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeSupersedeEvidence(ctx, a, owner.original.ID, foreign.replacement.ID, "reviewed")
		}},
		{"link", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeLinkEvidence(ctx, a, owner.original.ID, "product", owner.product.ID)
		}, func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeLinkEvidence(ctx, a, owner.original.ID, "product", foreign.product.ID)
		}},
		{"lifecycle", func(ctx context.Context, a domain.Actor) error {
			return commands.AuthorizeLifecycleEvent(ctx, a, owner.original.ID, lifecycle)
		}, func(ctx context.Context, a domain.Actor) error {
			input := lifecycle
			input.ReplacementID = foreign.replacement.ID
			return commands.AuthorizeLifecycleEvent(ctx, a, owner.original.ID, input)
		}},
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.valid(t.Context(), owner.actor); err != nil {
				t.Fatal("fixture guard rejected current ownership", err)
			}
			if err := tc.foreign(t.Context(), owner.actor); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("fixture guard accepted foreign references", err)
			}
			if err := tc.valid(t.Context(), foreign.actor); !errors.Is(err, app.ErrNotFound) {
				t.Fatal("fixture guard accepted another tenant's origin", err)
			}
			denied := owner.actor
			denied.Scopes = []string{"evidence:read"}
			if err := tc.valid(t.Context(), denied); !errors.Is(err, app.ErrForbidden) {
				t.Fatal("fixture guard skipped write authority", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := tc.valid(ctx, owner.actor); !errors.Is(err, context.Canceled) {
				t.Fatal("fixture guard ignored cancellation", err)
			}
		})
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only evidence guards changed repository state", err)
	}
}

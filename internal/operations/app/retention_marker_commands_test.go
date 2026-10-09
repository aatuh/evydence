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

type markerTestTx struct {
	steps     []string
	holds     []operationsdomain.LegalHold
	overrides []operationsdomain.RetentionOverride
	audits    []application.AuditEvent
	fail      string
}

func (x *markerTestTx) step(s string) error {
	x.steps = append(x.steps, s)
	if x.fail == s {
		return errors.New("injected marker failure")
	}
	return nil
}
func (x *markerTestTx) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := x.step("authorize"); err != nil {
		return err
	}
	return NewRetentionMarkerAuthorizer().Authorize(ctx, a, r)
}
func (x *markerTestTx) LockRetentionMarkerScope(_ context.Context, tenant, kind, id string) error {
	if tenant != "tenant" || id != "subject" || kind == "tenant" {
		return ErrNotFound
	}
	return x.step("lock")
}
func (x *markerTestTx) InsertLegalHold(_ context.Context, v operationsdomain.LegalHold) error {
	if err := x.step("write"); err != nil {
		return err
	}
	x.holds = append(x.holds, v)
	return nil
}
func (x *markerTestTx) InsertRetentionOverride(_ context.Context, v operationsdomain.RetentionOverride) error {
	if err := x.step("write"); err != nil {
		return err
	}
	x.overrides = append(x.overrides, v)
	return nil
}
func (x *markerTestTx) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if err := x.step("audit"); err != nil {
		return application.AuditReceipt{}, err
	}
	x.audits = append(x.audits, v)
	return application.AuditReceipt{}, nil
}

type markerTestTransactions struct {
	committed markerTestTx
	fail      string
	calls     int
}

func (x *markerTestTransactions) ExecuteRetentionMarker(ctx context.Context, fn func(context.Context, RetentionMarkerTransaction) error) error {
	x.calls++
	next := x.committed
	next.fail = x.fail
	next.steps = nil
	if err := fn(ctx, &next); err != nil {
		return err
	}
	if x.fail == "commit" {
		return errors.New("injected marker commit failure")
	}
	x.committed = next
	return nil
}
func markerTestCommands(t *testing.T, tx *markerTestTransactions, now time.Time) *RetentionMarkerCommands {
	t.Helper()
	c, err := NewRetentionMarkerCommands(RetentionMarkerConfig{Transactions: tx, Authorizer: NewRetentionMarkerAuthorizer(), Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func markerTestActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"admin"}}}}
}

func TestRetentionMarkersAppendAtomicallyAndPreserveSubjectAudit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, override := range []bool{false, true} {
		for _, fail := range []string{"", "authorize", "lock", "write", "audit", "commit"} {
			t.Run(fail+map[bool]string{false: "hold", true: "override"}[override], func(t *testing.T) {
				tx := &markerTestTransactions{fail: fail}
				c := markerTestCommands(t, tx, now)
				in := RetentionMarkerInput{ScopeType: " release ", ScopeID: " subject ", Reason: " review ", Owner: " legal "}
				var err error
				if override {
					v, e := c.CreateRetentionOverride(t.Context(), markerTestActor(), RetentionOverrideInput{RetentionMarkerInput: in, RetentionUntil: now.Add(time.Hour)})
					err = e
					if e == nil && (v.ID != "ro_new" || v.ScopeID != "subject" || !v.RetentionUntil.Equal(now.Add(time.Hour)) || v.SchemaVersion != operationsdomain.RetentionOverrideSchemaVersion) {
						t.Fatal(v)
					}
				} else {
					v, e := c.CreateLegalHold(t.Context(), markerTestActor(), in)
					err = e
					if e == nil && (v.ID != "lh_new" || v.Reason != "review" || v.Owner != "legal" || v.ReleasedAt != nil || v.SchemaVersion != operationsdomain.LegalHoldSchemaVersion) {
						t.Fatal(v)
					}
				}
				if fail != "" {
					if err == nil || len(tx.committed.holds)+len(tx.committed.overrides)+len(tx.committed.audits) != 0 {
						t.Fatal("partial marker committed", err)
					}
					return
				}
				if err != nil || strings.Join(tx.committed.steps, ",") != "authorize,lock,write,audit" || len(tx.committed.audits) != 1 {
					t.Fatal(tx.committed, err)
				}
				a := tx.committed.audits[0]
				if a.SubjectType != "release" || a.SubjectID != "subject" || a.ActorType != "human_user" || a.ActorID != "user" || a.TenantID != "tenant" || !a.OccurredAt.Equal(now) || a.PayloadHash != "" {
					t.Fatal("audit identity changed", a)
				}
			})
		}
	}
}

func TestRetentionMarkerReplayGuardIsReadOnlyAndDoesNotExpireHistoricalOverrides(t *testing.T) {
	tx := &markerTestTransactions{}
	c, err := NewRetentionMarkerCommands(RetentionMarkerConfig{Transactions: tx, Authorizer: NewRetentionMarkerAuthorizer(), Clock: application.ClockFunc(func() time.Time { t.Fatal("guard consulted clock"); return time.Time{} }), IDs: application.IDGeneratorFunc(func(string) string { t.Fatal("guard allocated ID"); return "" })})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AuthorizeRetentionMarker(t.Context(), markerTestActor(), " release ", " subject "); err != nil || strings.Join(tx.committed.steps, ",") != "authorize,lock" || len(tx.committed.audits) != 0 {
		t.Fatal("guard wrote state", err)
	}
	before := tx.calls
	a := markerTestActor()
	a.ResourceGrants = nil
	if err := c.AuthorizeRetentionMarker(t.Context(), a, "release", "subject"); !errors.Is(err, application.ErrForbidden) || tx.calls != before {
		t.Fatal("revoked authority reached storage", err)
	}
	a = markerTestActor()
	a.ResourceGrants[0].ResourceType = "product"
	a.ResourceGrants[0].ResourceID = "subject"
	if err := c.AuthorizeRetentionMarker(t.Context(), a, "product", "subject"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped admin became tenant admin", err)
	}
}

func TestRetentionMarkerInputBoundsAndExpiryRejectBeforeEffects(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tx := &markerTestTransactions{}
	c := markerTestCommands(t, tx, now)
	base := RetentionMarkerInput{ScopeType: "release", ScopeID: "subject", Reason: "review", Owner: "legal"}
	for _, mutate := range []func(*RetentionMarkerInput){func(v *RetentionMarkerInput) { v.ScopeType = "unknown" }, func(v *RetentionMarkerInput) { v.ScopeID = strings.Repeat(" ", 1024) + "subject" }, func(v *RetentionMarkerInput) { v.Reason = " " }, func(v *RetentionMarkerInput) { v.Owner = "bad\x00" }, func(v *RetentionMarkerInput) { v.Reason = string([]byte{255}) }, func(v *RetentionMarkerInput) { v.Owner = strings.Repeat("x", 65537) }} {
		in := base
		mutate(&in)
		before := tx.calls
		if _, err := c.CreateLegalHold(t.Context(), markerTestActor(), in); !errors.Is(err, ErrValidation) || tx.calls != before {
			t.Fatal("malformed marker reached transaction", err)
		}
	}
	for _, until := range []time.Time{{}, now, now.Add(-time.Hour), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, err := c.CreateRetentionOverride(t.Context(), markerTestActor(), RetentionOverrideInput{RetentionMarkerInput: base, RetentionUntil: until}); !errors.Is(err, ErrValidation) || len(tx.committed.overrides) != 0 || len(tx.committed.audits) != 0 {
			t.Fatal("expired/unencodable marker committed", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateLegalHold(ctx, markerTestActor(), base); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

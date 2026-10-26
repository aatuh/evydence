package app_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// This port supplies synthetic observations to test the native assessment
// taxonomy. It is not evidence of actual provider retention or WORM behavior.
type nativeFuzzRetention struct {
	policy      verificationdomain.ObjectRetentionPolicy
	observation verificationapp.RetentionObservation
	configured  bool
	observeErr  error
	fail        string
	reads       int
	observes    int
	updates     []verificationdomain.ObjectRetentionPolicy
	audits      []application.AuditEvent
}

func (s *nativeFuzzRetention) ReadObjectRetentionPolicy(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error) {
	s.reads++
	return s.policy, nil
}
func (s *nativeFuzzRetention) GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error) {
	value := s.policy
	if s.fail == "stale" {
		value.Name += "changed"
	}
	return value, nil
}
func (s *nativeFuzzRetention) LockObjectRetentionPolicy(_ context.Context, tenant, id string) error {
	if tenant != s.policy.TenantID || id != s.policy.ID {
		return verificationapp.ErrNotFound
	}
	return nil
}
func (s *nativeFuzzRetention) InsertObjectRetentionPolicy(context.Context, verificationdomain.ObjectRetentionPolicy) error {
	return verificationapp.ErrConflict
}
func (s *nativeFuzzRetention) UpdateObjectRetentionPolicy(_ context.Context, value verificationdomain.ObjectRetentionPolicy, oldStatus string) error {
	if s.fail == "update" {
		return errNativeFuzzWrite
	}
	if value.TenantID != s.policy.TenantID || value.ID != s.policy.ID || oldStatus != s.policy.Status || len(s.updates) != 0 {
		return verificationapp.ErrConflict
	}
	s.updates = append(s.updates, value)
	return nil
}
func (s *nativeFuzzRetention) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if s.fail == "audit" {
		return application.AuditReceipt{}, errNativeFuzzWrite
	}
	if event.TenantID != s.policy.TenantID || event.SubjectID != s.policy.ID || len(s.audits) != 0 {
		return application.AuditReceipt{}, verificationapp.ErrConflict
	}
	s.audits = append(s.audits, event)
	return application.AuditReceipt{ID: event.ID}, nil
}
func (s *nativeFuzzRetention) Authorize(ctx context.Context, actor identitydomain.Actor, req application.AuthorizationRequest) error {
	return verificationquery.NewRetentionAuthorizer().Authorize(ctx, actor, req)
}
func (s *nativeFuzzRetention) VerifyRetention(_ context.Context, request verificationapp.RetentionRequest) (verificationapp.RetentionObservation, bool, error) {
	s.observes++
	if request.TenantID != s.policy.TenantID || request.ObjectKey != s.policy.ObjectKey || request.ObjectPrefix != s.policy.ObjectPrefix || request.Mode != s.policy.Mode || request.RetentionDays != s.policy.RetentionDays || request.RequireLegalHold != s.policy.RequireLegalHold {
		return verificationapp.RetentionObservation{}, false, verificationapp.ErrConflict
	}
	return s.observation, s.configured, s.observeErr
}
func (s *nativeFuzzRetention) ExecuteRetentionCommand(ctx context.Context, fn func(context.Context, verificationapp.RetentionTransaction) error) error {
	tx := *s
	tx.updates, tx.audits = nil, nil
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if s.fail == "commit" {
		return errNativeFuzzWrite
	}
	s.updates, s.audits = tx.updates, tx.audits
	return nil
}

func nativeFuzzRetentionFixture(raw []byte) *nativeFuzzRetention {
	hold := true
	return &nativeFuzzRetention{
		policy:      verificationdomain.ObjectRetentionPolicy{ID: "policy", TenantID: "tenant", Name: "synthetic policy", ObjectPrefix: "tenants/tenant/", ObjectKey: "tenants/tenant/synthetic", Mode: "governance", RetentionDays: 30, MaxVerificationAgeHours: 24, RequireLegalHold: true, Status: "configured", SchemaVersion: verificationdomain.ObjectRetentionPolicyVersion, CreatedAt: nativeFuzzNow.Add(-time.Hour)},
		observation: verificationapp.RetentionObservation{Provider: "synthetic-fixture", Bucket: "synthetic-bucket", ObjectKey: "tenants/tenant/synthetic", Mode: "governance", RetentionDays: 30, Enforced: true, LegalHold: &hold, ObservedAt: nativeFuzzNow.Add(-time.Minute), Checks: []verificationdomain.VerifyCheck{{Name: "synthetic_provider_observation", Result: "passed", Detail: integrityFuzzDigest(raw)}}},
		configured:  true,
	}
}

func nativeFuzzRunRetention(t *testing.T, s *nativeFuzzRetention, actor identitydomain.Actor) (verificationdomain.ObjectRetentionPolicy, error) {
	t.Helper()
	c, err := verificationapp.NewRetentionCommands(verificationapp.RetentionCommandConfig{Reader: s, Transactions: s, Verifier: s, Hasher: integrityFuzzHasher{}, Authorizer: s, Clock: application.ClockFunc(func() time.Time { return nativeFuzzNow }), IDs: nativeFuzzIDs()})
	if err != nil {
		t.Fatal(err)
	}
	return c.VerifyObjectRetentionPolicy(t.Context(), actor, "policy")
}

func FuzzRetentionObservation(f *testing.F) {
	for mode := uint8(0); mode < 12; mode++ {
		f.Add([]byte("synthetic recorded retention observation"), mode)
	}
	f.Add([]byte{}, uint8(255))
	f.Fuzz(func(t *testing.T, raw []byte, mode uint8) {
		if len(raw) > 4096 {
			return
		}
		actor := nativeFuzzActor()
		s := nativeFuzzRetentionFixture(raw)
		before := nativeFuzzJSON(t, []any{s.policy, s.observation})
		positive, err := nativeFuzzRunRetention(t, s, actor)
		if err != nil || positive.Status != "verified" || positive.VerificationHash == "" || len(s.updates) != 1 || len(s.audits) != 1 || s.audits[0].PayloadHash != positive.VerificationHash || positive.VerificationExpiresAt == nil || !positive.VerificationExpiresAt.Equal(s.observation.ObservedAt.Add(24*time.Hour)) {
			t.Fatalf("synthetic positive observation assessment rejected: %v", err)
		}
		again, err := nativeFuzzRunRetention(t, nativeFuzzRetentionFixture(raw), actor)
		if err != nil || !reflect.DeepEqual(positive, again) {
			t.Fatal("retention assessment is not repeatable")
		}
		changed := nativeFuzzRetentionFixture(raw)
		expected := "not_verified"
		switch mode % 12 {
		case 0:
			changed.configured = false
		case 1:
			changed.observeErr = errors.New("synthetic private provider diagnostic")
		case 2:
			changed.observation.Enforced, expected = false, "not_enforced"
		case 3:
			changed.observation.ObjectKey = "tenants/foreign/synthetic"
		case 4:
			changed.observation.RetentionDays--
		case 5:
			changed.observation.LegalHold = nil
		case 6:
			changed.observation.Mode = "compliance"
		case 7:
			changed.observation.Checks[0].Result = "failed"
		case 8:
			changed.observation.Provider = ""
		case 9:
			changed.observation.Checks = make([]verificationdomain.VerifyCheck, verificationapp.MaxRetentionObservationFacts+1)
		case 10:
			changed.observation.Bucket = "bad\x00bucket"
		case 11:
			changed.observation.Checks[0].Result = "unknown"
		}
		decision, err := nativeFuzzRunRetention(t, changed, actor)
		if err != nil || decision.Status != expected || decision.VerificationExpiresAt != nil || len(changed.updates) != 1 || len(changed.audits) != 1 || changed.audits[0].EntryType != "object_retention_policy.verification_failed" || strings.Contains(nativeFuzzJSON(t, decision), "synthetic private provider diagnostic") {
			t.Fatalf("absent, invalid or negative observation acquired a verified state: %v", err)
		}
		if nativeFuzzJSON(t, []any{s.policy, s.observation}) != before {
			t.Fatal("retention command mutated its source policy or observation")
		}
		// Receipt freshness is assessed at report time without changing the
		// stored record. Synthetic verification is never live provider proof.
		snapshot := verificationapp.SigningCustodySnapshot{TenantID: "tenant", ObjectRetentionPolicies: []verificationdomain.ObjectRetentionPolicy{positive}}
		report, err := verificationapp.BuildSigningCustodyReviewReport(snapshot, "tenant", *positive.VerificationExpiresAt)
		if err != nil || len(report.ObjectRetentionPolicies) != 1 || report.ObjectRetentionPolicies[0].Status != "stale" || positive.Status != "verified" || report.Checks[2].Result != "failed" {
			t.Fatal("expired retention observation remained current or mutated its receipt")
		}
		snapshot.TenantID = "foreign"
		if _, err := verificationapp.BuildSigningCustodyReviewReport(snapshot, "tenant", nativeFuzzNow); !errors.Is(err, verificationapp.ErrNotFound) {
			t.Fatal("foreign custody snapshot was assessed")
		}
		failed := nativeFuzzRetentionFixture(raw)
		failed.fail = []string{"update", "audit", "commit", "stale"}[mode%4]
		_, err = nativeFuzzRunRetention(t, failed, actor)
		if (failed.fail == "stale" && !errors.Is(err, verificationapp.ErrConflict)) || (failed.fail != "stale" && !errors.Is(err, errNativeFuzzWrite)) || len(failed.updates)+len(failed.audits) != 0 {
			t.Fatal("retention transaction committed partial effects or stale policy")
		}
		foreign := nativeFuzzRetentionFixture(raw)
		actor.TenantID = "foreign"
		if _, err := nativeFuzzRunRetention(t, foreign, actor); !errors.Is(err, verificationapp.ErrNotFound) || foreign.observes != 0 || len(foreign.updates)+len(foreign.audits) != 0 {
			t.Fatal("foreign actor observed or changed retention policy")
		}
	})
}

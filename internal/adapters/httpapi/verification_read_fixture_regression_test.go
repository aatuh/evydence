package httpapi

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func TestVerificationQueryFixturesKeepTenantAuthorityAndReadOnlyState(t *testing.T) {
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory})
	owners := []evidenceFixtureScope{seedEvidenceFixtureScope(t, ledger, "Alpha"), seedEvidenceFixtureScope(t, ledger, "Bravo")}
	keys := signingKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	audits := auditLogFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	custody := custodyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range owners {
		keyPage, err := keys.ListPage(t.Context(), owner.actor, page, nil)
		if err != nil || len(keyPage.Items) != 1 || keyPage.Items[0].TenantID != owner.actor.TenantID || keyPage.Next != nil || signingKeyFromQuery(keyPage.Items[0]).Private != nil {
			t.Fatal("fixture signing-key page leaked tenant or private material", err)
		}
		since := owner.product.CreatedAt.Add(-time.Second)
		filter := verificationquery.AuditFilter{SubjectType: "product", SubjectID: owner.product.ID, Since: &since}
		auditPage, err := audits.ListPage(t.Context(), owner.actor, filter, page, nil)
		if err != nil || len(auditPage.Items) != 1 || auditPage.Items[0].TenantID != owner.actor.TenantID || auditPage.Items[0].SubjectID != owner.product.ID || auditPage.Next != nil {
			t.Fatal("fixture audit page lost tenant/subject/time filtering", err)
		}
		report, err := custody.Report(t.Context(), owner.actor)
		if err != nil || report.TenantID != owner.actor.TenantID {
			t.Fatal("fixture custody report lost tenant ownership", err)
		}
		denied := owner.actor
		denied.Scopes = []string{"evidence:read"}
		if _, err := keys.ListPage(t.Context(), denied, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture key query skipped administration scope", err)
		}
		if _, err := audits.ListPage(t.Context(), denied, filter, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture audit query skipped administration scope", err)
		}
		if _, err := custody.Report(t.Context(), denied); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("fixture custody query skipped administration scope", err)
		}
		scoped := domain.Actor{TenantID: owner.actor.TenantID, UserID: "scoped-human", Scopes: []string{"*"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"*"}}}}
		if _, err := keys.ListPage(t.Context(), scoped, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("product grant became tenant-wide key authority", err)
		}
		if _, err := audits.ListPage(t.Context(), scoped, filter, page, nil); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("product grant became tenant-wide audit authority", err)
		}
		if _, err := custody.Report(t.Context(), scoped); !errors.Is(err, app.ErrForbidden) {
			t.Fatal("product grant became tenant-wide custody authority", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := keys.ListPage(ctx, owner.actor, page, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("key query ignored cancellation", err)
		}
		if _, err := audits.ListPage(ctx, owner.actor, filter, page, nil); !errors.Is(err, context.Canceled) {
			t.Fatal("audit query ignored cancellation", err)
		}
		if _, err := custody.Report(ctx, owner.actor); !errors.Is(err, context.Canceled) {
			t.Fatal("custody query ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only verification fixture queries changed repository state", err)
	}
}

func TestSigningKeyFixtureConversionRetainsPublicLifecycleButNoPrivateBytes(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	key := domain.SigningKey{ID: "key", TenantID: "tenant", KID: "kid", Version: 7, Provider: "provider", Algorithm: "Ed25519", Status: "revoked", PublicKey: "public", PublicKeyFingerprint: "fingerprint", Private: []byte("private-fixture-key"), ValidFrom: now.Add(-time.Hour), ValidUntil: &now, CreatedAt: now.Add(-2 * time.Hour), RevokedAt: &now, RevocationReason: "reason", RevocationSemantics: "semantics", HistoricalValidityPolicy: "policy", CompromisedAt: &now}
	model, err := signingKeyFixtureModel(key)
	if err != nil {
		t.Fatal(err)
	}
	key.Private = nil
	if !reflect.DeepEqual(signingKeyFromQuery(model), key) {
		t.Fatal("fixture conversion exposed private bytes or lost public lifecycle metadata")
	}
}

func TestVerificationFixtureMappingRetainsFailedResultAndAssuranceProfile(t *testing.T) {
	value := domain.VerificationResult{ID: "result", TenantID: "tenant", SubjectType: "audit_chain", SubjectID: "chain", Result: "failed", Checks: []domain.VerifyCheck{{Name: "digest", Result: "failed", Detail: "mismatch"}}, Profile: domain.VerificationProfile{ID: "profile", Version: "1", RequiredChecks: []string{"digest"}, TrustMaterial: []string{"root"}, IdentityPolicy: "identity", TransparencyProof: "proof", PayloadScope: "scope", PayloadDigest: "digest", Limitations: []string{"profile-limit"}}, Limitations: []string{"result-limit"}, SchemaVersion: "1", VerifiedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)}
	model, err := fixtureVerificationResult(value, app.ErrVerificationFailed)
	if !errors.Is(err, app.ErrVerificationFailed) || !reflect.DeepEqual(domain.VerificationResultFromContextModel(model), value) {
		t.Fatal("fixture mapping hid a failed result or lost assurance data", err)
	}
	if result, err := fixtureVerificationResult(domain.VerificationResult{}, app.ErrForbidden); !errors.Is(err, app.ErrForbidden) || result.ID != "" {
		t.Fatal("denied verification produced a public result", err)
	}
}

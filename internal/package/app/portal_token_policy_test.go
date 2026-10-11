package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func TestPortalTokenPolicyCharacterizesCredentialAndPackageIsolationBeforeRefactor(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*portalTokenFixture)
		want error
	}{
		{"expired credential", func(f *portalTokenFixture) { f.access.ExpiresAt = time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC) }, application.ErrUnauthorized},
		{"revoked credential", func(f *portalTokenFixture) { at := f.access.CreatedAt; f.access.RevokedAt = &at }, application.ErrUnauthorized},
		{"foreign package tenant", func(f *portalTokenFixture) { f.pkg.TenantID = "foreign" }, ErrNotFound},
		{"different package", func(f *portalTokenFixture) { f.pkg.ID = "other" }, ErrNotFound},
		{"different product", func(f *portalTokenFixture) { f.pkg.ProductID = "other" }, ErrNotFound},
		{"different release", func(f *portalTokenFixture) { f.pkg.ReleaseID = "other" }, ErrNotFound},
		{"expired package", func(f *portalTokenFixture) { f.pkg.ExpiresAt = time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC) }, ErrNotFound},
	} {
		for _, download := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/read", true: "/download"}[download], func(t *testing.T) {
				c, f := newPortalTokenFixture(t)
				tc.edit(f)
				before, audits := ClonePortalAccess(f.access), append([]application.AuditEvent(nil), f.audits...)
				v, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, download)
				if !errors.Is(err, tc.want) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) || !reflect.DeepEqual(before, f.access) || !reflect.DeepEqual(audits, f.audits) {
					t.Fatal("denial leaked a package or changed acceptance/access/audit state", err)
				}
			})
		}
	}
}

func TestPortalTokenPolicyCharacterizesPreviouslyAcceptedAndOptionalNDA(t *testing.T) {
	for _, required := range []bool{false, true} {
		c, f := newPortalTokenFixture(t)
		f.access.RequireNDA = required
		if required {
			at := f.access.CreatedAt
			f.access.NDAAcceptedAt, f.access.NDAAcceptedBy = &at, "Original reviewer"
		}
		before := ClonePortalAccess(f.access)
		v, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{NDAAcceptedBy: "New label is not a new acceptance"}, true)
		if err != nil || v.ID != f.pkg.ID || f.access.AccessCount != before.AccessCount+1 || !reflect.DeepEqual(f.access.NDAAcceptedAt, before.NDAAcceptedAt) || f.access.NDAAcceptedBy != before.NDAAcceptedBy || len(f.audits) != 3 || f.audits[1].EntryType != "customer_portal_package.downloaded" || f.audits[2].SubjectID != f.pkg.ID {
			t.Fatal("existing consent or no-NDA access changed identity or audit semantics", err)
		}
	}
}

type cancelAfterPortalCommit struct {
	base   PortalTokenTransactions
	cancel context.CancelFunc
}

func (r cancelAfterPortalCommit) ExecutePortalToken(ctx context.Context, tenant string, fn func(context.Context, PortalTokenTransaction) error) error {
	if err := r.base.ExecutePortalToken(ctx, tenant, fn); err != nil {
		return err
	}
	r.cancel()
	return nil
}

func TestPortalTokenPolicyWithholdsPackageWhenCanceledAfterAccessCommit(t *testing.T) {
	for _, download := range []bool{false, true} {
		c, f := newPortalTokenFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c.config.Transactions = cancelAfterPortalCommit{f, cancel}
		v, err := c.AccessPortalPackage(ctx, f.secret, PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, download)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, packagedomain.CustomerSecurityPackage{}) {
			t.Error("late canceled request exposed the customer package", err)
		}
		// Cancellation cannot undo an already committed access. Do not
		// misreport this as rollback or weaken the original audit requirement.
		if f.access.AccessCount != 1 || f.access.NDAAcceptedAt == nil || len(f.audits) != 4 {
			t.Fatal("late cancellation changed the committed acceptance/access audit")
		}
	}
}

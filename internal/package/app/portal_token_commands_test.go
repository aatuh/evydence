package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type portalTokenFixture struct {
	*portalCommandFixture
	pkg    packagedomain.CustomerSecurityPackage
	secret string
}

func (f *portalTokenFixture) LookupPortalAccess(ctx context.Context, prefix string) (PortalAccessCandidate, error) {
	if prefix != f.access.Prefix {
		return PortalAccessCandidate{}, application.ErrUnauthorized
	}
	return PortalAccessCandidate{TenantID: f.access.TenantID, AccessID: f.access.ID}, ctx.Err()
}
func (f *portalTokenFixture) ExecutePortalToken(ctx context.Context, _ string, fn func(context.Context, PortalTokenTransaction) error) error {
	before, n := ClonePortalAccess(f.access), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errPortalFixture
	}
	if err != nil {
		f.access, f.audits = before, f.audits[:n]
	}
	return err
}
func (f *portalTokenFixture) ReadPortalAccessForToken(_ context.Context, _, _ string) (packagedomain.CustomerPortalAccess, error) {
	return ClonePortalAccess(f.access), nil
}
func (f *portalTokenFixture) GetPortalPackageForUpdate(context.Context, string, string) (packagedomain.CustomerSecurityPackage, error) {
	return cloneCustomerSecurityPackage(f.pkg), nil
}
func (f *portalTokenFixture) UpdatePortalTokenAccess(_ context.Context, _, v packagedomain.CustomerPortalAccess) error {
	if f.phase == "update" {
		return errPortalFixture
	}
	f.access = ClonePortalAccess(v)
	return nil
}
func (f *portalTokenFixture) HashPortalToken(token string) string {
	if token == f.secret {
		return f.access.Hash
	}
	return strings.Repeat("b", 64)
}
func (f *portalTokenFixture) EqualPortalHashes(a, b string) bool { return a == b }
func newPortalTokenFixture(t *testing.T) (*PortalTokenCommands, *portalTokenFixture) {
	t.Helper()
	c, f, a, in := newPortalCommandFixture(t)
	v, secret, err := c.CreatePortalAccess(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	tf := &portalTokenFixture{portalCommandFixture: f, secret: secret, pkg: packagedomain.CustomerSecurityPackage{ID: v.PackageID, TenantID: a.TenantID, ProductID: "product", ReleaseID: "release", Manifest: map[string]any{"evidence_ids": []string{"evidence"}}, ManifestHash: "sha256:manifest", ExpiresAt: in.ExpiresAt}}
	out, err := NewPortalTokenCommands(PortalTokenCommandConfig{Lookup: tf, Transactions: tf, Credentials: tf, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(application.NewID)})
	if err != nil {
		t.Fatal(err)
	}
	return out, tf
}
func TestPortalTokenCommandsNDAAuditWatermarkAndFailedAccessRevocation(t *testing.T) {
	c, f := newPortalTokenFixture(t)
	if _, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{}, false); !errors.Is(err, application.ErrForbidden) || f.access.AccessCount != 0 || len(f.audits) != 2 || f.audits[1].EntryType != "customer_portal_package.nda_required" {
		t.Fatal("NDA denial lost committed audit", err)
	}
	v, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: " Reviewer "}, false)
	if err != nil || f.access.AccessCount != 1 || f.access.NDAAcceptedBy != "Reviewer" || f.access.NDAAcceptedAt == nil || f.access.LastAccessedAt == nil || v.DistributionWatermark != f.access.Watermark || len(f.audits) != 5 {
		t.Fatal("portal acceptance/access contract differs", err)
	}
	v.Manifest["evidence_ids"] = "mutated"
	if _, ok := f.pkg.Manifest["evidence_ids"].([]string); !ok {
		t.Fatal("portal result aliases package")
	}
	if _, err = c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{}, true); err != nil || f.access.AccessCount != 2 || len(f.audits) != 7 || f.audits[5].EntryType != "customer_portal_package.downloaded" {
		t.Fatal("accepted NDA/download audit lost", err)
	}
	bad := f.secret[:len(f.secret)-1] + "B"
	for i := 1; i <= 5; i++ {
		if _, err := c.AccessPortalPackage(t.Context(), bad, PortalAcceptanceInput{}, false); !errors.Is(err, application.ErrUnauthorized) || f.access.FailedAccessCount != i || f.access.LastFailedAt == nil {
			t.Fatal("wrong token lost failure count", i, err)
		}
	}
	if f.access.RevokedAt == nil || f.audits[len(f.audits)-1].EntryType != "customer_portal_access.revoked_after_failed_access" {
		t.Fatal("fifth failed access did not revoke")
	}
	n := len(f.audits)
	if _, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{}, false); !errors.Is(err, application.ErrUnauthorized) || len(f.audits) != n {
		t.Fatal("revoked correct token still accesses", err)
	}
}
func TestPortalTokenCommandsRollbackAllLifecycleChanges(t *testing.T) {
	for _, phase := range []string{"update", "audit", "commit"} {
		for _, valid := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-valid-%t", phase, valid), func(t *testing.T) {
				c, f := newPortalTokenFixture(t)
				f.phase = phase
				token := f.secret
				if !valid {
					token = token[:len(token)-1] + "B"
				}
				v, err := c.AccessPortalPackage(t.Context(), token, PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false)
				if err == nil || v.ID != "" || f.access.NDAAcceptedAt != nil || f.access.AccessCount+f.access.FailedAccessCount != 0 || len(f.audits) != 1 {
					t.Fatal("failed access published committed effects", err)
				}
			})
		}
	}
	c, f := newPortalTokenFixture(t)
	f.pkg.ExpiresAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.AccessPortalPackage(t.Context(), f.secret, PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false); !errors.Is(err, ErrNotFound) || f.access.AccessCount != 0 {
		t.Fatal("expired package accessed", err)
	}
}
func TestPortalTokenTransitionRejectsImmutableChangesAndUnattestedNDA(t *testing.T) {
	_, f := newPortalTokenFixture(t)
	previous := ClonePortalAccess(f.access)
	at := time.Date(2026, 10, 3, 13, 0, 0, 0, time.UTC)
	current := ClonePortalAccess(previous)
	current.AccessCount++
	current.LastAccessedAt = &at
	if err := ValidatePortalTokenTransition(previous, current); err != nil {
		t.Fatal("valid access transition rejected", err)
	}
	for _, change := range []func(*packagedomain.CustomerPortalAccess){func(v *packagedomain.CustomerPortalAccess) { v.CustomerName = "other" }, func(v *packagedomain.CustomerPortalAccess) { v.Hash = strings.Repeat("b", 64) }, func(v *packagedomain.CustomerPortalAccess) { v.PackageID = "other" }, func(v *packagedomain.CustomerPortalAccess) { v.RequireNDA = false }, func(v *packagedomain.CustomerPortalAccess) { v.NDAAcceptedBy = "unattested" }, func(v *packagedomain.CustomerPortalAccess) { v.Watermark = "changed" }} {
		v := ClonePortalAccess(current)
		change(&v)
		if err := ValidatePortalTokenTransition(previous, v); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid lifecycle transition accepted", err)
		}
	}
}

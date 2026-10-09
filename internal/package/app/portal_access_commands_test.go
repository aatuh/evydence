package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var errPortalFixture = errors.New("private portal storage fault")

type portalCommandFixture struct {
	phase  string
	issued int
	access packagedomain.CustomerPortalAccess
	audits []application.AuditEvent
}

func (f *portalCommandFixture) ExecutePortalAccess(ctx context.Context, _ string, fn func(context.Context, PortalAccessTransaction) error) error {
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
func (f *portalCommandFixture) ReadPortalPackageScope(_ context.Context, tenant, id string) (PortalPackageScope, error) {
	s := PortalPackageScope{TenantID: tenant, PackageID: id, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release", CustomerPackageID: id}}
	if f.phase == "root" {
		return s, ErrNotFound
	}
	if f.phase == "forged-root" {
		s.TenantID = "other"
	}
	return s, nil
}
func (f *portalCommandFixture) ReadPortalAccessForRevocation(_ context.Context, tenant, id string) (packagedomain.CustomerPortalAccess, error) {
	if f.access.ID != id || f.access.TenantID != tenant {
		return packagedomain.CustomerPortalAccess{}, ErrNotFound
	}
	v := ClonePortalAccess(f.access)
	v.Hash = ""
	return v, nil
}
func (f *portalCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if !a.HasScope(r.Scope) || r.Scope != ScopePackageWrite || !r.ScopeOnly && a.UserID != "" && len(a.ResourceGrants) == 0 {
		return application.ErrForbidden
	}
	return ctx.Err()
}
func (f *portalCommandFixture) GeneratePortalCredential() (PortalCredential, error) {
	f.issued++
	if f.phase == "entropy" {
		return PortalCredential{}, errPortalFixture
	}
	secret := "evycp_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	v := PortalCredential{Secret: secret, Prefix: secret[:12], Hash: strings.Repeat("a", 64)}
	if f.phase == "credential" {
		v.Prefix = "forged"
	}
	return v, nil
}
func (f *portalCommandFixture) InsertPortalAccess(_ context.Context, v packagedomain.CustomerPortalAccess) error {
	if f.phase == "insert" {
		return errPortalFixture
	}
	f.access = ClonePortalAccess(v)
	return nil
}
func (f *portalCommandFixture) RevokePortalAccess(_ context.Context, _, _ string, at time.Time) error {
	if f.phase == "revoke" {
		return errPortalFixture
	}
	f.access.RevokedAt = &at
	return nil
}
func (f *portalCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errPortalFixture
	}
	f.audits = append(f.audits, v)
	return application.AuditReceipt{}, nil
}
func newPortalCommandFixture(t *testing.T) (*PortalAccessCommands, *portalCommandFixture, identitydomain.Actor, CreatePortalAccessInput) {
	t.Helper()
	f := &portalCommandFixture{}
	n := 0
	c, err := NewPortalAccessCommands(PortalAccessCommandConfig{Transactions: f, Credentials: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { n++; return fmt.Sprintf("%s-%d", prefix, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}, CreatePortalAccessInput{PackageID: " package ", CustomerName: " Customer\n ", ReviewerName: " Reviewer ", ReviewerEmail: " PERSON@EXAMPLE.TEST ", RequireNDA: true, ExpiresAt: time.Date(2026, 10, 4, 12, 0, 0, 123456789, time.UTC)}
}
func TestPortalCommandsAtomicIssuanceRevocationAndReadOnlyReplay(t *testing.T) {
	c, f, a, in := newPortalCommandFixture(t)
	if err := c.AuthorizeCreatePortalAccess(t.Context(), a, in); err != nil || f.issued != 0 || f.access.ID != "" || len(f.audits) != 0 {
		t.Fatal("replay guard minted or wrote", err)
	}
	v, secret, err := c.CreatePortalAccess(t.Context(), a, in)
	if err != nil || len(secret) != 49 || v.Hash != "" || len(f.access.Hash) != 64 || v.PackageID != "package" || v.CustomerName != "Customer" || v.ReviewerEmail != "person@example.test" || v.CreatedAt.Nanosecond() != 123456000 || v.ExpiresAt.Nanosecond() != 123456000 || v.Watermark != "Evydence package package for Reviewer <person@example.test> via access cpa-1." {
		t.Fatal("portal creation contract differs", err)
	}
	if len(f.audits) != 1 || f.audits[0].EntryType != "customer_portal_access.created" || f.audits[0].SubjectType != "customer_security_package" || f.audits[0].SubjectID != "package" || f.audits[0].ActorID != "key" || f.audits[0].PayloadHash != "" {
		t.Fatal("issuance audit differs")
	}
	v, err = c.RevokePortalAccess(t.Context(), a, v.ID)
	if err != nil || v.RevokedAt == nil || v.Hash != "" || len(f.audits) != 2 || f.audits[1].EntryType != "customer_portal_access.revoked" || f.audits[1].SubjectID != v.ID {
		t.Fatal("revocation contract differs", err)
	}
	*v.RevokedAt = time.Time{}
	if f.access.RevokedAt.IsZero() {
		t.Fatal("returned revocation aliases storage")
	}
	if _, err = c.RevokePortalAccess(t.Context(), a, v.ID); err != nil || len(f.audits) != 2 {
		t.Fatal("repeated revocation appends new audit", err)
	}
	a.UserID, a.KeyID = "user", ""
	if err = c.AuthorizeCreatePortalAccess(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("create replay ignores current package grant", err)
	}
	if err = c.AuthorizeRevokePortalAccess(t.Context(), a, v.ID); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revocation replay ignores current package grant", err)
	}
}
func TestPortalCommandsReturnNothingOnRollback(t *testing.T) {
	for _, phase := range []string{"root", "forged-root", "entropy", "credential", "insert", "audit", "commit"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := newPortalCommandFixture(t)
			f.phase = phase
			v, secret, err := c.CreatePortalAccess(t.Context(), a, in)
			if err == nil || secret != "" || !reflect.DeepEqual(v, packagedomain.CustomerPortalAccess{}) || f.access.ID != "" || len(f.audits) != 0 {
				t.Fatal("failed issuance published material", err)
			}
		})
	}
	for _, phase := range []string{"revoke", "audit", "commit"} {
		t.Run("revoke-"+phase, func(t *testing.T) {
			c, f, a, in := newPortalCommandFixture(t)
			v, _, err := c.CreatePortalAccess(t.Context(), a, in)
			if err != nil {
				t.Fatal(err)
			}
			f.phase = phase
			out, err := c.RevokePortalAccess(t.Context(), a, v.ID)
			if err == nil || !reflect.DeepEqual(out, packagedomain.CustomerPortalAccess{}) || f.access.RevokedAt != nil || len(f.audits) != 1 {
				t.Fatal("failed revocation changed committed state", err)
			}
		})
	}
}
func TestPortalInputBoundsAndFutureExpiry(t *testing.T) {
	for _, bad := range []CreatePortalAccessInput{{}, {PackageID: "x\x00", CustomerName: "Customer", ExpiresAt: time.Now()}, {PackageID: strings.Repeat(" ", 1025), CustomerName: "Customer", ExpiresAt: time.Now()}, {PackageID: "package", CustomerName: strings.Repeat("x", 641), ExpiresAt: time.Now()}, {PackageID: "package", CustomerName: "Customer", ReviewerEmail: "missing-at", ExpiresAt: time.Now()}, {PackageID: "package", CustomerName: "Customer", ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		if _, err := NormalizePortalAccessInput(bad); !errors.Is(err, ErrValidation) {
			t.Fatal("bad portal input accepted", err)
		}
	}
	c, f, a, in := newPortalCommandFixture(t)
	in.ExpiresAt = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	if err := c.AuthorizeCreatePortalAccess(t.Context(), a, in); err != nil {
		t.Fatal("expired completed replay rejected", err)
	}
	if _, _, err := c.CreatePortalAccess(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.issued != 0 {
		t.Fatal("expired fresh issuance minted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := c.CreatePortalAccess(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}

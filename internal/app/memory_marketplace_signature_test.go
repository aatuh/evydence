package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryMarketplaceCollectorAcceptsOnlyOwnedSignatureReferences(t *testing.T) {
	factory := NewMemoryUnitOfWorkFactory()
	ctx := t.Context()
	if err := ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repos Repositories) error {
		for _, tenant := range []string{"owner", "foreign"} {
			if err := repos.Identity.InsertTenant(ctx, domain.Tenant{ID: tenant, Name: tenant, CreatedAt: fixedNow()}); err != nil {
				return err
			}
			if err := repos.Signatures.InsertSigningKey(ctx, domain.SigningKey{ID: tenant + "-key", TenantID: tenant, KID: tenant, Algorithm: "Ed25519", Status: "active", PublicKey: "public", CreatedAt: fixedNow()}); err != nil {
				return err
			}
			if err := repos.Signatures.InsertSignature(ctx, domain.Signature{ID: tenant + "-signature", TenantID: tenant, KeyID: tenant + "-key", SubjectType: "package", SubjectID: tenant + "-package", Algorithm: "Ed25519", Value: "recorded", CreatedAt: fixedNow()}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, signature string
		want            error
	}{{"owned", "owner-signature", nil}, {"foreign", "foreign-signature", ErrNotFound}, {"missing", "missing-signature", ErrNotFound}, {"optional", "", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			v := domain.MarketplaceCollector{ID: "collector-" + tc.name, TenantID: "owner", Name: tc.name, Provider: "example", Version: "1", Publisher: "team", ManifestHash: "sha256:" + strings.Repeat("a", 64), SignatureID: tc.signature, State: "registered", SchemaVersion: domain.MarketplaceCollectorVersion, CreatedAt: fixedNow()}
			err = ExecuteUnitOfWork(ctx, factory, func(ctx context.Context, repos Repositories) error {
				return repos.Future.InsertMarketplaceCollector(ctx, v)
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("signature ownership error=%v, want %v", err, tc.want)
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if tc.want != nil {
				if !reflect.DeepEqual(before, after) {
					t.Fatal("rejected signature reference committed marketplace effects")
				}
			} else if len(after.MarketplaceCollectors) != len(before.MarketplaceCollectors)+1 || !reflect.DeepEqual(after.MarketplaceCollectors[v.ID], v) {
				t.Fatal("owned or optional signature reference did not persist the complete collector")
			}
		})
	}
}

package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type memorySigningAdminReader interface {
	ListLocalSigningKeysForUpdate(context.Context, string) ([]verificationdomain.SigningKey, error)
	GetSigningKeyForUpdate(context.Context, string, string) (verificationdomain.SigningKey, error)
	verificationapp.SigningKeyScopeLocker
}

func memorySigningAdminFixture(t *testing.T) (*memoryUnitOfWork, memorySigningAdminReader) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	r, ok := tx.Repositories().Signatures.(memorySigningAdminReader)
	if !ok {
		t.Fatal("memory signature repository lacks focused signing administration reads")
	}
	return tx, r
}

func TestMemorySigningAdministrationReadsOnlyCurrentOwnedPublicLifecycleAndDetachesDates(t *testing.T) {
	tx, r := memorySigningAdminFixture(t)
	for _, id := range []string{"b", "a"} {
		v := memorySigningKeyPageRecord(id)
		v.Private = []byte("private-must-not-be-exposed")
		tx.state.SigningKeys[id] = v
	}
	foreign := memorySigningKeyPageRecord("foreign")
	foreign.TenantID, foreign.Status = "foreign", "invalid"
	tx.state.SigningKeys[foreign.ID] = foreign
	external := memorySigningKeyPageRecord("external")
	external.Provider, external.Status = "aws_kms", "invalid"
	tx.state.SigningKeys[external.ID] = external
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.ListLocalSigningKeysForUpdate(t.Context(), "tenant")
	if err != nil || len(keys) != 2 || keys[0].ID != "a" || keys[1].ID != "b" || keys[0].RevocationReason != "reviewed" || keys[0].Version != 7 {
		t.Fatal("signing administration lost lifecycle or scope", err)
	}
	*keys[0].ValidUntil = fixedNow().Add(time.Hour)
	*keys[0].RevokedAt = fixedNow().Add(2 * time.Hour)
	*keys[0].CompromisedAt = fixedNow().Add(3 * time.Hour)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("signing metadata aliases private stored state")
	}
	key, err := r.GetSigningKeyForUpdate(t.Context(), "tenant", "b")
	if err != nil || key.ID != "b" || key.TenantID != "tenant" {
		t.Fatal("current key lookup failed", err)
	}
	if value, err := r.GetSigningKeyForUpdate(t.Context(), "tenant", foreign.ID); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(value, verificationdomain.SigningKey{}) {
		t.Fatal("foreign key metadata disclosed", err)
	}
	v := tx.state.SigningKeys["b"]
	v.Status, v.PublicKey = "invalid", strings.Repeat("unselected", 2000)
	tx.state.SigningKeys["b"] = v
	if err := r.LockSigningKeyScope(t.Context(), "tenant", "b"); err != nil {
		t.Fatal("ownership-only guard read lifecycle metadata", err)
	}
	if _, err := r.GetSigningKeyForUpdate(t.Context(), "tenant", "b"); !errors.Is(err, ErrConflict) {
		t.Fatal("fresh command accepted malformed lifecycle", err)
	}
}

func TestMemorySigningAdministrationRejectsOverflowCancellationAndClosedViewsWithoutPartialData(t *testing.T) {
	for _, mutate := range []func(*domain.SigningKey){
		func(k *domain.SigningKey) { k.ID = "different" },
		func(k *domain.SigningKey) { k.Version = 0 },
		func(k *domain.SigningKey) { k.PublicKey = strings.Repeat("x", 16385) },
		func(k *domain.SigningKey) { k.RevocationReason = strings.Repeat("x", 4097) },
		func(k *domain.SigningKey) { k.KID = "bad\x00text" },
	} {
		tx, r := memorySigningAdminFixture(t)
		v := memorySigningKeyPageRecord("key")
		mutate(&v)
		tx.state.SigningKeys["key"] = v
		if value, err := r.ListLocalSigningKeysForUpdate(t.Context(), "tenant"); !errors.Is(err, ErrConflict) || value != nil {
			t.Fatal("malformed key returned partial rotation metadata", err)
		}
	}
	tx, r := memorySigningAdminFixture(t)
	for i := range verificationapp.MaxSigningRotationKeys + 1 {
		v := memorySigningKeyPageRecord(fmt.Sprintf("key-%04d", i))
		tx.state.SigningKeys[v.ID] = v
	}
	if value, err := r.ListLocalSigningKeysForUpdate(t.Context(), "tenant"); !errors.Is(err, ErrConflict) || value != nil {
		t.Fatal("rotation row limit returned partial metadata", err)
	}
	tx.state.SigningKeys = map[string]domain.SigningKey{}
	for i := range 513 {
		v := memorySigningKeyPageRecord(fmt.Sprintf("key-%04d", i))
		v.PublicKey = strings.Repeat("x", 16384)
		tx.state.SigningKeys[v.ID] = v
	}
	if value, err := r.ListLocalSigningKeysForUpdate(t.Context(), "tenant"); !errors.Is(err, ErrConflict) || value != nil {
		t.Fatal("rotation byte limit returned partial metadata", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.LockSigningKeyScope(ctx, "tenant", "key"); !errors.Is(err, context.Canceled) {
		t.Fatal("ownership guard ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if value, err := r.ListLocalSigningKeysForUpdate(t.Context(), "tenant"); !errors.Is(err, ErrConflict) || value != nil {
		t.Fatal("closed key view returned metadata", err)
	}
}

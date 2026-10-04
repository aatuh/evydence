package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestPublicTransparencyMetadataLocalRequiresTenantWideHumanGrantAndSafeInput(t *testing.T) {
	l := NewLedger(Config{APIKeyPepper: "test"})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	in := CreatePublicTransparencyLogInput{Name: "public", Endpoint: "https://log.example.test", PublicKey: "pub"}
	human := a
	human.KeyID, human.UserID = "", "user"
	human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"keys:admin"}}}
	if v, err := l.CreatePublicTransparencyLog(t.Context(), human, in); !errors.Is(err, ErrForbidden) || v.ID != "" {
		t.Fatal("product grant configured tenant-wide log", v, err)
	}
	for _, bad := range []string{strings.Repeat(" ", 257) + "n", "x\x00", string([]byte{255})} {
		request := in
		request.Name = bad
		if v, err := l.CreatePublicTransparencyLog(t.Context(), a, request); !errors.Is(err, ErrValidation) || v.ID != "" {
			t.Fatal("unsafe log name accepted", err)
		}
	}
	for _, endpoint := range []string{"https://", "https://user:password@log.example.test", "https://log.example.test/#private"} {
		request := in
		request.Endpoint = endpoint
		if v, err := l.CreatePublicTransparencyLog(t.Context(), a, request); !errors.Is(err, ErrValidation) || v.ID != "" {
			t.Fatal("unsafe log endpoint recorded", endpoint, err)
		}
	}
}

func TestPublicTransparencyMetadataLocalPublicationRequiresCurrentTenant(t *testing.T) {
	l := NewLedger(Config{APIKeyPepper: "test"})
	_, _, secret, err := l.BootstrapTenant(t.Context(), "Tenant", "operator", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := l.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	log, err := l.CreatePublicTransparencyLog(t.Context(), a, CreatePublicTransparencyLogInput{Name: "public", Endpoint: "https://log.example.test", PublicKey: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := l.CreateMerkleBatch(t.Context(), a, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := l.CreateTransparencyCheckpoint(t.Context(), a, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal", ExternalID: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	delete(l.tenants, a.TenantID)
	if v, err := l.PublishPublicTransparencyLogEntry(t.Context(), a, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: cp.ID, ExternalID: "external"}); !errors.Is(err, ErrNotFound) || v.ID != "" || len(l.publicLogEntries) != 0 {
		t.Fatal("deleted tenant retained publication authority", v, err)
	}
}

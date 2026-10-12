package repositories

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestAuditVerificationDecodePreservesCanonicalJSONIntegers(t *testing.T) {
	e := domain.AuditChainEntry{ID: "entry", TenantID: "tenant", Sequence: 1, EntryType: "recorded", SubjectType: "product", SubjectID: "product", ActorType: "api_key", ActorID: "caller", Metadata: map[string]any{"number": json.Number("9007199254740993")}, SchemaVersion: domain.AuditChainEntrySchemaVersion}
	if err := app.RehashAuditChainEntry(&e); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAuditVerificationEntry(raw)
	if err != nil || decoded.Metadata["number"] != json.Number("9007199254740993") || !app.VerifyAuditChainEntryHash(decoded) {
		t.Fatal("native audit decoder rounded canonical metadata", err)
	}
	for _, bad := range []string{"null", "[]", "true", "{} {}", "{"} {
		if e, err := decodeAuditVerificationEntry([]byte(bad)); !errors.Is(err, app.ErrConflict) || !reflect.DeepEqual(e, domain.AuditChainEntry{}) {
			t.Fatal("invalid audit JSON exposed partial record", err)
		}
	}
}

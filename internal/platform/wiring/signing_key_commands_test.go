package wiring

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestPostgresSigningKeyCommandsAreAtomicTenantSafeAndSerialized(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Add(-time.Hour)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Keys'),('other','Other')`)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('old','tenant','old','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519'),('foreign','other','foreign','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519'),('hsm','tenant','hsm','Ed25519','active',$1,$2,$3,$3,99,'native_pkcs11_hsm')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), now)
	commands, err := BuildSigningKeyCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"keys:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"keys:admin"}}}}
	for _, input := range []struct{ id, reason string }{{"bad\x00id", "incident"}, {"old", "incident\x00reason"}} {
		if _, err := commands.RevokeSigningKey(ctx, actor, input.id, verificationapp.SigningKeyRevocationInput{Reason: input.reason}); !errors.Is(err, verificationapp.ErrValidation) {
			t.Fatal("invalid database text reached storage", err)
		}
	}
	for _, bad := range []identitydomain.Actor{{TenantID: "tenant", UserID: "user", Scopes: actor.Scopes, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: actor.Scopes}}}, {TenantID: "tenant", KeyID: "key", Scopes: []string{"verify:read"}}} {
		if _, err := commands.RotateSigningKey(ctx, bad, "denied"); !errors.Is(err, application.ErrForbidden) {
			t.Fatal("wrong scope/grant rotated", err)
		}
	}
	if _, err := commands.RevokeSigningKey(ctx, actor, "foreign", verificationapp.SigningKeyRevocationInput{Reason: "wrong tenant"}); !errors.Is(err, verificationapp.ErrNotFound) {
		t.Fatal(err)
	}
	key, err := commands.RotateSigningKey(ctx, actor, "scheduled")
	if err != nil || key.Version != 2 {
		t.Fatalf("key=%#v err=%v", key, err)
	}
	var status, hsmStatus string
	var material []byte
	if err := pool.QueryRow(ctx, `SELECT encrypted_private_key,(SELECT status FROM signing_keys WHERE id='old'),(SELECT status FROM signing_keys WHERE id='hsm') FROM signing_keys WHERE id=$1`, key.ID).Scan(&material, &status, &hsmStatus); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(material) != ed25519.PrivateKeySize || !ed25519.PublicKey(material[32:]).Equal(ed25519.PublicKey(decoded)) || status != "retiring" || hsmStatus != "active" {
		t.Fatal("rotation material/lifecycle mismatch", err)
	}
	clear(material)
	revoked, err := commands.RevokeSigningKey(ctx, actor, key.ID, verificationapp.SigningKeyRevocationInput{Reason: "incident", Semantics: "compromised", HistoricalValidityPolicy: "invalidate_all"})
	if err != nil || revoked.Status.String() != "revoked" || revoked.CompromisedAt == nil || revoked.HistoricalValidityPolicy != "invalidate_all" {
		t.Fatal("compromise semantics", err)
	}
	if _, err := commands.RevokeSigningKey(ctx, actor, key.ID, verificationapp.SigningKeyRevocationInput{Reason: "again"}); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := commands.RotateSigningKey(ctx, actor, "concurrent")
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("concurrent rotation failed", err)
		}
	}
	// The same serialization must work when no signing-key row exists yet.
	exec(`INSERT INTO tenants(id,name) VALUES('empty','Empty key set')`)
	emptyActor := identitydomain.Actor{TenantID: "empty", KeyID: "key", Scopes: []string{"keys:admin"}}
	emptyStart := make(chan struct{})
	emptyResults := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-emptyStart
			_, err := commands.RotateSigningKey(ctx, emptyActor, "first rotation")
			emptyResults <- err
		}()
	}
	close(emptyStart)
	for i := 0; i < 2; i++ {
		if err := <-emptyResults; err != nil {
			t.Fatal("empty-key-set concurrent rotation failed", err)
		}
	}
	var emptyActive, emptyKeys, emptyVersion int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='active'),count(*),max(version) FROM signing_keys WHERE tenant_id='empty'`).Scan(&emptyActive, &emptyKeys, &emptyVersion); err != nil || emptyActive != 1 || emptyKeys != 2 || emptyVersion != 2 {
		t.Fatalf("empty-key-set totals %d/%d/%d err=%v", emptyActive, emptyKeys, emptyVersion, err)
	}
	var active, local, audits int
	var maxVersion int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='active'),count(*),max(version),(SELECT count(*) FROM audit_chain_entries WHERE tenant_id='tenant') FROM signing_keys WHERE tenant_id='tenant' AND provider='local_ed25519'`).Scan(&active, &local, &maxVersion, &audits); err != nil || active != 1 || local != 4 || maxVersion != 4 || audits != 4 {
		t.Fatalf("rotation totals %d/%d/%d/%d err=%v", active, local, maxVersion, audits, err)
	}
	exec(`UPDATE signing_keys SET version=2147483647 WHERE id='old'`)
	if _, err := commands.RotateSigningKey(ctx, actor, "overflow"); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("version overflow", err)
	}
	exec(`UPDATE signing_keys SET version=1,revocation_reason=repeat('x',4097) WHERE id='old'`)
	if _, err := commands.RevokeSigningKey(ctx, actor, "old", verificationapp.SigningKeyRevocationInput{Reason: "oversize"}); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("oversized stored metadata", err)
	}
	exec(`UPDATE signing_keys SET revocation_reason='' WHERE id='old'`)
	exec(`CREATE FUNCTION reject_key_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit failure';END$$`)
	exec(`CREATE TRIGGER reject_key_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_key_audit()`)
	if result, err := commands.RotateSigningKey(ctx, actor, "rollback"); err == nil || result.ID != "" {
		t.Fatal("audit failure published rotation")
	}
	if result, err := commands.RevokeSigningKey(ctx, actor, "old", verificationapp.SigningKeyRevocationInput{Reason: "rollback"}); err == nil || result.ID != "" {
		t.Fatal("audit failure published revocation")
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE status='active'),count(*),max(version),(SELECT count(*) FROM audit_chain_entries WHERE tenant_id='tenant') FROM signing_keys WHERE tenant_id='tenant' AND provider='local_ed25519'`).Scan(&active, &local, &maxVersion, &audits); err != nil || active != 1 || local != 4 || maxVersion != 4 || audits != 4 {
		t.Fatal("rollback changed keys or audit", err)
	}
	exec(`DROP TRIGGER reject_key_audit ON audit_chain_entries`)
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,created_at,valid_from,version,provider) SELECT 'overflow_'||n,'tenant','overflow_'||n,'Ed25519','retiring',$1,$2,$2,n+4,'local_ed25519' FROM generate_series(1,$3) AS n`, base64.RawStdEncoding.EncodeToString(public), now, verificationapp.MaxSigningRotationKeys-3)
	if _, err := commands.RotateSigningKey(ctx, actor, "row overflow"); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("row overflow did not fail closed", err)
	}
}

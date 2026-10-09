package wiring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type bundleSignerHook struct {
	signer packageapp.PackageSigner
	after  func()
}

func (s bundleSignerHook) SignPackage(ctx context.Context, r packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	signature, err := s.signer.SignPackage(ctx, r)
	if err == nil {
		s.after()
	}
	return signature, err
}

type invalidBundleSigner struct{ signer packageapp.PackageSigner }

func (s invalidBundleSigner) SignPackage(ctx context.Context, r packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	signature, err := s.signer.SignPackage(ctx, r)
	signature.Value = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	return signature, err
}

func TestPostgresReleaseBundleCommandCommitsVerifiedSignatureAuditAndJob(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO tenants(id,name) VALUES('tenant','Bundle'),('other','Other')`)
	exec(`INSERT INTO products(id,tenant_id,name,slug) VALUES('product','tenant','Bundle','bundle'),('product_other','tenant','Other','other')`)
	exec(`INSERT INTO releases(id,tenant_id,product_id,version,state) VALUES('release','tenant','product','1.2.3','draft')`)
	exec(`INSERT INTO signing_keys(id,tenant_id,kid,algorithm,status,public_key,encrypted_private_key,created_at,valid_from,version,provider) VALUES('key','tenant','key','Ed25519','active',$1,$2,$3,$3,1,'local_ed25519')`, base64.RawStdEncoding.EncodeToString(public), []byte(private), now.Add(-time.Hour))
	commands, err := BuildReleaseBundleCommands(store, store, store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{"bundle:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"bundle:write"}}}}
	bundle, err := commands.CreateReleaseBundle(ctx, actor, "release")
	if err != nil {
		t.Fatal(err)
	}
	var signatureValue, auditRef, jobKind, jobHash string
	if err := pool.QueryRow(ctx, `SELECT s.value,a.signature_ref,j.kind,j.payload->>'manifest_hash' FROM signatures s JOIN audit_chain_entries a ON a.signature_ref=s.id JOIN outbox_jobs j ON j.subject_id=s.subject_id WHERE s.subject_id=$1`, bundle.ID).Scan(&signatureValue, &auditRef, &jobKind, &jobHash); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawStdEncoding.DecodeString(signatureValue)
	if err != nil || !ed25519.Verify(public, []byte(bundle.ManifestHash), decoded) || auditRef != bundle.SignatureRefs[0] || jobKind != "sign_bundle" || jobHash != bundle.ManifestHash {
		t.Fatal("signed durable effects mismatch", err)
	}
	for _, bad := range []identitydomain.Actor{
		{TenantID: "other", UserID: "user", Scopes: actor.Scopes, ResourceGrants: actor.ResourceGrants},
		{TenantID: "tenant", UserID: "user", Scopes: actor.Scopes, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product_other", Scopes: actor.Scopes}}},
		{TenantID: "tenant", UserID: "user", Scopes: []string{"bundle:read"}, ResourceGrants: actor.ResourceGrants},
	} {
		if _, err := commands.CreateReleaseBundle(ctx, bad, "release"); err == nil {
			t.Fatal("wrong actor generated bundle")
		}
	}
	// Invalidation after signing must be detected inside the write transaction.
	for _, mutation := range []string{
		`UPDATE signing_keys SET status='revoked' WHERE id='key'`,
		`UPDATE signing_keys SET valid_until=now()-interval '1 second' WHERE id='key'`,
		`UPDATE releases SET product_id='product_other' WHERE id='release'`,
	} {
		hooked, err := BuildReleaseBundleCommands(store, bundleSignerHook{store, func() { exec(mutation) }}, store)
		if err != nil {
			t.Fatal(err)
		}
		if result, err := hooked.CreateReleaseBundle(ctx, actor, "release"); err == nil || result.ID != "" {
			t.Fatalf("stale signing/scope committed: %#v %v", result, err)
		}
		exec(`UPDATE signing_keys SET status='active',valid_until=NULL WHERE id='key'`)
		exec(`UPDATE releases SET product_id='product' WHERE id='release'`)
	}
	invalid, err := BuildReleaseBundleCommands(store, invalidBundleSigner{store}, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.CreateReleaseBundle(ctx, actor, "release"); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal("invalid cryptographic signature accepted", err)
	}
	for _, mutation := range []string{
		`UPDATE signing_keys SET encrypted_private_key=decode('00','hex') WHERE id='key'`,
		`UPDATE signing_keys SET public_key='invalid-public-key' WHERE id='key'`,
		`UPDATE signing_keys SET valid_from=now()+interval '1 hour' WHERE id='key'`,
		`UPDATE signing_keys SET compromised_at=now() WHERE id='key'`,
	} {
		exec(mutation)
		if _, err := commands.CreateReleaseBundle(ctx, actor, "release"); !errors.Is(err, packageapp.ErrConflict) {
			t.Fatal("invalid key generated bundle", err)
		}
		exec(`UPDATE signing_keys SET public_key=$1,encrypted_private_key=$2,valid_from=$3,compromised_at=NULL WHERE id='key'`, base64.RawStdEncoding.EncodeToString(public), []byte(private), now.Add(-time.Hour))
	}
	exec(`CREATE FUNCTION reject_bundle_job() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced job failure';END$$`)
	exec(`CREATE TRIGGER reject_bundle_job BEFORE INSERT ON outbox_jobs FOR EACH ROW EXECUTE FUNCTION reject_bundle_job()`)
	if result, err := commands.CreateReleaseBundle(ctx, actor, "release"); err == nil || result.ID != "" {
		t.Fatal("job failure did not roll back", err)
	}
	var bundles, signatures, audits, jobs int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM release_bundles),(SELECT count(*) FROM signatures),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM outbox_jobs)`).Scan(&bundles, &signatures, &audits, &jobs); err != nil || bundles != 1 || signatures != 1 || audits != 1 || jobs != 1 {
		t.Fatalf("partial writes %d/%d/%d/%d err=%v", bundles, signatures, audits, jobs, err)
	}
	if _, err := store.SignPackage(ctx, packageapp.PackageSigningRequest{TenantID: "other", SubjectType: "release_bundle", SubjectID: "missing", PayloadHash: bundle.ManifestHash, CreatedAt: now}); !errors.Is(err, packageapp.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := commands.CreateReleaseBundle(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"bundle:read"}}, "release"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal(err)
	}
}

package wiring

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func importTestBundle(t *testing.T) packagedomain.EvidenceBundle {
	t.Helper()
	manifest := map[string]any{"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "tenant_id": "source_tenant", "evidence_ids": []string{"source_evidence"}, "private_input": "must-not-be-persisted", "numeric_metadata": json.Number("9007199254740993")}
	hash, err := application.NormalizedJSONHash(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return packagedomain.EvidenceBundle{TenantID: "source_tenant", EvidenceIDs: []string{"source_evidence"}, Manifest: manifest, ManifestHash: hash, SignatureRefs: []string{"untrusted_reference"}}
}

func TestBundleImportWiringPreservesMemoryRepositoryContract(t *testing.T) {
	memory := app.NewMemoryUnitOfWorkFactory()
	if err := app.ExecuteUnitOfWork(t.Context(), memory, func(ctx context.Context, repos app.Repositories) error {
		return repos.Identity.InsertTenant(ctx, domain.Tenant{ID: "ten_import", Name: "Import", CreatedAt: time.Now().UTC()})
	}); err != nil {
		t.Fatal(err)
	}
	commands, err := BuildBundleImportCommand(memory)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_import", KeyID: "key_import", Scopes: []string{"bundle:write"}}
	bundle := importTestBundle(t)
	receipt, err := commands.ImportEvidenceBundle(t.Context(), actor, bundle)
	if err != nil || receipt.ImportedCount != 1 || receipt.TenantID != actor.TenantID {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	state, err := memory.Snapshot()
	if err != nil || state.BundleImports[receipt.ID].BundleHash != bundle.ManifestHash || len(state.AuditEntries[actor.TenantID]) != 1 || len(state.Evidence) != 0 || len(state.EvidenceBundles) != 0 || len(state.Signatures) != 0 {
		t.Fatal("receipt command persisted other resources")
	}
	if _, err := BuildBundleImportCommand(nil); err == nil {
		t.Fatal("nil factory accepted")
	}
}

func TestPostgresBundleImportCommandCommitsOnlyReceiptAndAudit(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO tenants(id,name) VALUES('ten_import','Import'),('ten_other','Other')`)
	commands, err := BuildBundleImportCommand(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := identitydomain.Actor{TenantID: "ten_import", UserID: "user_import", Scopes: []string{"bundle:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_import", Scopes: []string{"bundle:write"}}}}
	bundle := importTestBundle(t)
	receipt, err := commands.ImportEvidenceBundle(ctx, actor, bundle)
	if err != nil || receipt.TenantID != actor.TenantID || receipt.ImportedCount != 1 || receipt.Result != "accepted" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	var storedHash, auditHash, storedTenant string
	if err := pool.QueryRow(ctx, `SELECT r.tenant_id,r.bundle_hash,a.payload_hash FROM evidence_bundle_imports r JOIN audit_chain_entries a ON a.tenant_id=r.tenant_id AND a.subject_id=r.id WHERE r.id=$1`, receipt.ID).Scan(&storedTenant, &storedHash, &auditHash); err != nil {
		t.Fatal(err)
	}
	if storedTenant != actor.TenantID || storedHash != bundle.ManifestHash || auditHash != storedHash {
		t.Fatal("receipt/audit mismatch")
	}
	for _, bad := range []identitydomain.Actor{
		{TenantID: "ten_other", UserID: actor.UserID, Scopes: actor.Scopes, ResourceGrants: actor.ResourceGrants},
		{TenantID: actor.TenantID, UserID: actor.UserID, Scopes: actor.Scopes, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "rel_1", Scopes: actor.Scopes}}},
		{TenantID: actor.TenantID, UserID: actor.UserID, Scopes: []string{"bundle:read"}, ResourceGrants: actor.ResourceGrants},
	} {
		if _, err := commands.ImportEvidenceBundle(ctx, bad, bundle); !errors.Is(err, application.ErrForbidden) {
			t.Fatalf("wrong actor err=%v", err)
		}
	}
	// Consistently hashed malformed input still must fail the manifest contract.
	duplicate := importTestBundle(t)
	duplicate.Manifest["evidence_ids"] = []string{"source_evidence", "source_evidence"}
	duplicate.ManifestHash, err = application.NormalizedJSONHash(duplicate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commands.ImportEvidenceBundle(ctx, actor, duplicate); !errors.Is(err, packageapp.ErrValidation) {
		t.Fatal("duplicate manifest was accepted")
	}
	exec(`CREATE FUNCTION reject_import_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'forced audit write failure';END$$`)
	exec(`CREATE TRIGGER reject_import_audit BEFORE INSERT ON audit_chain_entries FOR EACH ROW EXECUTE FUNCTION reject_import_audit()`)
	if receipt, err := commands.ImportEvidenceBundle(ctx, actor, bundle); err == nil || receipt.ID != "" {
		t.Fatalf("rollback receipt=%#v err=%v", receipt, err)
	}
	var imports, audits, other int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM evidence_bundle_imports),(SELECT count(*) FROM audit_chain_entries),(SELECT count(*) FROM evidence_items)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM evidence_bundles)`).Scan(&imports, &audits, &other); err != nil {
		t.Fatal(err)
	}
	if imports != 1 || audits != 1 || other != 0 {
		t.Fatalf("unexpected effects imports=%d audits=%d other=%d", imports, audits, other)
	}
}

package wiring

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func seedSubjectVerificationScopes(t *testing.T, p *pgxpool.Pool) *countedDSSEReader {
	t.Helper()
	objects := seedDSSEVerification(t, p, true)
	for _, sql := range []string{
		`INSERT INTO release_bundles(id,tenant_id,release_id,state,manifest,manifest_hash,signature_refs)VALUES('bundle','tenant','release','draft','{}','opaque','[]')`,
		`INSERT INTO merkle_batches(id,tenant_id,from_sequence,to_sequence,entry_count,leaf_hashes,root_hash,schema_version,created_at)VALUES('batch','tenant',1,1,1,'{}','opaque','merkle-batch.v1.0.0',now())`,
		`INSERT INTO artifact_signatures(id,tenant_id,artifact_id,subject_digest,algorithm,signature,verification_status,schema_version,created_at)VALUES('signature','tenant','artifact','opaque','Ed25519','opaque','pending','artifact-signature.v1.0.0',now())`,
		`INSERT INTO backup_manifests(id,tenant_id,state_hash,resource_counts,consistency_checks,schema_version,created_at)VALUES('backup','tenant','sha256:backup','{}','[{"name":"recorded","result":"passed"}]','backup-manifest.v1.0.0',now())`,
	} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	return objects
}

func TestPostgresSubjectVerificationScopeRejectsCurrentForeignOwnership(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedSubjectVerificationScopes(t, p)
	opts := subjectVerificationOptions(t, store, nil)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
	for _, tc := range []struct {
		table, id string
		subjects  []struct{ kind, id string }
		want      error
	}{
		{"products", "product", []struct{ kind, id string }{{"release_bundle", "bundle"}, {"audit_chain_release_manifest", "bundle"}}, verificationapp.ErrNotFound},
		{"releases", "release", []struct{ kind, id string }{{"release_bundle", "bundle"}, {"audit_chain_release_manifest", "bundle"}}, verificationapp.ErrNotFound},
		{"products", "product", []struct{ kind, id string }{{"evidence_item", "evidence"}, {"build_attestation", "attestation"}}, verificationapp.ErrConflict},
		{"projects", "project", []struct{ kind, id string }{{"evidence_item", "evidence"}, {"build_attestation", "attestation"}}, verificationapp.ErrConflict},
		{"releases", "release", []struct{ kind, id string }{{"evidence_item", "evidence"}, {"build_attestation", "attestation"}}, verificationapp.ErrConflict},
		{"build_runs", "build", []struct{ kind, id string }{{"evidence_item", "evidence"}, {"build_attestation", "attestation"}}, verificationapp.ErrConflict},
		{"evidence_items", "evidence", []struct{ kind, id string }{{"evidence_item", "evidence"}, {"build_attestation", "attestation"}}, verificationapp.ErrNotFound},
		{"build_attestations", "attestation", []struct{ kind, id string }{{"build_attestation", "attestation"}}, verificationapp.ErrNotFound},
		{"release_bundles", "bundle", []struct{ kind, id string }{{"release_bundle", "bundle"}, {"audit_chain_release_manifest", "bundle"}}, verificationapp.ErrNotFound},
		{"artifacts", "artifact", []struct{ kind, id string }{{"artifact_signature", "signature"}}, verificationapp.ErrNotFound},
		{"artifact_signatures", "signature", []struct{ kind, id string }{{"artifact_signature", "signature"}}, verificationapp.ErrNotFound},
		{"merkle_batches", "batch", []struct{ kind, id string }{{"merkle_batch", "batch"}, {"audit_chain_checkpoint", "batch"}}, verificationapp.ErrNotFound},
		{"backup_manifests", "backup", []struct{ kind, id string }{{"backup_manifest", "backup"}}, verificationapp.ErrNotFound},
	} {
		if _, err := p.Exec(t.Context(), "UPDATE "+tc.table+" SET tenant_id='other'WHERE id=$1", tc.id); err != nil {
			t.Fatal(err)
		}
		for _, subject := range tc.subjects {
			if err := opts.SubjectVerification.AuthorizeSubjectVerification(t.Context(), a, subject.kind, subject.id); !errors.Is(err, tc.want) {
				t.Fatal("foreign current ownership accepted", tc.table, subject, err, tc.want)
			}
		}
		if _, err := p.Exec(t.Context(), "UPDATE "+tc.table+" SET tenant_id='tenant'WHERE id=$1", tc.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE artifact_signatures SET artifact_id=repeat('x',1025)WHERE id='signature'`); err != nil {
		t.Fatal(err)
	}
	if err := opts.SubjectVerification.AuthorizeSubjectVerification(t.Context(), a, "artifact_signature", "signature"); !errors.Is(err, verificationapp.ErrConflict) {
		t.Fatal("oversized ownership coordinate accepted", err)
	}
	if dsseHTTPCounts(t, p) != [5]int{} {
		t.Fatal("ownership denials wrote effects")
	}
}

func subjectScopeCases() []struct {
	kind, id string
	refs     application.ResourceReferences
} {
	return []struct {
		kind, id string
		refs     application.ResourceReferences
	}{
		{"audit_chain", "", application.ResourceReferences{}},
		{"evidence_item", "evidence", application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}},
		{"release_bundle", "bundle", application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
		{"build_attestation", "attestation", application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}},
		{"artifact_signature", "signature", application.ResourceReferences{ArtifactID: "artifact"}},
		{"merkle_batch", "batch", application.ResourceReferences{}},
		{"audit_chain_checkpoint", "batch", application.ResourceReferences{}},
		{"audit_chain_release_manifest", "bundle", application.ResourceReferences{}},
		{"backup_manifest", "backup", application.ResourceReferences{}},
	}
}

func TestPostgresSubjectVerificationScopeReadsOnlyCurrentOwnership(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	objects := seedSubjectVerificationScopes(t, p)
	// All inspection metadata exceeds native inspection budgets. Ownership
	// resolution must neither select it nor perform a signature/payload check.
	for _, sql := range []string{
		`UPDATE build_attestations SET payload_ref=repeat('private-',1200000)`,
		`UPDATE evidence_items SET title=repeat('private-',1200000)`,
		`UPDATE release_bundles SET manifest=jsonb_build_object('private',repeat('x',9000000))`,
		`UPDATE merkle_batches SET root_hash=repeat('private-',1200000)`,
		`UPDATE artifact_signatures SET subject_digest=repeat('private-',1200000)`,
		`UPDATE backup_manifests SET consistency_checks=jsonb_build_array(jsonb_build_object('private',repeat('x',9000000)))`,
	} {
		if _, err := p.Exec(t.Context(), sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range subjectScopeCases() {
		t.Run(tc.kind, func(t *testing.T) {
			err := app.ExecuteUnitOfWork(t.Context(), store, func(ctx context.Context, repos app.Repositories) error {
				reader, ok := repos.Verification.(verificationapp.SubjectVerificationScopeReader)
				if !ok {
					t.Fatal("missing flat generic verification ownership reader")
				}
				subject, err := reader.ResolveSubjectVerificationScope(ctx, "tenant", tc.kind, tc.id)
				if err != nil || subject != (verificationapp.SubjectReference{TenantID: "tenant", Type: tc.kind, ID: tc.id, Resources: tc.refs}) {
					t.Fatal(subject, err)
				}
				if tc.kind != "audit_chain" {
					if _, err := reader.ResolveSubjectVerificationScope(ctx, "other", tc.kind, tc.id); !errors.Is(err, app.ErrNotFound) {
						t.Fatal("foreign subject visible", err)
					}
					if _, err := reader.ResolveSubjectVerificationScope(ctx, "tenant", tc.kind, "missing"); !errors.Is(err, app.ErrNotFound) {
						t.Fatal("missing subject resolved", err)
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	if objects.reads != 0 || dsseHTTPCounts(t, p) != [5]int{} {
		t.Fatal("read-only scope produced inspection/effects", objects.reads, dsseHTTPCounts(t, p))
	}
}

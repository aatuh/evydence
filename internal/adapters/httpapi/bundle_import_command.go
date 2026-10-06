package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

func decodeBundleImport(body []byte) (domain.EvidenceBundle, error) {
	var b domain.EvidenceBundle
	if err := decodeMembershipJSON(body, &b); err != nil {
		return b, err
	}
	if err := validateExactNonNullableObjectFields(body, "id", "tenant_id", "release_id", "evidence_ids", "manifest", "manifest_hash", "signature_refs", "verification_text", "schema_version", "created_at"); err != nil {
		return b, err
	}
	for _, field := range []string{"evidence_ids", "signature_refs"} {
		if err := validateNonNullableArrayItems(body, field); err != nil {
			return b, err
		}
	}
	return b, mapCustomerPackageAccessError(packageapp.ValidatePortableBundleInput(evidenceBundleForImport(b)))
}
func (s *Server) importEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in domain.EvidenceBundle
	if s.bundleImportCommand != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeBundleImport(body)
			if err != nil {
				return err
			}
			return mapCustomerPackageAccessError(s.bundleImportCommand.AuthorizeBundleImport(ctx, a, evidenceBundleForImport(in)))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.bundleImportCommand.ImportEvidenceBundle(ctx, a, evidenceBundleForImport(in))
			return 201, evidenceBundleImportFromCommands(v), mapCustomerPackageAccessError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.localBundleImport.ImportEvidenceBundle(ctx, a, in)
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeBundleImport(body)
		if err != nil {
			return nil, err
		}
		return body, s.localBundleImport.AuthorizeBundleImport(r.Context(), a, evidenceBundleForImport(in))
	})
}

func evidenceBundleForImport(value domain.EvidenceBundle) packagedomain.EvidenceBundle {
	return packagedomain.EvidenceBundle{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, EvidenceIDs: value.EvidenceIDs, Manifest: value.Manifest, ManifestHash: value.ManifestHash, SignatureRefs: value.SignatureRefs, VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}

func evidenceBundleFromCommands(value packagedomain.EvidenceBundle) domain.EvidenceBundle {
	return domain.EvidenceBundle{ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, EvidenceIDs: value.EvidenceIDs, Manifest: value.Manifest, ManifestHash: value.ManifestHash, SignatureRefs: value.SignatureRefs, VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt}
}
func evidenceBundleImportFromCommands(record packagedomain.EvidenceBundleImport) domain.EvidenceBundleImport {
	return domain.EvidenceBundleImport{ID: record.ID, TenantID: record.TenantID, BundleHash: record.BundleHash, Result: record.Result, ImportedCount: record.ImportedCount, SchemaVersion: record.SchemaVersion, CreatedAt: record.CreatedAt}
}

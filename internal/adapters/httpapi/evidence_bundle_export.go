package httpapi

import (
	"context"
	"net/http"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

type evidenceBundleExportRequest struct {
	ReleaseID   string   `json:"release_id"`
	EvidenceIDs []string `json:"evidence_ids"`
}

func decodeEvidenceBundleExport(body []byte) (evidenceBundleExportRequest, error) {
	var in evidenceBundleExportRequest
	if err := decodeMembershipJSON(body, &in); err != nil {
		return in, err
	}
	if err := validateExactNonNullableObjectFields(body, "release_id", "evidence_ids"); err != nil {
		return in, err
	}
	if err := validateNonNullableArrayItems(body, "evidence_ids"); err != nil {
		return in, err
	}
	var err error
	in.ReleaseID, in.EvidenceIDs, err = packageapp.NormalizeEvidenceBundleSelection(in.ReleaseID, in.EvidenceIDs)
	return in, mapCustomerPackageAccessError(err)
}

// Read only the saved public identity/selection, not its manifest metadata.
func evidenceBundleReplaySelection(a domain.Actor, in evidenceBundleExportRequest, response any) ([]string, error) {
	var tenant, release string
	var ids []string
	switch v := response.(type) {
	case domain.EvidenceBundle:
		tenant, release, ids = v.TenantID, v.ReleaseID, v.EvidenceIDs
	case map[string]any:
		var ok bool
		tenant, ok = v["tenant_id"].(string)
		if !ok {
			return nil, app.ErrConflict
		}
		if raw, exists := v["release_id"]; exists {
			release, ok = raw.(string)
			if !ok {
				return nil, app.ErrConflict
			}
		}
		switch values := v["evidence_ids"].(type) {
		case []string:
			ids = values
		case []any:
			if len(values) > packageapp.MaxBundleSnapshotRows {
				return nil, app.ErrConflict
			}
			for _, value := range values {
				str, ok := value.(string)
				if !ok {
					return nil, app.ErrConflict
				}
				ids = append(ids, str)
			}
		default:
			return nil, app.ErrConflict
		}
	default:
		return nil, app.ErrConflict
	}
	if tenant != a.TenantID || release != in.ReleaseID {
		return nil, app.ErrConflict
	}
	_, ids, err := packageapp.NormalizeEvidenceBundleSelection(release, ids)
	if err != nil || len(in.EvidenceIDs) > 0 && !slices.Equal(in.EvidenceIDs, ids) {
		return nil, app.ErrConflict
	}
	return ids, nil
}

func (s *Server) exportEvidenceBundle(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in evidenceBundleExportRequest
	if s.evidenceBundleCommands != nil {
		s.executeDurableCreate(w, r, app.SmallJSONRequestLimit, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeEvidenceBundleExport(body)
			if err != nil {
				return err
			}
			return mapCustomerPackageAccessError(s.evidenceBundleCommands.AuthorizeEvidenceBundleExport(ctx, a, in.ReleaseID, in.EvidenceIDs))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.evidenceBundleCommands.ExportEvidenceBundle(ctx, a, in.ReleaseID, in.EvidenceIDs)
			return http.StatusCreated, evidenceBundleFromCommands(v), mapCustomerPackageAccessError(err)
		}, nil, nil, func(ctx context.Context, a domain.Actor, response any) error {
			ids, err := evidenceBundleReplaySelection(a, in, response)
			if err != nil {
				return err
			}
			return mapCustomerPackageAccessError(s.evidenceBundleCommands.AuthorizeEvidenceBundleReplay(ctx, a, in.ReleaseID, ids))
		})
		return
	}
	// Local memory has no durable ownership transaction. Guard the request and
	// saved response explicitly; it cannot serve production composition.
	s.createWithActorFingerprintAndResponseGuard(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.localEvidenceBundles.ExportEvidenceBundle(ctx, a, in.ReleaseID, in.EvidenceIDs)
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeEvidenceBundleExport(body)
		if err != nil {
			return nil, err
		}
		return body, s.localEvidenceBundles.AuthorizeEvidenceBundleExport(r.Context(), a, in.ReleaseID, in.EvidenceIDs)
	}, func(ctx context.Context, a domain.Actor, response any) error {
		ids, err := evidenceBundleReplaySelection(a, in, response)
		if err != nil {
			return err
		}
		return s.localEvidenceBundles.AuthorizeEvidenceBundleExport(ctx, a, in.ReleaseID, ids)
	})
}

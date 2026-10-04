package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func decodeReleaseBundleCreationRequest(body []byte) (string, error) {
	var req struct {
		ReleaseID string `json:"release_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return "", err
	}
	if err := validateExactNonNullableObjectFields(body, "release_id"); err != nil {
		return "", err
	}
	id, err := packageapp.NormalizeReleaseBundleID(req.ReleaseID)
	return id, mapCustomerPackageAccessError(err)
}

func releaseBundleCreationSchema() map[string]any {
	v := objectSchema(map[string]any{
		"release_id": map[string]any{"type": "string", "minLength": 1, "maxLength": packageapp.MaxProductReleaseIDBytes, "description": "Nonblank current tenant-owned release ID; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
	}, "release_id")
	v["description"] = "Creates a signed release evidence bundle; it does not establish legal compliance, complete evidence or a secure release. Native PostgreSQL execution checks current release/product access before reservation and every replay, using flat share locks after the tenant fence. Bundle, signature, audit, worker job and successful replay commit together without a Ledger clone. Replay does not read manifest inputs or signing-key material and does not sign again. Both profiles reject unknown, duplicate, case-aliased, explicitly null, invalid UTF-8/NUL or over-budget fields; the whole JSON body is capped at 64 KiB. Unsafe cookie writes require same-origin protection. Local memory retains explicit nondurable compatibility storage."
	return v
}

func (s *Server) createReleaseBundleCommand(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.releaseBundleCommands != nil {
		var id string
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			id, err = decodeReleaseBundleCreationRequest(body)
			if err != nil {
				return err
			}
			return mapCustomerPackageAccessError(s.releaseBundleCommands.AuthorizeReleaseBundleCreation(ctx, a, id))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.releaseBundleCommands.CreateReleaseBundle(ctx, a, id)
			return http.StatusCreated, releaseBundleFromQuery(v), mapCustomerPackageAccessError(err)
		})
		return
	}
	// Only explicit local memory uses the nondurable compatibility store.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		id, err := decodeReleaseBundleCreationRequest(body)
		if err != nil {
			return 0, nil, err
		}
		v, err := s.packages.CreateReleaseBundle(ctx, a, id)
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		id, err := decodeReleaseBundleCreationRequest(body)
		if err != nil {
			return nil, err
		}
		return body, s.ledger.AuthorizeReleaseBundleCreation(r.Context(), a, id)
	})
}

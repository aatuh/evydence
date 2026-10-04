package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

func validateBackupGenerationRequest(body []byte) error {
	if err := decodeMembershipJSON(body, &struct{}{}); err != nil {
		return err
	}
	return validateExactNonNullableObjectFields(body)
}

func (s *Server) generateBackupManifest(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if s.backupGenerationCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			if err := validateBackupGenerationRequest(body); err != nil {
				return err
			}
			return mapSigningKeyCommandError(s.backupGenerationCommands.AuthorizeBackupGeneration(ctx, a))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.backupGenerationCommands.GenerateBackupManifest(ctx, a)
			return http.StatusCreated, domain.BackupManifestFromContextModel(v), mapSigningKeyCommandError(err)
		})
		return
	}
	// Only explicit local memory retains its distinct v1 whole-state hash.
	// The native path never binds or reloads that compatibility aggregate.
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, body []byte) (int, any, error) {
		if err := validateBackupGenerationRequest(body); err != nil {
			return 0, nil, err
		}
		v, err := s.verification.GenerateBackupManifest(ctx, a)
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := validateBackupGenerationRequest(body); err != nil {
			return nil, err
		}
		return body, mapSigningKeyCommandError(application.AuthorizeTenantWideScope(r.Context(), a, app.ScopeAdmin))
	})
}

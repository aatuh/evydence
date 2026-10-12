package httpapi

import (
	"context"
	"net/http"

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
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := validateBackupGenerationRequest(body); err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.backupGenerationCommands.AuthorizeBackupGeneration(ctx, a))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.backupGenerationCommands.GenerateBackupManifest(ctx, a)
		return http.StatusCreated, domain.BackupManifestFromContextModel(v), mapSigningKeyCommandError(err)
	})
}

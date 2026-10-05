package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func decodeCandidateCreation(body []byte) (releaseapp.CreateReleaseCandidateInput, error) {
	var req struct {
		ReleaseID   string   `json:"release_id"`
		Name        string   `json:"name"`
		BuildIDs    []string `json:"build_ids"`
		ArtifactIDs []string `json:"artifact_ids"`
		SBOMIDs     []string `json:"sbom_ids"`
		ScanIDs     []string `json:"scan_ids"`
		VEXIDs      []string `json:"vex_ids"`
		ContractIDs []string `json:"contract_ids"`
		BundleIDs   []string `json:"bundle_ids"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CreateReleaseCandidateInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "release_id", "name", "build_ids", "artifact_ids", "sbom_ids", "scan_ids", "vex_ids", "contract_ids", "bundle_ids"); err != nil {
		return releaseapp.CreateReleaseCandidateInput{}, err
	}
	for _, field := range []string{"build_ids", "artifact_ids", "sbom_ids", "scan_ids", "vex_ids", "contract_ids", "bundle_ids"} {
		if err := validateNonNullableArrayItems(body, field); err != nil {
			return releaseapp.CreateReleaseCandidateInput{}, err
		}
	}
	in := releaseapp.CreateReleaseCandidateInput{ReleaseID: req.ReleaseID, Name: req.Name, BuildIDs: req.BuildIDs, ArtifactIDs: req.ArtifactIDs, SBOMIDs: req.SBOMIDs, ScanIDs: req.ScanIDs, VEXIDs: req.VEXIDs, ContractIDs: req.ContractIDs, BundleIDs: req.BundleIDs}
	_, err := releaseapp.NormalizeCandidateCreationInput(in)
	return in, mapBuildAttestationCommandError(err)
}
func candidateLocalInput(in releaseapp.CreateReleaseCandidateInput) app.CreateReleaseCandidateInput {
	return app.CreateReleaseCandidateInput{ReleaseID: in.ReleaseID, Name: in.Name, BuildIDs: in.BuildIDs, ArtifactIDs: in.ArtifactIDs, SBOMIDs: in.SBOMIDs, ScanIDs: in.ScanIDs, VEXIDs: in.VEXIDs, ContractIDs: in.ContractIDs, BundleIDs: in.BundleIDs}
}
func (s *Server) createReleaseCandidate(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CreateReleaseCandidateInput
	if s.candidateCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeCandidateCreation(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.candidateCommands.AuthorizeCandidateCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.candidateCommands.CreateReleaseCandidate(ctx, a, in)
			return http.StatusCreated, releaseCandidateFromQuery(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.CreateReleaseCandidate(ctx, a, candidateLocalInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeCandidateCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeCandidateCreation(r.Context(), a, in)
	})
}

package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func decodeArtifactRegistration(body []byte) (releaseapp.RegisterArtifactInput, error) {
	var req struct {
		Name      string `json:"name"`
		MediaType string `json:"media_type"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.RegisterArtifactInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "media_type", "digest", "size"); err != nil {
		return releaseapp.RegisterArtifactInput{}, err
	}
	in := releaseapp.RegisterArtifactInput{Name: req.Name, MediaType: req.MediaType, Digest: req.Digest, Size: req.Size}
	_, err := releaseapp.NormalizeArtifactRegistrationInput(in)
	return in, mapBuildAttestationCommandError(err)
}
func decodeContainerImageRegistration(body []byte) (releaseapp.RegisterContainerImageInput, error) {
	var req struct {
		ArtifactID string `json:"artifact_id"`
		Repository string `json:"repository"`
		Tag        string `json:"tag"`
		Digest     string `json:"digest"`
		Platform   string `json:"platform"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.RegisterContainerImageInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "artifact_id", "repository", "tag", "digest", "platform"); err != nil {
		return releaseapp.RegisterContainerImageInput{}, err
	}
	in := releaseapp.RegisterContainerImageInput{ArtifactID: req.ArtifactID, Repository: req.Repository, Tag: req.Tag, Digest: req.Digest, Platform: req.Platform}
	_, err := releaseapp.NormalizeContainerImageRegistrationInput(in)
	return in, mapBuildAttestationCommandError(err)
}
func (s *Server) registerArtifact(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.RegisterArtifactInput
	if s.artifactCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeArtifactRegistration(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.artifactCommands.AuthorizeArtifactRegistration(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.artifactCommands.RegisterArtifact(ctx, a, in)
			return 201, artifactFromQuery(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.RegisterArtifact(ctx, a, in.Name, in.MediaType, in.Digest, in.Size)
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeArtifactRegistration(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeArtifactRegistration(r.Context(), a, in)
	})
}
func (s *Server) registerContainerImage(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.RegisterContainerImageInput
	if s.containerImageCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeContainerImageRegistration(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.containerImageCommands.AuthorizeContainerImageRegistration(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.containerImageCommands.RegisterContainerImage(ctx, a, in)
			return 201, containerImageFromCommand(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.RegisterContainerImage(ctx, a, app.RegisterContainerImageInput{ArtifactID: in.ArtifactID, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest, Platform: in.Platform})
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeContainerImageRegistration(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeContainerImageRegistration(r.Context(), a, in)
	})
}

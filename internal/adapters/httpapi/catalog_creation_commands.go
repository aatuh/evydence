package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func decodeProductCreation(body []byte) (releaseapp.CreateProductInput, error) {
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CreateProductInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "slug"); err != nil {
		return releaseapp.CreateProductInput{}, err
	}
	in := releaseapp.CreateProductInput{Name: req.Name, Slug: req.Slug}
	_, err := releaseapp.NormalizeProductCreationInput(in)
	return in, mapBuildAttestationCommandError(err)
}
func decodeProjectCreation(body []byte) (releaseapp.CreateProjectInput, error) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CreateProjectInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "name"); err != nil {
		return releaseapp.CreateProjectInput{}, err
	}
	in := releaseapp.CreateProjectInput{ProductID: req.ProductID, Name: req.Name}
	_, err := releaseapp.NormalizeProjectCreationInput(in)
	return in, mapBuildAttestationCommandError(err)
}
func decodeReleaseCreation(body []byte) (releaseapp.CreateReleaseInput, error) {
	var req struct {
		ProductID string `json:"product_id"`
		Version   string `json:"version"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CreateReleaseInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "version"); err != nil {
		return releaseapp.CreateReleaseInput{}, err
	}
	in := releaseapp.CreateReleaseInput{ProductID: req.ProductID, Version: req.Version}
	_, err := releaseapp.NormalizeReleaseCreationInput(in)
	return in, mapBuildAttestationCommandError(err)
}

func (s *Server) createProduct(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CreateProductInput
	if s.productCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeProductCreation(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.productCommands.AuthorizeProductCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.productCommands.CreateProduct(ctx, a, in)
			return 201, productFromCommand(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.CreateProduct(ctx, a, in.Name, in.Slug)
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeProductCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeProductCreation(r.Context(), a, in)
	})
}
func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CreateProjectInput
	if s.projectCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeProjectCreation(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.projectCommands.AuthorizeProjectCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.projectCommands.CreateProject(ctx, a, in)
			return 201, projectFromCommand(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.CreateProject(ctx, a, in.ProductID, in.Name)
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeProjectCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeProjectCreation(r.Context(), a, in)
	})
}
func (s *Server) createRelease(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CreateReleaseInput
	if s.releaseCreationCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeReleaseCreation(body)
			if err != nil {
				return err
			}
			return mapBuildAttestationCommandError(s.releaseCreationCommands.AuthorizeReleaseCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.releaseCreationCommands.CreateRelease(ctx, a, in)
			return 201, releaseFromCommand(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.CreateRelease(ctx, a, in.ProductID, in.Version)
		return 201, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeReleaseCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.releaseCatalog.AuthorizeReleaseCreation(r.Context(), a, in)
	})
}

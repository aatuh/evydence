package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func decodeSigningProviderRequest(body []byte) (verificationapp.CreateSigningProviderInput, error) {
	var req struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		KeyRef    string `json:"key_ref"`
		Encrypted bool   `json:"encrypted"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.CreateSigningProviderInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "type", "key_ref", "encrypted"); err != nil {
		return verificationapp.CreateSigningProviderInput{}, err
	}
	in, err := verificationapp.NormalizeSigningProviderInput(verificationapp.CreateSigningProviderInput{Name: req.Name, Type: req.Type, KeyRef: req.KeyRef, Encrypted: req.Encrypted})
	return in, mapSigningKeyCommandError(err)
}

func decodeDSSETrustRootRequest(body []byte) (verificationapp.CreateDSSETrustRootInput, error) {
	var req struct {
		Name                  string   `json:"name"`
		KeyID                 string   `json:"key_id"`
		Algorithm             string   `json:"algorithm"`
		PublicKey             string   `json:"public_key"`
		AllowedPredicateTypes []string `json:"allowed_predicate_types"`
		ExpectedBuilderIDs    []string `json:"expected_builder_ids"`
		RequiredClaims        []string `json:"required_claims"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return verificationapp.CreateDSSETrustRootInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "key_id", "algorithm", "public_key", "allowed_predicate_types", "expected_builder_ids", "required_claims"); err != nil {
		return verificationapp.CreateDSSETrustRootInput{}, err
	}
	for _, field := range []string{"allowed_predicate_types", "expected_builder_ids", "required_claims"} {
		if err := validateNonNullableArrayItems(body, field); err != nil {
			return verificationapp.CreateDSSETrustRootInput{}, err
		}
	}
	in, err := verificationapp.NormalizeDSSETrustRootInput(verificationapp.CreateDSSETrustRootInput{Name: req.Name, KeyID: req.KeyID, Algorithm: req.Algorithm, PublicKey: req.PublicKey, AllowedPredicateTypes: req.AllowedPredicateTypes, ExpectedBuilderIDs: req.ExpectedBuilderIDs, RequiredClaims: req.RequiredClaims})
	return in, mapSigningKeyCommandError(err)
}

func (s *Server) createSigningProvider(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateSigningProviderInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSigningProviderRequest(body)
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.trustConfigurationCommands.AuthorizeTrustConfiguration(ctx, a))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.trustConfigurationCommands.CreateSigningProvider(ctx, a, in)
		return http.StatusCreated, domain.SigningProviderFromContextModel(v), mapSigningKeyCommandError(err)
	})
}

func (s *Server) createDSSETrustRoot(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in verificationapp.CreateDSSETrustRootInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeDSSETrustRootRequest(body)
		if err != nil {
			return err
		}
		return mapSigningKeyCommandError(s.trustConfigurationCommands.AuthorizeTrustConfiguration(ctx, a))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.trustConfigurationCommands.CreateDSSETrustRoot(ctx, a, in)
		return http.StatusCreated, domain.DSSETrustRootFromContextModel(v), mapSigningKeyCommandError(err)
	})
}

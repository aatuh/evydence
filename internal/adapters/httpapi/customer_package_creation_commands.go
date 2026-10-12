package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// CustomerPackageCreationCommands can authorize and freeze one public package;
// it exposes neither Ledger state nor other context services to the handler.
type CustomerPackageCreationCommands interface {
	AuthorizeCreateCustomerSecurityPackage(context.Context, identitydomain.Actor, packageapp.CreateCustomerPackageInput) error
	CreateCustomerSecurityPackage(context.Context, identitydomain.Actor, packageapp.CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error)
}

func decodeCustomerPackageCreationRequest(body []byte) (packageapp.CreateCustomerPackageInput, error) {
	var req struct {
		ProductID          string    `json:"product_id"`
		ReleaseID          string    `json:"release_id"`
		RedactionProfileID string    `json:"redaction_profile_id"`
		Title              string    `json:"title"`
		ExpiresAt          time.Time `json:"expires_at"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateCustomerPackageInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "release_id", "redaction_profile_id", "title", "expires_at"); err != nil {
		return packageapp.CreateCustomerPackageInput{}, err
	}
	in, err := packageapp.NormalizeCustomerPackageInput(packageapp.CreateCustomerPackageInput{ProductID: req.ProductID, ReleaseID: req.ReleaseID, RedactionProfileID: req.RedactionProfileID, Title: req.Title, ExpiresAt: req.ExpiresAt})
	return in, mapCustomerPackageAccessError(err)
}

func (s *Server) createCustomerPackage(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	s.createDurableCustomerPackage(w, r)
}

func (s *Server) createDurableCustomerPackage(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateCustomerPackageInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeCustomerPackageCreationRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.customerPackageCreationCommands.AuthorizeCreateCustomerSecurityPackage(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.customerPackageCreationCommands.CreateCustomerSecurityPackage(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		return http.StatusCreated, customerPackageFromAccess(v), nil
	})
}

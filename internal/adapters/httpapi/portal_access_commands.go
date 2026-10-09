package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type PortalAccessCommands interface {
	AuthorizeCreatePortalAccess(context.Context, identitydomain.Actor, packageapp.CreatePortalAccessInput) error
	AuthorizeRevokePortalAccess(context.Context, identitydomain.Actor, string) error
	CreatePortalAccess(context.Context, identitydomain.Actor, packageapp.CreatePortalAccessInput) (packagedomain.CustomerPortalAccess, string, error)
	RevokePortalAccess(context.Context, identitydomain.Actor, string) (packagedomain.CustomerPortalAccess, error)
}
type PortalTokenCommands interface {
	AccessPortalPackage(context.Context, string, packageapp.PortalAcceptanceInput, bool) (packagedomain.CustomerSecurityPackage, error)
}
type portalTokenRequest struct {
	Token         string `json:"token"`
	NDAAccepted   bool   `json:"nda_accepted"`
	NDAAcceptedBy string `json:"nda_accepted_by"`
}

func decodePortalTokenRequest(body []byte) (portalTokenRequest, error) {
	var in portalTokenRequest
	if err := decodeMembershipJSON(body, &in); err != nil {
		return in, err
	}
	if err := validateExactNonNullableObjectFields(body, "token", "nda_accepted", "nda_accepted_by"); err != nil {
		return in, err
	}
	v, err := packageapp.NormalizePortalAcceptanceInput(packageapp.PortalAcceptanceInput{NDAAccepted: in.NDAAccepted, NDAAcceptedBy: in.NDAAcceptedBy})
	in.NDAAcceptedBy = v.NDAAcceptedBy
	return in, mapCustomerPackageAccessError(err)
}
func (s *Server) portalPackage(ctx context.Context, token string, in packageapp.PortalAcceptanceInput) (domain.CustomerSecurityPackage, error) {
	v, err := s.portalTokenCommands.AccessPortalPackage(ctx, token, in, false)
	if err != nil {
		return domain.CustomerSecurityPackage{}, mapCustomerPackageAccessError(err)
	}
	return customerPackageFromAccess(v), nil
}
func (s *Server) portalArchive(ctx context.Context, token string, in packageapp.PortalAcceptanceInput) (app.CustomerPackageArchive, error) {
	v, err := s.portalTokenCommands.AccessPortalPackage(ctx, token, in, true)
	if err != nil {
		return app.CustomerPackageArchive{}, mapCustomerPackageAccessError(err)
	}
	return app.RenderCustomerPackageArchive(customerPackageFromAccess(v))
}
func decodePortalAccessRequest(body []byte) (packageapp.CreatePortalAccessInput, error) {
	var in struct {
		PackageID     string    `json:"package_id"`
		CustomerName  string    `json:"customer_name"`
		ReviewerName  string    `json:"reviewer_name"`
		ReviewerEmail string    `json:"reviewer_email"`
		RequireNDA    bool      `json:"require_nda"`
		Watermark     string    `json:"watermark"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if err := decodeMembershipJSON(body, &in); err != nil {
		return packageapp.CreatePortalAccessInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "package_id", "customer_name", "reviewer_name", "reviewer_email", "require_nda", "watermark", "expires_at"); err != nil {
		return packageapp.CreatePortalAccessInput{}, err
	}
	v, err := packageapp.NormalizePortalAccessInput(packageapp.CreatePortalAccessInput{PackageID: in.PackageID, CustomerName: in.CustomerName, ReviewerName: in.ReviewerName, ReviewerEmail: in.ReviewerEmail, RequireNDA: in.RequireNDA, Watermark: in.Watermark, ExpiresAt: in.ExpiresAt})
	return v, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurablePortalAccess(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreatePortalAccessInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePortalAccessRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.portalAccessCommands.AuthorizeCreatePortalAccess(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, secret, err := s.portalAccessCommands.CreatePortalAccess(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		return http.StatusCreated, map[string]any{"access": portalAccessFromQuery(v), "secret": secret}, nil
	})
}
func (s *Server) revokeDurablePortalAccess(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, _ []byte) error {
		return mapCustomerPackageAccessError(s.portalAccessCommands.AuthorizeRevokePortalAccess(ctx, a, id))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.portalAccessCommands.RevokePortalAccess(ctx, a, id)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		return http.StatusOK, portalAccessFromQuery(v), nil
	})
}

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type QuestionnairePackageCommands interface {
	AuthorizeCreateQuestionnairePackage(context.Context, identitydomain.Actor, packageapp.CreateQuestionnairePackageInput) error
	CreateQuestionnairePackage(context.Context, identitydomain.Actor, packageapp.CreateQuestionnairePackageInput) (packagedomain.QuestionnairePackage, error)
}

func decodeQuestionnairePackageRequest(body []byte) (packageapp.CreateQuestionnairePackageInput, error) {
	var req struct {
		TemplateID string `json:"template_id"`
		PackageID  string `json:"package_id"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateQuestionnairePackageInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "template_id", "package_id", "product_id", "release_id"); err != nil {
		return packageapp.CreateQuestionnairePackageInput{}, err
	}
	in, err := packageapp.NormalizeQuestionnairePackageInput(packageapp.CreateQuestionnairePackageInput{TemplateID: req.TemplateID, PackageID: req.PackageID, ProductID: req.ProductID, ReleaseID: req.ReleaseID})
	return in, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurableQuestionnairePackage(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateQuestionnairePackageInput
	s.createDurableWithFingerprint(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeQuestionnairePackageRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.questionnairePackageCommands.AuthorizeCreateQuestionnairePackage(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.questionnairePackageCommands.CreateQuestionnairePackage(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		encoded, err := packageapp.EncodeQuestionnairePackage(v)
		return http.StatusCreated, json.RawMessage(encoded), err
	}, nil, questionnairePackageReplayFingerprint)
}
func questionnairePackageReplayFingerprint(a domain.Actor, body []byte) ([]byte, error) {
	return questionnaireReplayFingerprint(a, body, "questionnaire-package-permissions-v1")
}

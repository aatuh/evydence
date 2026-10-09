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

type QuestionnaireTemplateCommands interface {
	AuthorizeCreateQuestionnaireTemplate(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireTemplateInput) error
	CreateQuestionnaireTemplate(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireTemplateInput) (packagedomain.QuestionnaireTemplate, error)
}

func decodeQuestionnaireTemplateRequest(body []byte) (packageapp.CreateQuestionnaireTemplateInput, error) {
	var req struct {
		Name      string                         `json:"name"`
		Version   string                         `json:"version"`
		Questions []domain.QuestionnaireQuestion `json:"questions"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateQuestionnaireTemplateInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "version", "questions"); err != nil {
		return packageapp.CreateQuestionnaireTemplateInput{}, err
	}
	var raw struct {
		Questions []json.RawMessage `json:"questions"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return packageapp.CreateQuestionnaireTemplateInput{}, err
	}
	for _, q := range raw.Questions {
		if err := validateExactNonNullableObjectFields(q, "id", "prompt", "evidence_type", "control_id", "allowed_fields"); err != nil {
			return packageapp.CreateQuestionnaireTemplateInput{}, err
		}
		if err := validateNonNullableArrayItems(q, "allowed_fields"); err != nil {
			return packageapp.CreateQuestionnaireTemplateInput{}, err
		}
	}
	qs := make([]packagedomain.QuestionnaireQuestion, len(req.Questions))
	for i, q := range req.Questions {
		qs[i] = packagedomain.QuestionnaireQuestion{ID: q.ID, Prompt: q.Prompt, EvidenceType: q.EvidenceType, ControlID: q.ControlID, AllowedFields: q.AllowedFields}
	}
	in, err := packageapp.NormalizeQuestionnaireTemplateInput(packageapp.CreateQuestionnaireTemplateInput{Name: req.Name, Version: req.Version, Questions: qs})
	return in, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurableQuestionnaireTemplate(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateQuestionnaireTemplateInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeQuestionnaireTemplateRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.questionnaireTemplateCommands.AuthorizeCreateQuestionnaireTemplate(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.questionnaireTemplateCommands.CreateQuestionnaireTemplate(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		encoded, err := packageapp.EncodeQuestionnaireTemplate(v)
		return http.StatusCreated, json.RawMessage(encoded), err
	})
}

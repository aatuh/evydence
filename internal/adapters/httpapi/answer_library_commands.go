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

type AnswerLibraryCommands interface {
	AuthorizeCreateAnswerLibraryEntry(context.Context, identitydomain.Actor, packageapp.CreateAnswerLibraryEntryInput) error
	CreateAnswerLibraryEntry(context.Context, identitydomain.Actor, packageapp.CreateAnswerLibraryEntryInput) (packagedomain.QuestionnaireAnswerLibraryEntry, error)
}

func decodeAnswerLibraryRequest(body []byte) (packageapp.CreateAnswerLibraryEntryInput, error) {
	var req struct {
		QuestionID   string   `json:"question_id"`
		EvidenceType string   `json:"evidence_type"`
		ControlID    string   `json:"control_id"`
		ProductID    string   `json:"product_id"`
		ReleaseID    string   `json:"release_id"`
		Answer       string   `json:"answer"`
		EvidenceIDs  []string `json:"evidence_ids"`
		Limitations  []string `json:"limitations"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateAnswerLibraryEntryInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "question_id", "evidence_type", "control_id", "product_id", "release_id", "answer", "evidence_ids", "limitations"); err != nil {
		return packageapp.CreateAnswerLibraryEntryInput{}, err
	}
	for _, field := range []string{"evidence_ids", "limitations"} {
		if err := validateNonNullableArrayItems(body, field); err != nil {
			return packageapp.CreateAnswerLibraryEntryInput{}, err
		}
	}
	in, err := packageapp.NormalizeAnswerLibraryInput(packageapp.CreateAnswerLibraryEntryInput{QuestionID: req.QuestionID, EvidenceType: req.EvidenceType, ControlID: req.ControlID, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Answer: req.Answer, EvidenceIDs: req.EvidenceIDs, Limitations: req.Limitations})
	return in, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurableAnswerLibraryEntry(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateAnswerLibraryEntryInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeAnswerLibraryRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.answerLibraryCommands.AuthorizeCreateAnswerLibraryEntry(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.answerLibraryCommands.CreateAnswerLibraryEntry(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		raw, err := packageapp.EncodeAnswerLibraryEntry(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}

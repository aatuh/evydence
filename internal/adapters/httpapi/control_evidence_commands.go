package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ControlEvidenceCommands has no control administration or query capability.
type ControlEvidenceCommands interface {
	AuthorizeControlEvidenceLink(context.Context, identitydomain.Actor, string, riskapp.LinkControlEvidenceInput) error
	LinkControlEvidence(context.Context, identitydomain.Actor, string, riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error)
}

// The decoded path is persisted as part of the idempotency key. Reject invalid
// database text before reserving that key, not only inside the owning command.
func validateControlEvidencePathID(id string) error {
	_, err := riskapp.NormalizeControlEvidencePathID(id)
	return mapControlCommandError(err)
}

func decodeControlEvidenceLink(body []byte, id string, a domain.Actor) (string, riskapp.LinkControlEvidenceInput, error) {
	var req struct {
		EvidenceType string `json:"evidence_type"`
		SubjectType  string `json:"subject_type"`
		SubjectID    string `json:"subject_id"`
		ProductID    string `json:"product_id"`
		ReleaseID    string `json:"release_id"`
		Confidence   string `json:"confidence"`
		Notes        string `json:"notes"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return "", riskapp.LinkControlEvidenceInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "evidence_type", "subject_type", "subject_id", "product_id", "release_id", "confidence", "notes"); err != nil {
		return "", riskapp.LinkControlEvidenceInput{}, err
	}
	id, in, err := riskapp.NormalizeControlEvidenceLinkInput(id, riskapp.LinkControlEvidenceInput{EvidenceType: req.EvidenceType, SubjectType: req.SubjectType, SubjectID: req.SubjectID, ProductID: req.ProductID, ReleaseID: req.ReleaseID, Confidence: req.Confidence, Notes: req.Notes})
	if err != nil {
		return "", riskapp.LinkControlEvidenceInput{}, mapControlCommandError(err)
	}
	if !riskapp.ValidControlEvidenceLinkKey(a.TenantID, riskapp.ControlEvidenceLinkKey{ControlID: id, EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID}) {
		return "", riskapp.LinkControlEvidenceInput{}, app.ErrValidation
	}
	return id, in, nil
}

func localControlEvidenceInput(in riskapp.LinkControlEvidenceInput) app.LinkControlEvidenceInput {
	return app.LinkControlEvidenceInput{EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Confidence: in.Confidence, Notes: in.Notes}
}

func (s *Server) linkControlEvidence(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := validateControlEvidencePathID(r.PathValue("id")); err != nil {
		writeProblem(w, r, err)
		return
	}
	var id string
	var in riskapp.LinkControlEvidenceInput
	if s.controlEvidenceCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			id, in, err = decodeControlEvidenceLink(body, r.PathValue("id"), a)
			if err != nil {
				return err
			}
			return mapControlCommandError(s.controlEvidenceCommands.AuthorizeControlEvidenceLink(ctx, a, id, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.controlEvidenceCommands.LinkControlEvidence(ctx, a, id, in)
			return http.StatusCreated, controlEvidenceFromQuery(v), mapControlCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.ledger.LinkControlEvidence(ctx, a, id, localControlEvidenceInput(in))
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		id, in, err = decodeControlEvidenceLink(body, r.PathValue("id"), a)
		if err != nil {
			return nil, err
		}
		return body, s.ledger.AuthorizeControlEvidenceLink(r.Context(), a, id, localControlEvidenceInput(in))
	})
}

package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type ApprovalCommands interface {
	AuthorizeApproval(context.Context, identitydomain.Actor, riskapp.CreateApprovalInput) error
	CreateApprovalRecord(context.Context, identitydomain.Actor, riskapp.CreateApprovalInput) (riskdomain.ApprovalRecord, error)
}

func (s *Server) createDurableApproval(w http.ResponseWriter, r *http.Request) {
	var input riskapp.CreateApprovalInput
	s.createDurable(w, r, func(ctx context.Context, actor domain.Actor, body []byte) error {
		var req struct {
			SubjectType string `json:"subject_type"`
			SubjectID   string `json:"subject_id"`
			Decision    string `json:"decision"`
			Reason      string `json:"reason"`
			EvidenceID  string `json:"evidence_id"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "subject_type", "subject_id", "decision", "reason", "evidence_id"); err != nil {
			return err
		}
		input = riskapp.CreateApprovalInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, Decision: req.Decision, Reason: req.Reason, EvidenceID: req.EvidenceID}
		return mapControlCommandError(s.approvalCommands.AuthorizeApproval(ctx, actor, input))
	}, func(ctx context.Context, actor domain.Actor, _ []byte) (int, any, error) {
		v, err := s.approvalCommands.CreateApprovalRecord(ctx, actor, input)
		return http.StatusCreated, domain.ApprovalRecord{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Decision: v.Decision, Reason: v.Reason, ApproverID: v.ApproverID, EvidenceID: v.EvidenceID, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}, mapControlCommandError(err)
	})
}

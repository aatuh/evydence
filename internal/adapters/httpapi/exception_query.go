package httpapi

import (
	"time"

	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func exceptionFromQuery(value riskdomain.Exception) domain.Exception {
	var approvedAt *time.Time
	if value.ApprovedAt != nil {
		at := *value.ApprovedAt
		approvedAt = &at
	}
	return domain.Exception{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID,
		FindingID: value.FindingID, ControlID: value.ControlID, Reason: value.Reason,
		Owner: value.Owner, ExpiresAt: value.ExpiresAt, Approved: value.Approved,
		ApprovedBy: value.ApprovedBy, ApprovedAt: approvedAt,
		CreatedAt: value.CreatedAt,
	}
}

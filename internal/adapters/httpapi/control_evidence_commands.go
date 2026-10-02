package httpapi

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

// ControlEvidenceCommands has no control administration or query capability.
type ControlEvidenceCommands interface {
	LinkControlEvidence(context.Context, identitydomain.Actor, string, riskapp.LinkControlEvidenceInput) (riskdomain.ControlEvidence, error)
}

// The decoded path is persisted as part of the idempotency key. Reject invalid
// database text before reserving that key, not only inside the owning command.
func validateControlEvidencePathID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
		return app.ErrValidation
	}
	return nil
}

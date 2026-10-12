package app

import (
	"encoding/json"
	"net/mail"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Membership administration needs the published email field on authorized
// replay. Project only this versioned public DTO; logs/customer packages still
// use generic PII redaction. Unknown fields cannot acquire this exception.
func publicHumanUserReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	var user domain.HumanUser
	if json.Unmarshal(encoded, &user) != nil || user.SchemaVersion != domain.HumanUserSchemaVersion || user.CreatedAt.IsZero() {
		return nil, false
	}
	for _, id := range []string{user.ID, user.TenantID} {
		if !validPublicMembershipText(id, 1024) || id == "" || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if !validPublicMembershipText(user.OrganizationID, 1024) || strings.TrimSpace(user.OrganizationID) != user.OrganizationID || redaction.RedactString(user.OrganizationID) != user.OrganizationID || !validPublicMembershipText(user.DisplayName, 65536) || strings.TrimSpace(user.DisplayName) == "" || !validPublicMembershipText(user.Email, 2304) || len(user.TenantID)+len(user.Email) > 2304 {
		return nil, false
	}
	address, err := mail.ParseAddress(user.Email)
	if err != nil || address.Name != "" || address.Address != user.Email || strings.TrimSpace(user.Email) != user.Email {
		return nil, false
	}
	switch user.Status {
	case "active":
		if user.DeactivatedAt != nil {
			return nil, false
		}
	case "deactivated":
		if user.DeactivatedAt == nil || user.DeactivatedAt.IsZero() {
			return nil, false
		}
	default:
		return nil, false
	}
	encoded, err = json.Marshal(user)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	if json.Unmarshal(encoded, &projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	result := safe.(map[string]any)
	result["email"] = user.Email
	return result, true
}

func validPublicMembershipText(value string, max int) bool {
	return len(value) <= max && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

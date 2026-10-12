package app

import (
	"encoding/json"
	"net/mail"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

// Only this versioned administration DTO may retain its published email. Logs,
// packages and arbitrary response maps continue to use generic PII redaction.
func publicSSOIdentityLinkReplay(value any) (map[string]any, bool) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	encoded, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	var link domain.UserIdentityLink
	if json.Unmarshal(encoded, &link) != nil || link.SchemaVersion != "user-identity-link.v1.0.0" || !link.Verified || link.CreatedAt.IsZero() {
		return nil, false
	}
	for _, id := range []string{link.ID, link.TenantID, link.UserID, link.ProviderID} {
		if id == "" || !validPublicMembershipText(id, 1024) || strings.TrimSpace(id) != id || redaction.RedactString(id) != id {
			return nil, false
		}
	}
	if link.Subject == "" || !validPublicMembershipText(link.Subject, 2304) || strings.TrimSpace(link.Subject) != link.Subject || len(link.TenantID)+len(link.ProviderID)+len(link.Subject) > 2304 || !validPublicMembershipText(link.Email, 2304) || len(link.TenantID)+len(link.Email) > 2304 || strings.TrimSpace(link.Email) != link.Email || !plainIdentityLinkEmail(link.Email) {
		return nil, false
	}
	encoded, err = json.Marshal(link)
	if err != nil {
		return nil, false
	}
	var projected map[string]any
	if json.Unmarshal(encoded, &projected) != nil {
		return nil, false
	}
	safe, _ := redaction.RemoveSensitive(projected)
	result := safe.(map[string]any)
	result["email"] = link.Email
	// Diagnostic redaction flattens line breaks, but this opaque subject is a
	// persisted identifier. Restore harmless text verbatim, not credential-like
	// or embedded-PII text; a plain whole-mailbox subject is explicitly public.
	redactedSubject := redaction.RedactString(link.Subject)
	flattenedSubject := strings.NewReplacer("\r", " ", "\n", " ").Replace(link.Subject)
	if redactedSubject == flattenedSubject || plainIdentityLinkEmail(link.Subject) && redactedSubject == redaction.Redacted {
		result["subject"] = link.Subject
	}
	return result, true
}
func plainIdentityLinkEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

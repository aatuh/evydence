package authz

import (
	"context"
	"strings"
	"unicode/utf8"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// CheckCollectorAttribution constrains caller-supplied provenance to the
// authenticated collector identity. It supplements, not replaces, action and
// resource authorization and the current storage-owned credential binding.
// An omitted claim uses the actor's binding; a conflicting claim must not be
// silently overwritten or retained in immutable source metadata. Historical
// imports have their own verification boundary and do not use this create rule.
// No metadata is modified and unrelated source claims acquire no trust here.
func CheckCollectorAttribution(ctx context.Context, actor identitydomain.Actor, collectorID string, sourceIdentity map[string]any) error {
	if ctx == nil {
		return ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor.TenantID == "" || actor.KeyID == "" && actor.UserID == "" && actor.CollectorID == "" {
		return ErrUnauthorized
	}
	claimedSource, hasSourceClaim := sourceIdentity["collector_id"]
	if actor.CollectorID == "" {
		if collectorID != "" || hasSourceClaim {
			return ErrForbidden
		}
		return nil
	}
	for _, id := range []string{actor.TenantID, actor.KeyID, actor.CollectorID} {
		if id == "" || len(id) > 1024 || strings.TrimSpace(id) != id || !utf8.ValidString(id) || strings.ContainsRune(id, 0) {
			return ErrForbidden
		}
	}
	if actor.UserID != "" || actor.SessionID != "" || collectorID != "" && collectorID != actor.CollectorID {
		return ErrForbidden
	}
	if hasSourceClaim {
		id, ok := claimedSource.(string)
		if !ok || id != actor.CollectorID {
			return ErrForbidden
		}
	}
	return nil
}

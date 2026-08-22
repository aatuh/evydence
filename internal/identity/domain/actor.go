package domain

import (
	"errors"
	"sort"
	"strings"
)

var ErrInvalidActor = errors.New("invalid actor")

func NewActor(tenantID string, scopes []string) (Actor, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Actor{}, ErrInvalidActor
	}
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			set[scope] = struct{}{}
		}
	}
	normalized := make([]string, 0, len(set))
	for scope := range set {
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return Actor{TenantID: tenantID, Scopes: normalized}, nil
}

func (actor Actor) HasScope(scope string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return false
	}
	for _, candidate := range actor.Scopes {
		if candidate == scope || candidate == "*" {
			return true
		}
	}
	return false
}

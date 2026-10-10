package app

import (
	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func validCollectorScopes(scopes []string) bool {
	_, err := integrationapp.NormalizeCollectorScopes(scopes)
	return err == nil
}

func validCollectorType(typ string) bool {
	return integrationapp.ValidCollectorType(typ)
}

func actorType(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func actorID(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	if actor.UserID != "" {
		return actor.UserID
	}
	return actor.KeyID
}

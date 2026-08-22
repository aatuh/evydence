package domain

import (
	"reflect"
	"testing"
)

func TestNewActorNormalizesScopesAndRejectsMissingTenant(t *testing.T) {
	actor, err := NewActor(" ten_1 ", []string{"release:read", " evidence:read ", "release:read", ""})
	if err != nil {
		t.Fatalf("NewActor: %v", err)
	}
	if actor.TenantID != "ten_1" || !reflect.DeepEqual(actor.Scopes, []string{"evidence:read", "release:read"}) {
		t.Fatalf("actor was not normalized: %#v", actor)
	}
	if !actor.HasScope(" evidence:read ") || actor.HasScope("") || actor.HasScope("evidence:write") {
		t.Fatalf("unexpected scope evaluation: %#v", actor)
	}
	if !(Actor{Scopes: []string{"*"}}).HasScope("evidence:write") {
		t.Fatal("wildcard scope was not honored")
	}
	if _, err := NewActor(" ", nil); err == nil {
		t.Fatal("empty tenant was accepted")
	}
}

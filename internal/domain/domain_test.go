package domain

import "testing"

func TestActorHasScopeSupportsExactAndWildcardScopes(t *testing.T) {
	if !((Actor{Scopes: []string{"evidence:write"}}).HasScope("evidence:write")) {
		t.Fatal("exact scope should be accepted")
	}
	if !((Actor{Scopes: []string{"*"}}).HasScope("controls:admin")) {
		t.Fatal("wildcard scope should be accepted")
	}
	if (Actor{Scopes: []string{"evidence:read"}}).HasScope("evidence:write") {
		t.Fatal("ungranted scope should be rejected")
	}
}

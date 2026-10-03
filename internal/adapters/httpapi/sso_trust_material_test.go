package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSSOProviderHTTPRejectsPrivateTrustWithoutExposingInput(t *testing.T) {
	s, secret := testServer(t)
	public := `{"keys":[{"kty":"RSA","kid":"fixture","n":"public-only","e":"AQAB"}]}`
	body := `{"name":"Fixture","type":"oidc","issuer":"https://issuer.example.test","client_id":"client","jwks":` + public + `}`
	out := postRaw(t, s, secret, "/v1/sso/providers", "public-trust", []byte(body), 201)
	var provider struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &provider); err != nil || provider.Data.ID == "" {
		t.Fatal("public provider response lost", err)
	}
	extended := strings.Replace(body, `"jwks":{"keys":`, `"jwks":{"client_secret":"private-jwks-canary","keys":`, 1)
	extended = strings.Replace(extended, `"e":"AQAB"`, `"e":"AQAB","extension":{"password":"private-jwks-canary"}`, 1)
	out = postRaw(t, s, secret, "/v1/sso/providers", "public-projection", []byte(extended), 201)
	if strings.Contains(out, "private-jwks-canary") || strings.Contains(out, "client_secret") || strings.Contains(out, "extension") {
		t.Fatal("unrecognized JWKS metadata reached public provider DTO")
	}
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		private := strings.Replace(public, `"e":"AQAB"`, `"e":"AQAB","`+field+`":"private-jwks-canary"`, 1)
		create := strings.Replace(body, public, private, 1)
		out := postRaw(t, s, secret, "/v1/sso/providers", "private-create-"+field, []byte(create), 400)
		if strings.Contains(out, "private-jwks-canary") {
			t.Fatal("private provider input leaked into error")
		}
		out = postRaw(t, s, secret, "/v1/sso/providers/"+provider.Data.ID+"/trust-material", "private-rotate-"+field, []byte(`{"jwks":`+private+`}`), 400)
		if strings.Contains(out, "private-jwks-canary") {
			t.Fatal("private rotation input leaked into error")
		}
	}
}

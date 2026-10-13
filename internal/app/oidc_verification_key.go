package app

import "errors"

func oidcVerificationJWK(jwks map[string]any, kid, algorithm, keyType string) (map[string]any, error) {
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 64 {
		return nil, errors.New("invalid OIDC verification key set")
	}
	var selected map[string]any
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("invalid OIDC verification key")
		}
		if key["kid"] != kid {
			continue
		}
		if selected != nil {
			return nil, errors.New("ambiguous OIDC verification key id")
		}
		selected = key
	}
	if selected == nil || selected["kty"] != keyType {
		return nil, errors.New("matching OIDC verification key not found")
	}
	for name, expected := range map[string]string{"alg": algorithm, "use": "sig"} {
		if got, present := selected[name]; present && got != expected {
			return nil, errors.New("OIDC key algorithm or use is incompatible")
		}
	}
	if operations, present := selected["key_ops"]; present {
		switch operations := operations.(type) {
		case []any:
			if len(operations) != 1 || operations[0] != "verify" {
				return nil, errors.New("OIDC key is not verification-only")
			}
		case []string:
			if len(operations) != 1 || operations[0] != "verify" {
				return nil, errors.New("OIDC key is not verification-only")
			}
		default:
			return nil, errors.New("invalid OIDC key operations")
		}
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, present := selected[name]; present {
			return nil, errors.New("OIDC trust key contains private material")
		}
	}
	return selected, nil
}

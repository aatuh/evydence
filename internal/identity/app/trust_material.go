package app

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
)

// PublicTrustMaterialValidator is a stateless normalization policy shared by
// focused identity commands and the explicit local compatibility facade.
// It validates supported metadata shapes, not provider ownership or trust.
type PublicTrustMaterialValidator struct{}

var _ TrustMaterialValidator = PublicTrustMaterialValidator{}

func (PublicTrustMaterialValidator) NormalizeJWKS(jwks map[string]any) (map[string]any, error) {
	if len(jwks) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(jwks)
	if err != nil || len(body) > 64*1024 {
		return nil, ErrValidation
	}
	var normalized map[string]any
	if json.Unmarshal(body, &normalized) != nil || hasPrivateJWKMembers(normalized) {
		return nil, ErrValidation
	}
	keys, ok := normalized["keys"].([]any)
	if !ok || len(keys) == 0 || len(keys) > 10 {
		return nil, ErrValidation
	}
	public := make([]any, 0, len(keys))
	for _, raw := range keys {
		key, ok := raw.(map[string]any)
		if !ok || hasPrivateJWKMembers(key) {
			return nil, ErrValidation
		}
		kty, _ := key["kty"].(string)
		kid, _ := key["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return nil, ErrValidation
		}
		switch kty {
		case "OKP":
			crv, _ := key["crv"].(string)
			x, _ := key["x"].(string)
			if crv != "Ed25519" || strings.TrimSpace(x) == "" {
				return nil, ErrValidation
			}
		case "RSA":
			n, _ := key["n"].(string)
			e, _ := key["e"].(string)
			if strings.TrimSpace(n) == "" || strings.TrimSpace(e) == "" {
				return nil, ErrValidation
			}
		default:
			return nil, ErrValidation
		}
		projected, err := projectPublicJWK(key)
		if err != nil {
			return nil, err
		}
		public = append(public, projected)
	}
	// Trust records retain supported public JWK members only. Arbitrary root
	// or key extensions are not an evidence/credential metadata storage channel.
	return map[string]any{"keys": public}, nil
}

func projectPublicJWK(key map[string]any) (map[string]any, error) {
	public := make(map[string]any)
	for _, member := range []string{"kty", "kid", "crv", "x", "n", "e", "alg", "use", "x5u", "x5t", "x5t#S256", "key_ops", "x5c"} {
		value, present := key[member]
		if !present {
			continue
		}
		if member == "key_ops" || member == "x5c" {
			values, ok := value.([]any)
			if !ok {
				return nil, ErrValidation
			}
			for _, item := range values {
				if _, ok := item.(string); !ok {
					return nil, ErrValidation
				}
			}
		} else if _, ok := value.(string); !ok {
			return nil, ErrValidation
		}
		public[member] = value
	}
	return public, nil
}

func hasPrivateJWKMembers(value map[string]any) bool {
	// Reject member presence, even null: private or symmetric parameters never
	// belong in public provider trust material and must not reach persistence.
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, present := value[member]; present {
			return true
		}
	}
	return false
}

func (PublicTrustMaterialValidator) NormalizeSAMLSigningCertificates(certs []string) ([]string, error) {
	if len(certs) == 0 {
		return nil, nil
	}
	if len(certs) > 5 {
		return nil, ErrValidation
	}
	out := make([]string, 0, len(certs))
	for _, raw := range certs {
		value := strings.TrimSpace(raw)
		if value == "" || len(value) > 16*1024 {
			return nil, ErrValidation
		}
		block, _ := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, ErrValidation
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrValidation
		}
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return nil, ErrValidation
		}
		out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
	}
	return out, nil
}

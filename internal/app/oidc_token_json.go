package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

func decodeOIDCSegment(value string) ([]byte, error) {
	body, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != value {
		return nil, errors.New("noncanonical OIDC encoding")
	}
	return body, nil
}

// Signed JSON must have one interpretation, including escaped member names.
// Bound nesting and token work before decoding into the claim/header structs.
func decodeOIDCObject(body []byte, target any) error {
	if len(body) > 16*1024 || !utf8.Valid(body) {
		return errors.New("invalid OIDC JSON size or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("OIDC JSON must be an object")
	}
	remaining := 4096
	if err := scanOIDCJSONValue(d, first, 0, &remaining); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing OIDC JSON")
	}
	return json.Unmarshal(body, target)
}

func scanOIDCJSONValue(d *json.Decoder, token json.Token, depth int, remaining *int) error {
	*remaining -= 1
	if *remaining < 0 || depth > 32 {
		return errors.New("OIDC JSON exceeds structure limits")
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	seen := map[string]struct{}{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid OIDC JSON member")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("duplicate OIDC JSON member")
			}
			seen[name] = struct{}{}
		}
		next, err := d.Token()
		if err != nil {
			return err
		}
		if err := scanOIDCJSONValue(d, next, depth+1, remaining); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	if delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']') {
		return nil
	}
	return errors.New("invalid OIDC JSON structure")
}

package jsonbounds

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func FuzzBoundedJSONRoundTrip(f *testing.F) {
	for _, seed := range []string{
		`null`, `true`, `0`, `1e1000`, `"\ud83d\ude00"`,
		`{"items":[{"name":"release"}],"count":2}`,
		`{"id":1,"\u0069d":2}`, `{} {}`, `{"x":[1,]}`,
		strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17),
		`"` + strings.Repeat("x", 1025) + `"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			return
		}
		limits := Limits{
			MaxDepth: 16, MaxObjectKeys: 64,
			MaxArrayItems: 128, MaxStringBytes: 1024,
		}
		err := Validate(raw, limits)
		again := Validate(raw, limits)
		if err != nil {
			if !errors.Is(err, ErrInvalid) || !errors.Is(again, ErrInvalid) ||
				errors.Is(err, ErrDuplicateObjectKey) != errors.Is(again, ErrDuplicateObjectKey) {
				t.Fatal("rejected JSON did not retain deterministic error categories")
			}
			return
		}
		if again != nil {
			t.Fatal("accepted JSON was not repeatable")
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("accepted JSON did not decode: %v", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil || Validate(encoded, limits) != nil {
			t.Fatalf("accepted JSON did not survive serialization: %v", err)
		}
		tail := append(append([]byte(nil), raw...), []byte("\nnull")...)
		if !errors.Is(Validate(tail, limits), ErrInvalid) {
			t.Fatal("validator accepted a second JSON value")
		}
	})
}

func FuzzDuplicateJSONKeys(f *testing.F) {
	for _, key := range []string{"", "id", "\x00", "quote\"", "\\u0061", "\u00e9", "\U0001f600", string([]byte{0xff})} {
		f.Add(key, uint8(1))
	}
	f.Fuzz(func(t *testing.T, key string, value uint8) {
		if len(key) > 128 {
			return
		}
		encoded, err := json.Marshal("key-" + key)
		if err != nil {
			t.Fatal(err)
		}
		// The fixed ASCII prefix makes the second spelling valid JSON for
		// every input, while both spellings decode to the exact same key.
		alias := `"\u006b` + string(encoded[2:])
		duplicate := "{" + string(encoded) + ":" + strconv.Itoa(int(value)) +
			"," + alias + ":null}"
		for _, raw := range []string{duplicate, "[" + duplicate + "]", `{"nested":` + duplicate + "}"} {
			err := Validate([]byte(raw), DefaultLimits())
			if !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrDuplicateObjectKey) {
				t.Fatalf("decoded duplicate key was not rejected: %v", err)
			}
		}
	})
}

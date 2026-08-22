// Package jsonbounds validates JSON structure before application decoding.
// It limits the work performed by generic decoders while also rejecting
// duplicate object keys, which otherwise create ambiguous security inputs.
package jsonbounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var ErrInvalid = errors.New("JSON violates structural limits")

// ErrDuplicateObjectKey identifies an ambiguous object that contains the same
// key more than once. It is paired with ErrInvalid by Validate so callers can
// retain a compatible diagnostic without exposing parser internals.
var ErrDuplicateObjectKey = errors.New("JSON contains duplicate object key")

type Limits struct {
	MaxDepth       int
	MaxObjectKeys  int
	MaxArrayItems  int
	MaxStringBytes int
}

func DefaultLimits() Limits {
	return Limits{
		MaxDepth:       32,
		MaxObjectKeys:  256,
		MaxArrayItems:  1024,
		MaxStringBytes: 16 << 10,
	}
}

func (l Limits) Valid() bool {
	return l.MaxDepth > 0 && l.MaxObjectKeys > 0 && l.MaxArrayItems > 0 && l.MaxStringBytes > 0
}

// Validate reads one JSON value within the supplied structural budget. The
// decoder never descends past MaxDepth, and object/array counters are checked
// before additional values are processed.
func Validate(body []byte, limits Limits) error {
	if !limits.Valid() {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := validateValue(decoder, limits, 0); err != nil {
		if errors.Is(err, ErrDuplicateObjectKey) {
			return errors.Join(ErrInvalid, ErrDuplicateObjectKey)
		}
		return ErrInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func validateValue(decoder *json.Decoder, limits Limits, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if value, ok := token.(string); ok {
		if len(value) > limits.MaxStringBytes {
			return ErrInvalid
		}
		return nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= limits.MaxDepth {
		return ErrInvalid
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{}, min(limits.MaxObjectKeys, 64))
		for count := 0; decoder.More(); count++ {
			if count >= limits.MaxObjectKeys {
				return ErrInvalid
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || len(key) > limits.MaxStringBytes {
				return ErrInvalid
			}
			if _, exists := keys[key]; exists {
				return ErrDuplicateObjectKey
			}
			keys[key] = struct{}{}
			if err := validateValue(decoder, limits, depth+1); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil || token != json.Delim('}') {
			return ErrInvalid
		}
		return nil
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= limits.MaxArrayItems {
				return ErrInvalid
			}
			if err := validateValue(decoder, limits, depth+1); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil || token != json.Delim(']') {
			return ErrInvalid
		}
		return nil
	default:
		return ErrInvalid
	}
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

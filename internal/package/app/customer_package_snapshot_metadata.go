package app

import (
	"encoding"
	"encoding/json"
	"reflect"
	"strings"
)

// Keep the established internal collection shapes while normalizing unknown
// JSON-compatible metadata. The decoded tree is already structurally bounded;
// no custom marshaler/unmarshaler is invoked while restoring typed values.
func restoreCustomerSnapshotMetadata(source, decoded PackageSnapshot, excludedFields []string) PackageSnapshot {
	excluded := make(map[string]bool, len(excludedFields)+len(hardExcludedPackageFields))
	for key := range hardExcludedPackageFields {
		excluded[key] = true
	}
	for _, key := range excludedFields {
		excluded[strings.ToLower(strings.TrimSpace(key))] = true
	}
	from, to := reflect.ValueOf(source), reflect.ValueOf(&decoded).Elem()
	mapType, sliceType := reflect.TypeOf(map[string]any{}), reflect.TypeOf([]map[string]any{})
	for i := 0; i < from.NumField(); i++ {
		if from.Field(i).Type() == mapType || from.Field(i).Type() == sliceType {
			to.Field(i).Set(reflect.ValueOf(customerSnapshotJSONValue(from.Field(i).Interface(), to.Field(i).Interface(), excluded)))
		}
	}
	return decoded
}

func customerSnapshotJSONValue(source, decoded any, excluded map[string]bool) any {
	switch value := source.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		generic, _ := decoded.(map[string]any)
		for key, child := range value {
			if !excluded[strings.ToLower(strings.TrimSpace(key))] {
				result[key] = customerSnapshotJSONValue(child, generic[key], excluded)
			}
		}
		return result
	case []map[string]any:
		result := make([]map[string]any, len(value))
		generic, _ := decoded.([]any)
		// Top-level snapshot collections decode into their concrete slice type.
		maps, _ := decoded.([]map[string]any)
		for i, child := range value {
			var fallback any
			if i < len(generic) {
				fallback = generic[i]
			} else if i < len(maps) {
				fallback = maps[i]
			}
			result[i] = customerSnapshotJSONValue(child, fallback, excluded).(map[string]any)
		}
		return result
	case []any:
		result := make([]any, len(value))
		generic, _ := decoded.([]any)
		for i, child := range value {
			var fallback any
			if i < len(generic) {
				fallback = generic[i]
			}
			result[i] = customerSnapshotJSONValue(child, fallback, excluded)
		}
		return result
	case []string:
		return append([]string(nil), value...)
	case map[string]int:
		result := make(map[string]int, len(value))
		for key, count := range value {
			if !excluded[strings.ToLower(strings.TrimSpace(key))] {
				result[key] = count
			}
		}
		return result
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return value
	default:
		safe := sanitizeManifestValue(decoded, excluded)
		if reflect.DeepEqual(decoded, safe) {
			// Only immutable scalars and owned string slices can retain a plain
			// struct shape (for example a public verification profile). Any
			// excluded field or richer/custom type uses the sanitized JSON tree.
			if copy, ok := cloneCustomerPlainMetadataValue(source); ok {
				return copy
			}
		}
		return safe
	}
}

func cloneCustomerPlainMetadataValue(value any) (any, bool) {
	v := reflect.ValueOf(value)
	if !v.IsValid() || !customerPlainMetadataStruct(v.Type()) {
		return nil, false
	}
	copy := reflect.New(v.Type()).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Slice && !field.IsNil() {
			owned := reflect.MakeSlice(field.Type(), field.Len(), field.Len())
			reflect.Copy(owned, field)
			copy.Field(i).Set(owned)
		} else {
			copy.Field(i).Set(field)
		}
	}
	return copy.Interface(), true
}

func customerPlainMetadataStruct(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	for _, contract := range []reflect.Type{
		reflect.TypeOf((*json.Marshaler)(nil)).Elem(),
		reflect.TypeOf((*json.Unmarshaler)(nil)).Elem(),
		reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem(),
		reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem(),
	} {
		if t.Implements(contract) || reflect.PointerTo(t).Implements(contract) {
			return false
		}
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" || field.Tag.Get("json") == "-" || field.Type.PkgPath() != "" {
			return false
		}
		switch field.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		case reflect.Slice:
			if field.Type.Elem() != reflect.TypeOf("") {
				return false
			}
		default:
			return false
		}
	}
	return true
}

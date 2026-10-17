package config

import (
	"net/url"
	"slices"
	"time"
)

type nativeSettingValue interface {
	string | bool | int64 | time.Duration | Secret | NativeURL | []string | []uint16
}

// NativeOption preserves supplied presence independently of effective nonempty
// input. Value is deliberate access; formatting and JSON always redact it.
// Native SDK defaults and reference resolution are not applied here.
type NativeOption[T nativeSettingValue] struct {
	redactedValue
	value    T
	present  bool
	hasValue bool
}

func (o NativeOption[T]) Present() bool  { return o.present }
func (o NativeOption[T]) HasValue() bool { return o.hasValue }
func (o NativeOption[T]) Value() T       { return cloneNativeOptionValue(o.value) }

func cloneNativeOptionValue[T nativeSettingValue](value T) T {
	switch value := any(value).(type) {
	case []string:
		return any(slices.Clone(value)).(T)
	case []uint16:
		return any(slices.Clone(value)).(T)
	}
	return value
}

// NativeURL redacts parsed endpoints, including proxy userinfo. URL explicitly
// returns a value copy; url.Userinfo itself has no mutation methods.
type NativeURL struct {
	redactedValue
	value url.URL
}

func (u NativeURL) URL() url.URL { return u.value }

func projectNativeOption[T nativeSettingValue](input nativeInputs, name string, convert func(nativeValue) T) NativeOption[T] {
	for _, d := range nativeInputDefinitions {
		if d.Name != name {
			continue
		}
		value, hasValue := input.selected(d)
		present := hasValue
		for _, candidate := range append([]string{d.Name}, d.Fallbacks...) {
			_, exists := input.values[candidate]
			present = present || exists
		}
		var typed T
		if hasValue {
			typed = cloneNativeOptionValue(convert(value))
		}
		return NativeOption[T]{value: typed, present: present, hasValue: hasValue}
	}
	return NativeOption[T]{}
}

func nativeString(input nativeInputs, name string) NativeOption[string] {
	return projectNativeOption(input, name, func(v nativeValue) string { return v.scalar.text })
}

func nativeBoolean(input nativeInputs, name string) NativeOption[bool] {
	return projectNativeOption(input, name, func(v nativeValue) bool { return v.scalar.boolean })
}

func nativeInteger(input nativeInputs, name string) NativeOption[int64] {
	return projectNativeOption(input, name, func(v nativeValue) int64 { return v.scalar.integer })
}

func nativeDuration(input nativeInputs, name string) NativeOption[time.Duration] {
	return projectNativeOption(input, name, func(v nativeValue) time.Duration { return v.scalar.duration })
}

func nativeSecret(input nativeInputs, name string) NativeOption[Secret] {
	return projectNativeOption(input, name, func(v nativeValue) Secret { return Secret{value: v.raw} })
}

func nativeURL(input nativeInputs, name string) NativeOption[NativeURL] {
	return projectNativeOption(input, name, func(v nativeValue) NativeURL { return NativeURL{value: v.endpoint} })
}

func nativeItems(input nativeInputs, name string) NativeOption[[]string] {
	return projectNativeOption(input, name, func(v nativeValue) []string { return v.items })
}

func nativePorts(input nativeInputs, name string) NativeOption[[]uint16] {
	return projectNativeOption(input, name, func(v nativeValue) []uint16 { return v.ports })
}

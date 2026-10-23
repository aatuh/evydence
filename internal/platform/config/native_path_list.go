package config

import "strings"

// parseNativePathItems follows filepath.SplitList's Windows quote semantics.
// Raw item bounds apply before quote removal; empty entries remain explicit.
// It takes a separator so the same pure parser can be checked across platforms.
func parseNativePathItems(raw string, separator byte, maxItems, maxItemBytes int) ([]string, error) {
	if maxItems <= 0 || maxItemBytes <= 0 {
		return nil, ErrInvalidValue
	}
	if raw == "" {
		return nil, nil
	}
	items := make([]string, 0, min(maxItems, 16))
	start, quoted := 0, false
	for i := 0; i <= len(raw); i++ {
		end := i == len(raw)
		if !end && separator == ';' && raw[i] == '"' {
			quoted = !quoted
		}
		if end || raw[i] == separator && !quoted {
			if len(items) >= maxItems || i-start > maxItemBytes {
				return nil, ErrInvalidValue
			}
			item := raw[start:i]
			if separator == ';' {
				item = strings.ReplaceAll(item, `"`, "")
			}
			if item != "" && strings.TrimSpace(item) == "" {
				return nil, ErrInvalidValue
			}
			items = append(items, item)
			start = i + 1
		} else if i-start >= maxItemBytes {
			return nil, ErrInvalidValue
		}
	}
	return items, nil
}

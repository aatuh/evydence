package postgres

import (
	"database/sql"
	"encoding/json"
	"time"
)

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableSQLString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableSQLTime(value sql.NullTime) *time.Time {
	if !value.Valid || value.Time.IsZero() {
		return nil
	}
	t := value.Time.UTC()
	return &t
}

func decodeJSON(raw []byte, out any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}
	return value.UTC()
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nonZeroInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func textArray(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

func nonZeroTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().UTC()
	}
	return value.UTC()
}

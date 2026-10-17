// Package config defines bounded, secret-safe process configuration inputs.
// Parse validates a captured environment into owned, role-specific settings
// without ambient reads or external side effects. Parsed settings do not prove
// a complete runtime is ready: bounded database/file/credential resolution and
// command adoption remain subsequent EVY-1205 work.
package config

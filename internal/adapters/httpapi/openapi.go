package httpapi

import "github.com/aatuh/api-toolkit/v3/specs"

func NewSpecRegistry() *specs.Registry {
	registry := specs.NewRegistryWithOptions(specs.Info{
		Title:       "Evydence API",
		Description: "Self-hosted API evidence and compliance-readiness ledger.",
		Version:     "dev",
	}, specs.RegistryOptions{OpenAPIVersion: specs.OpenAPIVersion31})
	registry.RegisterSecurityScheme("BearerAuth", specs.SecurityScheme{Type: "http", Scheme: "bearer"})
	registry.RegisterSchema("Problem", map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type":     map[string]any{"type": "string"},
			"title":    map[string]any{"type": "string"},
			"status":   map[string]any{"type": "integer"},
			"detail":   map[string]any{"type": "string"},
			"instance": map[string]any{"type": "string"},
			"code":     map[string]any{"type": "string"},
		},
	})
	return registry
}

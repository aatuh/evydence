package wiring

import identityquery "github.com/aatuh/evydence/internal/identity/query"

// BuildRoleBindingQuery binds admin inventory reads to durable storage.
func BuildRoleBindingQuery(reader identityquery.RoleBindingReader) (*identityquery.RoleBindings, error) {
	return identityquery.NewRoleBindings(reader)
}

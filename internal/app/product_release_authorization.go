package app

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) authorizeProductReleaseLocked(a domain.Actor, scope, product, release string) (application.ResourceReferences, error) {
	var empty application.ResourceReferences
	if err := l.ensureScopeLocked(a.TenantID, product, "", release); err != nil {
		return empty, err
	}
	p := product
	if release != "" {
		parent := l.releases[release].ProductID
		if p != "" && p != parent {
			return empty, ErrNotFound
		}
		p = parent
	}
	if err := l.ensureScopeLocked(a.TenantID, p, "", ""); err != nil {
		return empty, err
	}
	if err := l.authorizeResourceLocked(a, scope, resourceRefs{ProductID: product, ReleaseID: release}); err != nil {
		return empty, err
	}
	return application.ResourceReferences{ProductID: p, ReleaseID: release}, nil
}

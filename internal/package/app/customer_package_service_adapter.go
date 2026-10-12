package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Transitional local-memory/legacy adapters delegate business rules to the
// focused command. Production composition must provide a database reader and
// flat write adapter instead; these adapters do not retire Ledger themselves.
type serviceCustomerCreationReader struct {
	reader    Reader
	refresher ProjectionRefresher
}

func (r serviceCustomerCreationReader) ReadCustomerPackageCreationSnapshot(ctx context.Context, tenant, product, release, profile string, _ time.Time) (CustomerPackageCreationSnapshot, error) {
	var empty CustomerPackageCreationSnapshot
	if r.refresher != nil {
		if err := r.refresher.RefreshPackageProjection(ctx, tenant); err != nil {
			return empty, err
		}
	}
	p, err := r.reader.GetRedactionProfile(ctx, tenant, profile)
	if err != nil {
		return empty, err
	}
	if !validCustomerCreationProfile(p, tenant, profile) {
		return empty, ErrNotFound
	}
	s, err := r.reader.ReadCommittedPackageSnapshot(ctx, tenant, product, release)
	if err != nil {
		return empty, err
	}
	// The legacy profile and snapshot are separate reads. Profiles are checked
	// again under the write transaction; native readers use one database view.
	return CustomerPackageCreationSnapshot{Profile: p, Snapshot: s}, nil
}

type serviceCustomerCreationTransactions struct{ runner TransactionRunner }

func (t serviceCustomerCreationTransactions) ExecuteCustomerPackageCreation(ctx context.Context, fn func(context.Context, CustomerPackageCreationTransaction) error) error {
	return t.runner.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, serviceCustomerCreationTransaction{tx})
	})
}

type serviceCustomerCreationTransaction struct{ tx Transaction }

func (t serviceCustomerCreationTransaction) GetRedactionProfile(ctx context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	return t.tx.Packages().GetRedactionProfile(ctx, tenant, id)
}
func (t serviceCustomerCreationTransaction) InsertCustomerSecurityPackage(ctx context.Context, v packagedomain.CustomerSecurityPackage) error {
	return t.tx.Packages().InsertCustomerSecurityPackage(ctx, v)
}
func (t serviceCustomerCreationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return t.tx.Authorization().Authorize(ctx, a, r)
}
func (t serviceCustomerCreationTransaction) AppendAudit(ctx context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	return t.tx.Audit().AppendAudit(ctx, v)
}

package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

// ExecuteUnitOfWork runs a transaction-backed application command using this
// ledger's configured persistence factory.
func (l *Ledger) ExecuteUnitOfWork(ctx context.Context, command UnitOfWorkCommand) error {
	if l == nil || l.unitOfWork == nil {
		return ErrValidation
	}
	if repositories, ok := activeRepositories(ctx); ok {
		return command(ctx, repositories)
	}
	l.transactionGate.RLock()
	defer l.transactionGate.RUnlock()
	return ExecuteUnitOfWork(ctx, l.unitOfWork, command)
}

// publishCommittedAuditEntryLocked refreshes the local read model only after
// the transaction holding the entry has committed.
func (l *Ledger) publishCommittedAuditEntryLocked(entry domain.AuditChainEntry) {
	if l == nil || entry.ID == "" || entry.TenantID == "" || entry.Sequence < 1 {
		return
	}
	entries := l.chain[entry.TenantID]
	// A transaction can commit after a worker has appended an entry that this
	// process has not projected yet. Never turn that harmless stale prefix into
	// a permanently divergent cache by appending across a sequence gap or by
	// replacing an already observed sequence. The next authoritative projection
	// refresh can safely extend the unchanged prefix.
	if entry.Sequence <= int64(len(entries)) || entry.Sequence != int64(len(entries))+1 {
		return
	}
	expectedPreviousHash := ""
	if len(entries) > 0 {
		expectedPreviousHash = entries[len(entries)-1].EntryHash
	}
	if entry.PreviousEntryHash != expectedPreviousHash {
		return
	}
	canonical, valid, err := verifiedAuditChainCanonicalHash(entry)
	if err != nil || !valid || entry.EntryHash != hashBytes([]byte(entry.PreviousEntryHash+"\n"+canonical)) {
		return
	}
	entry.Metadata = cloneMap(entry.Metadata)
	l.chain[entry.TenantID] = append(entries, entry)
}

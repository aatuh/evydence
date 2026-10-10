package app

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var _ verificationapp.AuditChainVerificationReader = memoryVerificationRepository{}

// Current typed test-backend view and bounded pages. These are not PostgreSQL
// writer fences, SQL transfer/allocation bounds or durable snapshots.
func memoryAuditVerificationView(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant string) (verificationapp.AuditChainVerificationView, error) {
	view := verificationapp.AuditChainVerificationView{TenantID: tenant}
	for _, e := range s.AuditEntries[tenant] {
		if err := ctx.Err(); err != nil {
			return verificationapp.AuditChainVerificationView{}, err
		}
		if e.TenantID != tenant {
			return verificationapp.AuditChainVerificationView{}, ErrConflict
		}
		if view.EntryCount == 0 || e.Sequence > view.HeadSequence {
			view.HeadSequence, view.HeadHash = e.Sequence, e.EntryHash
		}
		view.EntryCount++
	}
	if !memoryGovernanceText(view.HeadHash, 1024) {
		return verificationapp.AuditChainVerificationView{}, ErrConflict
	}
	return view, nil
}

func (r memoryVerificationRepository) LockAuditChainVerification(ctx context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	var out verificationapp.AuditChainVerificationView
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(s *MemoryUnitOfWorkSnapshot) error {
		var err error
		out, err = memoryAuditVerificationView(ctx, s, tenant)
		return err
	})
	if err != nil {
		return verificationapp.AuditChainVerificationView{}, err
	}
	return out, nil
}

func (r memoryVerificationRepository) ReadAuditChainVerificationPage(ctx context.Context, view verificationapp.AuditChainVerificationView, after *int64, maxBytes int) (verificationapp.AuditChainVerificationPage, error) {
	var out verificationapp.AuditChainVerificationPage
	if maxBytes < 0 || maxBytes > verificationapp.MaxAuditChainVerificationBytes {
		return out, ErrValidation
	}
	err := memoryIdentityRepository(r).membershipRead(ctx, view.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		current, err := memoryAuditVerificationView(ctx, s, view.TenantID)
		if err != nil {
			return err
		}
		if current != view {
			return ErrConflict
		}
		entries := s.AuditEntries[view.TenantID]
		// Select only the next page of coordinates, not a sorted copy/index of
		// the tenant's complete private audit inventory.
		indices := make([]int, 0, verificationapp.MaxAuditChainVerificationPageEntries)
		for index, e := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if after != nil && e.Sequence <= *after || e.Sequence > view.HeadSequence {
				continue
			}
			position := sort.Search(len(indices), func(i int) bool { return entries[indices[i]].Sequence >= e.Sequence })
			if position == verificationapp.MaxAuditChainVerificationPageEntries {
				continue
			}
			if len(indices) < verificationapp.MaxAuditChainVerificationPageEntries {
				indices = append(indices, 0)
			}
			copy(indices[position+1:], indices[position:])
			indices[position] = index
		}
		page := verificationapp.AuditChainVerificationPage{Bindings: map[string]verificationapp.AuditSignatureBinding{}}
		budget := memoryCustomerSnapshotBudget{remainingBytes: maxBytes}
		refs := []string{}
		seen := map[string]bool{}
		for _, i := range indices {
			if err := ctx.Err(); err != nil {
				return err
			}
			e := entries[i]
			if !memoryCustomerSnapshotID(e.ID, false) || !memoryGovernanceText(e.SignatureRef, 1024) || !memoryGovernanceText(e.SubjectID, 1024) {
				return ErrConflict
			}
			raw, err := json.Marshal(e)
			if err != nil || budget.chargeJSON(raw) != nil || jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: 4096, MaxStringBytes: verificationapp.MaxAuditChainVerificationBytes}) != nil {
				return ErrConflict
			}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var detached domain.AuditChainEntry
			if err := decoder.Decode(&detached); err != nil {
				return ErrConflict
			}
			page.Entries = append(page.Entries, verificationdomain.AuditChainEntry(detached))
			if e.SignatureRef == "" {
				continue
			}
			if !seen[e.SignatureRef] {
				seen[e.SignatureRef] = true
				refs = append(refs, e.SignatureRef)
			}
			binding, ok := memoryCustomerAuditBinding(s, e)
			if !ok {
				continue
			}
			if !memoryGovernanceText(binding.Payload, 1024) || !memoryGovernanceText(binding.Subject.ID, 1024) || !memoryGovernanceText(binding.Subject.Type, 64) {
				return ErrConflict
			}
			raw, err = json.Marshal(binding)
			if err != nil || budget.chargeJSON(raw) != nil {
				return ErrConflict
			}
			page.Bindings[e.ID] = binding
		}
		var material memoryVerificationPublicMaterial
		if err := readMemoryVerificationPublicMaterial(ctx, s, view.TenantID, refs, &budget, &material); err != nil {
			return err
		}
		page.Signatures, page.Keys = material.Signatures, material.Keys
		// Include page framing and the byte-count field itself. Core consumes
		// this same exact encoding across pages under one combined budget.
		if len(page.Entries) > 0 {
			for {
				raw, err := json.Marshal(page)
				if err != nil || len(raw) > maxBytes {
					return ErrConflict
				}
				if page.BytesRead == len(raw) {
					break
				}
				page.BytesRead = len(raw)
			}
		}
		out = page
		return ctx.Err()
	})
	if err != nil {
		return verificationapp.AuditChainVerificationPage{}, err
	}
	return out, nil
}

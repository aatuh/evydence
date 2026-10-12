package app

import (
	"context"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var _ verificationquery.SigningKeyReader = memorySignatureRepository{}

// This typed test adapter keeps only page-size+1 candidate coordinates before
// projecting public metadata. It models keyset semantics, not SQL work/transfer
// bounds, encrypted storage, database locks or durability.
func (r memorySignatureRepository) PageSigningKeys(ctx context.Context, req verificationquery.SigningKeyPageRequest) (appquery.Result[verificationdomain.SigningKey], error) {
	var out appquery.Result[verificationdomain.SigningKey]
	if err := appquery.Validate(req.Page, req.After); err != nil {
		return out, err
	}
	type candidate struct {
		id string
		at time.Time
	}
	var cursor *candidate
	if req.After != nil {
		c := candidate{id: req.After.ID}
		if req.Page.Sort == appquery.SortCreatedAt {
			at, err := time.Parse(time.RFC3339Nano, req.After.Value)
			if err != nil || at.UTC().Format(time.RFC3339Nano) != req.After.Value {
				return out, appquery.ErrInvalidCursor
			}
			c.at = at
		} else if req.After.Value != req.After.ID {
			return out, appquery.ErrInvalidCursor
		}
		cursor = &c
	}
	before := func(a, b candidate) bool {
		comparison := 0
		if req.Page.Sort == appquery.SortCreatedAt {
			comparison = a.at.Compare(b.at)
		}
		if comparison == 0 {
			comparison = strings.Compare(a.id, b.id)
		}
		if req.Page.Direction == appquery.Descending {
			return comparison > 0
		}
		return comparison < 0
	}
	err := memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		points := make([]candidate, 0, req.Page.PageSize+1)
		for id, key := range s.SigningKeys {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := candidate{id: id, at: key.CreatedAt}
			if key.TenantID != req.TenantID || cursor != nil && !before(*cursor, c) {
				continue
			}
			position := sort.Search(len(points), func(i int) bool { return before(c, points[i]) })
			if position >= req.Page.PageSize+1 {
				continue
			}
			if len(points) < req.Page.PageSize+1 {
				points = append(points, candidate{})
			}
			copy(points[position+1:], points[position:])
			points[position] = c
		}
		items := make([]verificationdomain.SigningKey, 0, len(points))
		for _, c := range points {
			if err := ctx.Err(); err != nil {
				return err
			}
			key := s.SigningKeys[c.id]
			if key.ID != c.id || key.ID == "" || !memoryGovernanceText(key.ID, 1024) || key.CreatedAt.IsZero() {
				return verificationquery.ErrSigningKeyProjection
			}
			status, err := verificationdomain.ParseSigningKeyStatus(key.Status)
			if err != nil {
				return verificationquery.ErrSigningKeyProjection
			}
			// Private key bytes are neither copied nor validated by this read.
			items = append(items, verificationdomain.SigningKey{ID: key.ID, TenantID: key.TenantID, KID: key.KID, Version: key.Version, Provider: key.Provider, Algorithm: key.Algorithm, Status: status, PublicKey: key.PublicKey, PublicKeyFingerprint: key.PublicKeyFingerprint, ValidFrom: key.ValidFrom.UTC(), ValidUntil: cloneTimePtr(key.ValidUntil), CreatedAt: key.CreatedAt.UTC(), RevokedAt: cloneTimePtr(key.RevokedAt), RevocationReason: key.RevocationReason, RevocationSemantics: key.RevocationSemantics, HistoricalValidityPolicy: key.HistoricalValidityPolicy, CompromisedAt: cloneTimePtr(key.CompromisedAt)})
		}
		out = appquery.Result[verificationdomain.SigningKey]{Items: items}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
			last := out.Items[len(out.Items)-1]
			next := appquery.RecordSortKey(last.ID, last.CreatedAt, req.Page.Sort)
			out.Next = &next
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, err
	}
	return out, nil
}

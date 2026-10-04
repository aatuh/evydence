package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxPublicTransparencyDigestBytes = 128
const MaxPublicTransparencyProofNodes = 64

type PublicTransparencyProofInput struct {
	LeafHash, RootHash  string
	LeafIndex, TreeSize int
	InclusionProof      []string
}

// The reader returns one bounded entry and its assessment coordinates, never
// old check/limitation arrays, log keys, endpoints, or Merkle leaf material.
// It must resolve current tenant-owned log/checkpoint/batch references.
type PublicTransparencyVerificationReader interface {
	ReadPublicTransparencyVerification(context.Context, string, string) (d.PublicTransparencyLogEntry, error)
}
type PublicTransparencyVerificationTransaction interface {
	PublicTransparencyVerificationReader
	application.AuditAppender
	UpdatePublicTransparencyVerification(context.Context, d.PublicTransparencyLogEntry, d.PublicTransparencyLogEntry) error
}
type PublicTransparencyVerificationTransactions interface {
	ExecutePublicTransparencyVerification(context.Context, string, func(context.Context, PublicTransparencyVerificationTransaction) error) error
}
type PublicTransparencyVerificationConfig struct {
	Transactions PublicTransparencyVerificationTransactions
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PublicTransparencyVerificationCommands struct {
	config PublicTransparencyVerificationConfig
}

func NewPublicTransparencyVerificationCommands(c PublicTransparencyVerificationConfig) (*PublicTransparencyVerificationCommands, error) {
	if c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PublicTransparencyVerificationCommands{c}, nil
}
func publicTransparencyDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func NormalizePublicTransparencyProofInput(id string, in PublicTransparencyProofInput) (PublicTransparencyProofInput, error) {
	if !anomalyText(id, MaxPublicTransparencyIDBytes) || strings.TrimSpace(id) == "" || !anomalyText(in.LeafHash, MaxPublicTransparencyDigestBytes) || !anomalyText(in.RootHash, MaxPublicTransparencyDigestBytes) || len(in.InclusionProof) > MaxPublicTransparencyProofNodes || in.TreeSize <= 0 || in.LeafIndex < 0 || in.LeafIndex >= in.TreeSize {
		return PublicTransparencyProofInput{}, ErrValidation
	}
	in.LeafHash, in.RootHash = strings.TrimSpace(in.LeafHash), strings.TrimSpace(in.RootHash)
	if !publicTransparencyDigest(in.RootHash) || (in.LeafHash != "" && !publicTransparencyDigest(in.LeafHash)) {
		return PublicTransparencyProofInput{}, ErrValidation
	}
	// Preserve the legacy commitment's empty proof => JSON null normalization.
	proof := append([]string(nil), in.InclusionProof...)
	for i, node := range proof {
		if !anomalyText(node, MaxPublicTransparencyDigestBytes) {
			return PublicTransparencyProofInput{}, ErrValidation
		}
		proof[i] = strings.TrimSpace(node)
		if !publicTransparencyDigest(proof[i]) {
			return PublicTransparencyProofInput{}, ErrValidation
		}
	}
	in.InclusionProof = proof
	return in, nil
}
func ValidatePublicTransparencyVerificationSource(tenant, id string, v d.PublicTransparencyLogEntry) error {
	if v.TenantID != tenant || v.ID != id {
		return ErrNotFound
	}
	for _, s := range []string{v.ID, v.TenantID, v.LogID, v.CheckpointID, v.MerkleBatchID, v.ExternalID} {
		if !anomalyID(s) {
			return ErrValidation
		}
	}
	if !validPublicTransparencyRecord(v.ID, v.TenantID, v.CreatedAt) || v.SchemaVersion != d.PublicTransparencyEntryVersion || !publicTransparencyDigest(v.EntryHash) {
		return ErrValidation
	}
	switch v.State {
	case "published":
		if v.InclusionRootHash != "" || v.InclusionProofHash != "" || v.InclusionVerifiedAt != nil {
			return ErrValidation
		}
	case "inclusion_verified", "inclusion_not_verified":
		if !publicTransparencyDigest(v.InclusionRootHash) || !publicTransparencyDigest(v.InclusionProofHash) || v.InclusionVerifiedAt == nil || !validPublicTransparencyRecord(v.ID, v.TenantID, *v.InclusionVerifiedAt) {
			return ErrValidation
		}
	default:
		return ErrValidation
	}
	return nil
}
func ClonePublicTransparencyEntry(v d.PublicTransparencyLogEntry) d.PublicTransparencyLogEntry {
	v.VerificationChecks = append([]d.VerificationCheck(nil), v.VerificationChecks...)
	v.VerificationLimitations = append([]string(nil), v.VerificationLimitations...)
	if v.InclusionVerifiedAt != nil {
		at := *v.InclusionVerifiedAt
		v.InclusionVerifiedAt = &at
	}
	return v
}

// Compare immutable publication coordinates and the previous assessment, not
// just its state: two different proofs may have the same terminal state.
func SamePublicTransparencyAssessment(a, b d.PublicTransparencyLogEntry) bool {
	sameTime := (a.InclusionVerifiedAt == nil && b.InclusionVerifiedAt == nil) || (a.InclusionVerifiedAt != nil && b.InclusionVerifiedAt != nil && a.InclusionVerifiedAt.Equal(*b.InclusionVerifiedAt))
	return a.ID == b.ID && a.TenantID == b.TenantID && a.LogID == b.LogID && a.CheckpointID == b.CheckpointID && a.MerkleBatchID == b.MerkleBatchID && a.ExternalID == b.ExternalID && a.EntryHash == b.EntryHash && a.SchemaVersion == b.SchemaVersion && a.CreatedAt.Equal(b.CreatedAt) && a.State == b.State && a.InclusionRootHash == b.InclusionRootHash && a.InclusionProofHash == b.InclusionProofHash && sameTime
}
func BuildPublicTransparencyVerification(v d.PublicTransparencyLogEntry, in PublicTransparencyProofInput, source string, at time.Time) (d.PublicTransparencyLogEntry, error) {
	if err := ValidatePublicTransparencyVerificationSource(v.TenantID, v.ID, v); err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	if !validPublicTransparencyRecord(v.ID, v.TenantID, at) || (source != "" && source != "fetched") {
		return d.PublicTransparencyLogEntry{}, ErrValidation
	}
	in, err := NormalizePublicTransparencyProofInput(v.ID, in)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	if in.LeafHash == "" {
		in.LeafHash = v.EntryHash
	}
	bound := in.LeafHash == v.EntryHash
	valid := bound && VerifyPublicTransparencyProof(in.LeafHash, in.RootHash, in.LeafIndex, in.TreeSize, in.InclusionProof)
	result := func(ok bool) string {
		if ok {
			return "passed"
		}
		return "failed"
	}
	v.VerificationChecks = []d.VerificationCheck{{Name: "public_log_leaf_binding", Result: result(bound), Detail: "The supplied leaf hash must match the published Evydence entry hash."}, {Name: "public_log_inclusion_proof", Result: result(valid), Detail: "The supplied proof must recompute the supplied public-log root hash."}}
	v.VerificationLimitations = []string{"Evydence verifies RFC6962-style proof material locally; the material may be supplied by an operator or fetched through a configured transparency proof fetcher.", "Operators remain responsible for public-log trust, endpoint availability, and any provider-specific inclusion semantics."}
	if source == "fetched" {
		v.VerificationChecks = append(v.VerificationChecks, d.VerificationCheck{Name: "public_log_proof_source", Result: "passed", Detail: "Inclusion proof material was fetched through the configured transparency proof fetcher."})
		v.VerificationLimitations = append(v.VerificationLimitations, "Fetched proof material is trusted only as input to local verification; provider identity and availability remain deployment responsibilities.")
	}
	hash, err := application.NormalizedJSONHash(struct {
		EntryID        string   `json:"entry_id"`
		LeafHash       string   `json:"leaf_hash"`
		RootHash       string   `json:"root_hash"`
		LeafIndex      int      `json:"leaf_index"`
		TreeSize       int      `json:"tree_size"`
		InclusionProof []string `json:"inclusion_proof"`
		Source         string   `json:"source,omitempty"`
	}{v.ID, in.LeafHash, in.RootHash, in.LeafIndex, in.TreeSize, in.InclusionProof, source})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	v.InclusionRootHash, v.InclusionProofHash, v.InclusionVerifiedAt = in.RootHash, hash, &at
	v.State = "inclusion_not_verified"
	if valid {
		v.State = "inclusion_verified"
	}
	return ClonePublicTransparencyEntry(v), nil
}
func (c *PublicTransparencyVerificationCommands) authorize(ctx context.Context, a identitydomain.Actor, id string, in PublicTransparencyProofInput) (PublicTransparencyProofInput, error) {
	if c == nil {
		return PublicTransparencyProofInput{}, ErrValidation
	}
	if err := AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return PublicTransparencyProofInput{}, err
	}
	return NormalizePublicTransparencyProofInput(id, in)
}
func (c *PublicTransparencyVerificationCommands) AuthorizeVerifyPublicTransparencyLogEntry(ctx context.Context, a identitydomain.Actor, id string, in PublicTransparencyProofInput) error {
	if _, err := c.authorize(ctx, a, id, in); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	return c.config.Transactions.ExecutePublicTransparencyVerification(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyVerificationTransaction) error {
		v, err := tx.ReadPublicTransparencyVerification(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if err := ValidatePublicTransparencyVerificationSource(a.TenantID, id, v); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (c *PublicTransparencyVerificationCommands) VerifyPublicTransparencyLogEntry(ctx context.Context, a identitydomain.Actor, id string, in PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error) {
	in, err := c.authorize(ctx, a, id, in)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	id = strings.TrimSpace(id)
	var out d.PublicTransparencyLogEntry
	err = c.config.Transactions.ExecutePublicTransparencyVerification(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyVerificationTransaction) error {
		v, err := tx.ReadPublicTransparencyVerification(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if err := ValidatePublicTransparencyVerificationSource(a.TenantID, id, v); err != nil {
			return err
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		out, err = BuildPublicTransparencyVerification(v, in, "", at)
		if err != nil {
			return err
		}
		if err := tx.UpdatePublicTransparencyVerification(ctx, out, v); err != nil {
			return err
		}
		if err := AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
			return err
		}
		auditID := c.config.IDs.NewID("ace")
		if !anomalyID(auditID) {
			return ErrValidation
		}
		kind, actorID := anomalyActor(a)
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: auditID, TenantID: a.TenantID, EntryType: "public_transparency_log_entry." + out.State, SubjectType: "public_transparency_log_entry", SubjectID: id, ActorType: kind, ActorID: actorID, PayloadHash: out.InclusionProofHash, OccurredAt: at})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return ClonePublicTransparencyEntry(out), nil
}
func VerifyPublicTransparencyProof(leafHash, rootHash string, leafIndex, treeSize int, proof []string) bool {
	if treeSize <= 0 || leafIndex < 0 || leafIndex >= treeSize || len(proof) > MaxPublicTransparencyProofNodes || !publicTransparencyDigest(leafHash) || !publicTransparencyDigest(rootHash) {
		return false
	}
	node, _ := hex.DecodeString(leafHash[7:])
	root, _ := hex.DecodeString(rootHash[7:])
	index, last, n := leafIndex, treeSize-1, 0
	for last > 0 {
		if n >= len(proof) || !publicTransparencyDigest(proof[n]) {
			return false
		}
		sibling, _ := hex.DecodeString(proof[n][7:])
		h := sha256.New()
		h.Write([]byte{0x01})
		if index%2 == 1 || index == last {
			h.Write(sibling)
			h.Write(node)
			for index%2 == 0 && index != 0 {
				index /= 2
				last /= 2
			}
		} else {
			h.Write(node)
			h.Write(sibling)
		}
		node = h.Sum(nil)
		index /= 2
		last /= 2
		n++
	}
	return n == len(proof) && bytes.Equal(node, root)
}
func EncodePublicTransparencyVerification(v d.PublicTransparencyLogEntry) ([]byte, error) {
	checks := make([]map[string]string, len(v.VerificationChecks))
	for i, c := range v.VerificationChecks {
		checks[i] = map[string]string{"name": c.Name, "result": c.Result, "detail": c.Detail}
	}
	return json.Marshal(map[string]any{"id": v.ID, "tenant_id": v.TenantID, "log_id": v.LogID, "checkpoint_id": v.CheckpointID, "merkle_batch_id": v.MerkleBatchID, "external_id": v.ExternalID, "entry_hash": v.EntryHash, "state": v.State, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt, "inclusion_root_hash": v.InclusionRootHash, "inclusion_proof_hash": v.InclusionProofHash, "inclusion_verified_at": v.InclusionVerifiedAt, "verification_checks": checks, "verification_limitations": v.VerificationLimitations})
}

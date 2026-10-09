package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type VerifyCosignInput struct {
	ArtifactSignatureID string
	ExpectedIdentity    string
	ExpectedIssuer      string
	Mode                CosignVerificationMode
	Offline             bool
}

type CreateSigningProviderInput struct {
	Name      string
	Type      string
	KeyRef    string
	Encrypted bool
}

type SigningKeyRevocationInput struct {
	Reason                   string
	Semantics                string
	HistoricalValidityPolicy string
}

type CreateMerkleBatchInput struct {
	FromSequence int64
	ToSequence   int64
}

type CreateTransparencyCheckpointInput struct {
	BatchID     string
	Provider    string
	ExternalURL string
	ExternalID  string
}

type CreateObjectRetentionPolicyInput struct {
	Name                    string
	ObjectPrefix            string
	ObjectKey               string
	Mode                    string
	RetentionDays           int
	MaxVerificationAgeHours int
	RequireLegalHold        bool
}

const (
	defaultRetentionVerificationAgeHours = 24
	maxRetentionVerificationAgeHours     = 24 * 366
)

func cosignVerificationProfile(mode CosignVerificationMode, digest string) domain.VerificationProfile {
	return verificationProfileFromContext(verificationapp.CosignFullProfile(verificationapp.CosignVerificationMode(mode), digest))
}

func loadCosignBundle(ctx context.Context, tenantID string, sig domain.ArtifactSignature, objects ObjectStore, store Store) ([]byte, error) {
	if objects == nil || !validDigest(sig.PayloadHash) {
		return nil, ErrVerificationFailed
	}
	_, expectedKey, err := CanonicalObjectPayloadKeys(tenantID, sig.PayloadHash)
	if err != nil || sig.PayloadRef != "object://"+expectedKey {
		return nil, ErrVerificationFailed
	}
	if lifecycle, ok := store.(ObjectPayloadLifecycleStore); ok {
		if err := RequireFinalizedObjectPayload(ctx, lifecycle, tenantID, sig.PayloadHash, expectedKey); err != nil {
			return nil, err
		}
	}
	object, err := objects.Get(ctx, expectedKey)
	if err != nil || object.Key != expectedKey || object.TenantID != tenantID || object.Digest != sig.PayloadHash || hashBytes(object.Bytes) != sig.PayloadHash {
		return nil, ErrVerificationFailed
	}
	return append([]byte(nil), object.Bytes...), nil
}

func copyBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func normalizedReadinessChecks(checks []ReadinessCheck) []ReadinessCheck {
	return operationsquery.NormalizeReadinessChecks(checks)
}

func (l *Ledger) resourceCountsLocked(tenantID string) map[string]int {
	counts := map[string]int{
		"audit_chain_entries":       len(l.chain[tenantID]),
		"artifact_signatures":       0,
		"cosign_verifications":      0,
		"evidence":                  0,
		"merkle_batches":            0,
		"object_retention_policies": 0,
		"release_bundles":           0,
		"transparency_checkpoints":  0,
	}
	for _, item := range l.evidence {
		if item.TenantID == tenantID {
			counts["evidence"]++
		}
	}
	for _, bundle := range l.bundles {
		if bundle.TenantID == tenantID {
			counts["release_bundles"]++
		}
	}
	for _, sig := range l.artifactSigs {
		if sig.TenantID == tenantID {
			counts["artifact_signatures"]++
		}
	}
	for _, verification := range l.cosignVerifs {
		if verification.TenantID == tenantID {
			counts["cosign_verifications"]++
		}
	}
	for _, batch := range l.merkleBatches {
		if batch.TenantID == tenantID {
			counts["merkle_batches"]++
		}
	}
	for _, checkpoint := range l.transparency {
		if checkpoint.TenantID == tenantID {
			counts["transparency_checkpoints"]++
		}
	}
	for _, policy := range l.retentionPolicies {
		if policy.TenantID == tenantID {
			counts["object_retention_policies"]++
		}
	}
	return counts
}

func merkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return ""
	}
	level := append([]string(nil), leaves...)
	for len(level) > 1 {
		next := []string{}
		for i := 0; i < len(level); i += 2 {
			right := level[i]
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, hashBytes([]byte(level[i]+"\n"+right)))
		}
		level = next
	}
	return level[0]
}

func validSigningProviderType(value string) bool {
	switch value {
	case "local_encrypted_dev", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm", "native_pkcs11_hsm":
		return true
	default:
		return false
	}
}

func signingProviderRefContainsSecret(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"pin-value=", "pin-source=", "password=", "secret=", "token=" + "secret"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

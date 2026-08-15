package domain

import "testing"

func TestVerificationProfileDefinitionsAreCompleteAndDefensive(t *testing.T) {
	definitions := VerificationProfileDefinitions()
	if len(definitions) < 12 {
		t.Fatalf("profile definitions=%d, want complete verification surface", len(definitions))
	}
	seen := map[string]struct{}{}
	for _, definition := range definitions {
		if definition.ID == "" || definition.Version == "" || definition.Canonicalization == "" || definition.HashAlgorithm == "" || definition.SignatureAlgorithm == "" || definition.TrustRootPolicy == "" || definition.IdentityPolicy == "" || definition.IssuerPolicy == "" || definition.TransparencyPolicy == "" || definition.ClockPolicy == "" || definition.RevocationPolicy == "" || definition.OfflinePolicy == "" {
			t.Fatalf("incomplete profile definition: %#v", definition)
		}
		if _, exists := seen[definition.ID]; exists {
			t.Fatalf("duplicate profile %q", definition.ID)
		}
		seen[definition.ID] = struct{}{}
		if len(definition.RequiredChecks) == 0 {
			t.Fatalf("profile %q has no required checks", definition.ID)
		}
	}
	for _, id := range []string{
		VerificationProfileArtifactSignatureMetadata,
		VerificationProfileCosignFull,
		VerificationProfileDSSEAttestationSignature,
		VerificationProfileReleaseBundleSignature,
		VerificationProfileMerkleCheckpoint,
		VerificationProfileTransparencyInclusion,
		VerificationProfileObjectRetention,
		VerificationProfileBackupManifest,
		VerificationProfileCustomerPackageManifest,
		VerificationProfileReleaseArtifactManifest,
	} {
		if _, ok := VerificationProfileDefinitionFor(id); !ok {
			t.Fatalf("missing profile definition %q", id)
		}
	}
	definitions[0].RequiredChecks[0] = "mutated"
	fresh, ok := VerificationProfileDefinitionFor(definitions[0].ID)
	if !ok || fresh.RequiredChecks[0] == "mutated" {
		t.Fatalf("profile definition leaked mutable state: %#v", fresh)
	}
}

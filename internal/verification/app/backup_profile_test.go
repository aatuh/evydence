package app

import (
	"reflect"
	"strings"
	"testing"
)

func TestBackupProfileVocabularyPreservesFrozenVersionsAndFreshCopies(t *testing.T) {
	for _, tc := range []struct {
		profile    string
		resources  []BackupCommitmentResource
		count      int
		headerHash string
	}{
		{BackupStateCommitmentProfileV1, BackupCommitmentProfileResourcesV1(), 97, "sha256:3ef4cc91c3263312b9bddb03f17ec18701c37bd1a7f15ffd70a726b5d8864159"},
		{BackupStateCommitmentProfileV2, BackupCommitmentProfileResourcesV2(), 98, "sha256:dd3b77b5896b352e386ac00c2d81e0845eaebf4ac25f621e986a77e494574c4a"},
		{BackupStateCommitmentProfileV3, BackupCommitmentProfileResourcesV3(), 98, "sha256:1396036ce0b4c233ae42eade4a1d5596e7f70ac80168ac22e04679870d4cc79e"},
		{BackupStateCommitmentProfile, BackupCommitmentProfileResources(), 99, "sha256:cec6c60250406b7fadb0b1bc2c9b55809cbdaf6b3314db59ba01fe79c77ca52c"},
	} {
		if len(tc.resources) != tc.count {
			t.Fatal("declared profile resource count changed", tc.profile)
		}
		d, err := NewBackupStateDigesterWithProfile(tc.profile, "tenant", tc.resources)
		if err != nil {
			t.Fatal(err)
		}
		hash, rows, _, err := d.Finish()
		if err != nil || rows != 0 || hash != tc.headerHash {
			t.Fatal("immutable profile header, order or columns changed", tc.profile, hash, err)
		}
		// These are header-only regression vectors, never completed backup
		// commitments or evidence of storage, backup completeness or restore.
	}
	v1, v2 := BackupCommitmentProfileResourcesV1(), BackupCommitmentProfileResourcesV2()
	var prior []BackupCommitmentResource
	for _, resource := range v2 {
		if resource.Name != "vulnerability_decision_supersessions" {
			prior = append(prior, resource)
		}
	}
	if !reflect.DeepEqual(prior, v1) {
		t.Fatal("v2 changed historical v1 resources")
	}
	v1[0].Name, v1[0].Columns[0] = "caller", "caller"
	v2[0].Name, v2[0].Columns[0] = "caller", "caller"
	v3 := BackupCommitmentProfileResourcesV3()
	v3[0].Name, v3[0].Columns[0] = "caller", "caller"
	v4 := BackupCommitmentProfileResources()
	v4[0].Name, v4[0].Columns[0] = "caller", "caller"
	if BackupCommitmentProfileResourcesV1()[0].Name == "caller" || BackupCommitmentProfileResourcesV2()[0].Columns[0] == "caller" || BackupCommitmentProfileResourcesV3()[0].Columns[0] == "caller" || BackupCommitmentProfileResources()[0].Columns[0] == "caller" {
		t.Fatal("caller mutated canonical profile vocabulary")
	}
}

func TestBackupProfileVocabularyExcludesCredentialsAndReplayContents(t *testing.T) {
	for _, resource := range BackupCommitmentProfileResources() {
		if resource.Name == "idempotency_records" || resource.Name == "ledger_state" || resource.Name == "resource_index" || resource.Name == "schema_migrations" || resource.Name == "vulnerability_decision_heads" || resource.Name == "vulnerability_decision_projection" {
			t.Fatal("compatibility/replay storage added to commitment", resource.Name)
		}
		for _, field := range resource.Columns {
			for _, forbidden := range []string{"private_key", "password", "secret", "token_hash", "ciphertext", "lease_token", "failure_detail"} {
				if strings.Contains(field, forbidden) {
					t.Fatal("credential material added to declared profile", resource.Name, field)
				}
			}
			if resource.Name == "api_keys" && field == "hash" || resource.Name == "customer_portal_access" && field == "hash" || resource.Name == "sso_sessions" && field == "hash" || resource.Name == "oidc_authentication_requests" && (field == "state_hash" || field == "nonce_hash") || resource.Name == "outbox_jobs" && (field == "payload" || field == "last_error") {
				t.Fatal("sensitive contents added to profile", resource.Name, field)
			}
		}
	}
}

func TestBackupProfileCommitsSessionLifecycleMetadataInNewVersion(t *testing.T) {
	if BackupStateCommitmentProfileV3 != "tenant-relational-state.v3" {
		t.Fatal("session metadata changed a frozen commitment version")
	}
	for _, resource := range BackupCommitmentProfileResourcesV3() {
		if resource.Name != "sso_sessions" {
			continue
		}
		for _, required := range []string{"last_used_at", "maximum_lifetime_seconds", "idle_timeout_seconds"} {
			found := false
			for _, column := range resource.Columns {
				if column == required {
					found = true
				}
			}
			if !found {
				t.Fatal("lifecycle metadata omitted from current commitment", required)
			}
		}
		return
	}
	t.Fatal("session resource missing from commitment")
}

func TestBackupProfileCommitsOIDCRequestMetadataWithoutCredentialHashes(t *testing.T) {
	if BackupStateCommitmentProfile != "tenant-relational-state.v4" {
		t.Fatal("new login state must not mutate a frozen commitment profile")
	}
	for _, resource := range BackupCommitmentProfileResources() {
		if resource.Name != "oidc_authentication_requests" {
			continue
		}
		want := []string{"id", "tenant_id", "provider_id", "delivery", "trust_fingerprint", "created_at", "expires_at", "consumed_at", "schema_version"}
		if !reflect.DeepEqual(resource.Columns, want) {
			t.Fatal("OIDC request metadata was omitted or credential hashes were selected", resource.Columns)
		}
		return
	}
	t.Fatal("OIDC request metadata is unclassified")
}

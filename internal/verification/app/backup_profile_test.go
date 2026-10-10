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
		{BackupStateCommitmentProfile, BackupCommitmentProfileResources(), 98, "sha256:dd3b77b5896b352e386ac00c2d81e0845eaebf4ac25f621e986a77e494574c4a"},
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
	v1, v2 := BackupCommitmentProfileResourcesV1(), BackupCommitmentProfileResources()
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
	if BackupCommitmentProfileResourcesV1()[0].Name == "caller" || BackupCommitmentProfileResources()[0].Columns[0] == "caller" {
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
			if resource.Name == "api_keys" && field == "hash" || resource.Name == "customer_portal_access" && field == "hash" || resource.Name == "sso_sessions" && field == "hash" || resource.Name == "outbox_jobs" && (field == "payload" || field == "last_error") {
				t.Fatal("sensitive contents added to profile", resource.Name, field)
			}
		}
	}
}

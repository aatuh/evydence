package app

import (
	"strings"
	"testing"
)

func TestSourceCommitReuseNormalizesSHAAndPreservesOriginal(t *testing.T) {
	l := newLegacyLedgerFixture(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, actor := bootstrapEnterpriseTestTenant(t, l)
	r, err := l.CreateSourceRepository(t.Context(), actor, CreateRepositoryInput{Provider: "git", FullName: "org/api"})
	if err != nil {
		t.Fatal(err)
	}
	in := RecordCommitInput{RepositoryID: r.ID, SHA: strings.Repeat("ab", 20), Author: " Original ", Message: " original message "}
	one, err := l.RecordSourceCommit(t.Context(), actor, in)
	if err != nil {
		t.Fatal(err)
	}
	in.SHA, in.Author, in.Message = strings.ToUpper(in.SHA), "changed", "changed"
	two, err := l.RecordSourceCommit(t.Context(), actor, in)
	if err != nil || two != one {
		t.Fatal("case-only SHA reuse changed immutable commit", one, two, err)
	}
	if len(l.commits) != 1 {
		t.Fatal("duplicate commit", len(l.commits))
	}
	var audits int
	for _, entry := range l.chain[actor.TenantID] {
		if entry.EntryType == "source_commit.recorded" {
			audits++
		}
	}
	if audits != 1 {
		t.Fatal("duplicate commit audit", audits)
	}
}

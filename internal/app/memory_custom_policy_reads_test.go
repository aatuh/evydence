package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

func memoryCustomPolicyFixture(t *testing.T) (*memoryUnitOfWork, riskapp.CustomPolicyReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	p := domain.CustomPolicy{ID: "tenant-policy", TenantID: "tenant", Name: "Policy", Version: "1", Description: "Requirements", Rules: []domain.PolicyRule{{Name: "SBOM", EvidenceType: "sbom", Severity: "high", Required: true}}, SchemaVersion: domain.CustomPolicySchemaVersion, CreatedAt: fixedNow()}
	tx.state.CustomPolicies[p.ID] = p
	reader, ok := tx.Repositories().Risk.(riskapp.CustomPolicyReader)
	if !ok {
		t.Fatal("memory Risk repository lacks focused custom-policy reader")
	}
	return tx, reader
}

func TestMemoryCustomPolicyReadsKeepCurrentOwnershipDetachedRulesAndCoherentFacts(t *testing.T) {
	tx, reader := memoryCustomPolicyFixture(t)
	tx.state.Evidence["owned-sbom"] = domain.EvidenceItem{ID: "owned-sbom", TenantID: "tenant", ReleaseID: "tenant-release", Type: "sbom", Title: strings.Repeat("private", 10000)}
	tx.state.Evidence["borrowed-threat-model"] = domain.EvidenceItem{ID: "borrowed-threat-model", TenantID: "tenant", ProductID: "foreign-product", ReleaseID: "tenant-release", Type: "threat_model"}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	value, err := reader.ReadCustomPolicy(t.Context(), "tenant", "tenant-policy")
	if err != nil || !reflect.DeepEqual(value, domain.CustomPolicyToContext(tx.state.CustomPolicies["tenant-policy"])) {
		t.Fatal("policy read lost complete selected DTO", value, err)
	}
	value.Rules[0].Name = "changed"
	presence, err := reader.ReadCustomPolicyEvidencePresence(t.Context(), "tenant", "tenant-release", []string{"sbom", "threat_model"})
	if err != nil || !reflect.DeepEqual(presence, map[string]bool{"sbom": true, "threat_model": false}) {
		t.Fatal("policy presence accepted foreign/incoherent evidence", presence, err)
	}
	presence["threat_model"] = true
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("policy/fact reads or result mutations changed repository data")
	}
	for _, id := range []string{"foreign-policy", "missing"} {
		if value, err := reader.ReadCustomPolicy(t.Context(), "tenant", id); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(value, riskdomain.CustomPolicy{}) {
			t.Fatal("foreign policy read disclosed metadata", value, err)
		}
	}
	if found, err := reader.PolicyTenantExists(t.Context(), "tenant"); err != nil || !found {
		t.Fatal("owned policy tenant missing", err)
	}
	if found, err := reader.PolicyTenantExists(t.Context(), "missing"); err != nil || found {
		t.Fatal("missing policy tenant fabricated", err)
	}
	if _, err := reader.ReadCustomPolicySubject(t.Context(), "tenant", "release", "foreign-release"); !errors.Is(err, ErrNotFound) {
		t.Fatal("policy subject crossed tenant", err)
	}
}

func TestMemoryCustomPolicyReadsRejectSelectedOverflowWithoutWideningScopeGuards(t *testing.T) {
	t.Run("exact-rule-count", func(t *testing.T) {
		tx, reader := memoryCustomPolicyFixture(t)
		p := tx.state.CustomPolicies["tenant-policy"]
		p.Rules = make([]domain.PolicyRule, 4096)
		for i := range p.Rules {
			p.Rules[i] = domain.PolicyRule{Name: "Rule", EvidenceType: "sbom", Severity: "high"}
		}
		tx.state.CustomPolicies[p.ID] = p
		if value, err := reader.ReadCustomPolicy(t.Context(), "tenant", p.ID); err != nil || len(value.Rules) != 4096 {
			t.Fatal("exact rule-count limit rejected or truncated", len(value.Rules), err)
		}
	})
	for _, change := range []string{"name", "description", "rules-count", "rules-bytes", "nil-rules", "invalid-text"} {
		t.Run(change, func(t *testing.T) {
			tx, reader := memoryCustomPolicyFixture(t)
			p := tx.state.CustomPolicies["tenant-policy"]
			switch change {
			case "name":
				p.Name = strings.Repeat("x", 1025)
			case "description":
				p.Description = strings.Repeat("x", 65537)
			case "rules-count":
				p.Rules = make([]domain.PolicyRule, 4097)
			case "rules-bytes":
				p.Rules = make([]domain.PolicyRule, 129)
				for i := range p.Rules {
					p.Rules[i] = domain.PolicyRule{Name: strings.Repeat("x", 65536), EvidenceType: "sbom", Severity: "high"}
				}
			case "nil-rules":
				p.Rules = nil
			case "invalid-text":
				p.Name = "bad\x00text"
			}
			tx.state.CustomPolicies[p.ID] = p
			if _, err := reader.ReadCustomPolicySubject(t.Context(), "tenant", "policy", p.ID); err != nil {
				t.Fatal("identifier guard read private policy definition", err)
			}
			if value, err := reader.ReadCustomPolicy(t.Context(), "tenant", p.ID); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(value, riskdomain.CustomPolicy{}) {
				t.Fatal("invalid selected policy returned partial data", err)
			}
		})
	}
}

func TestMemoryCustomPolicyReadsValidateFactVocabularyCancellationAndTransactionLifetime(t *testing.T) {
	tx, reader := memoryCustomPolicyFixture(t)
	for _, kinds := range [][]string{{"unknown"}, {"sbom", "sbom"}, make([]string, 20)} {
		if value, err := reader.ReadCustomPolicyEvidencePresence(t.Context(), "tenant", "tenant-release", kinds); !errors.Is(err, ErrValidation) || value != nil {
			t.Fatal("invalid policy fact vocabulary accepted", value, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.ReadCustomPolicy(ctx, "tenant", "tenant-policy"); !errors.Is(err, context.Canceled) {
		t.Fatal("policy ignored cancellation", err)
	}
	if _, err := reader.ReadCustomPolicyEvidencePresence(ctx, "tenant", "tenant-release", []string{"sbom"}); !errors.Is(err, context.Canceled) {
		t.Fatal("policy facts ignored cancellation", err)
	}
	var absent context.Context
	if _, err := reader.ReadCustomPolicy(absent, "tenant", "tenant-policy"); !errors.Is(err, ErrValidation) {
		t.Fatal("policy accepted nil context", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadCustomPolicy(t.Context(), "tenant", "tenant-policy"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction returned policy", err)
	}
}

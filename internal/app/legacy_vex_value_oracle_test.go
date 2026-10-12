package app

// Historical OpenVEX wrappers and constants are not runtime ingestion ports.

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	vexparser "github.com/aatuh/evydence/internal/app/parsers/vex"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

const (
	decisionStatusAffected           = "affected"
	decisionStatusNotAffected        = "not_affected"
	decisionStatusFixed              = "fixed"
	decisionStatusUnderInvestigation = "under_investigation"
)

type openVEXDocument struct {
	Context    any                `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    any                `json:"version"`
	Statements []openVEXStatement `json:"statements"`
	Warnings   []string           `json:"-"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVulnerability `json:"vulnerability"`
	Products        []openVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	Justification   string               `json:"justification"`
	ImpactStatement string               `json:"impact_statement"`
	ActionStatement string               `json:"action_statement"`
}

type openVEXVulnerability struct {
	Name string `json:"name"`
}

type openVEXProduct struct {
	ID            string           `json:"@id"`
	Subcomponents []openVEXProduct `json:"subcomponents,omitempty"`
}

func redactionProfileExcludesPackageSensitiveFields(profile domain.RedactionProfile) bool {
	required := map[string]struct{}{"payload_ref": {}, "object_key": {}, "private_key": {}, "token": {}, "secret": {}, "internal_notes": {}}
	for _, field := range profile.ExcludedFields {
		delete(required, strings.ToLower(strings.TrimSpace(field)))
	}
	return len(required) == 0
}

func parseOpenVEX(raw []byte) (openVEXDocument, error) {
	return parseOpenVEXReader(bytes.NewReader(raw))
}

func parseOpenVEXReader(reader io.Reader) (openVEXDocument, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, EvidenceDocumentLimit+1))
	if err != nil || int64(len(raw)) > EvidenceDocumentLimit {
		return openVEXDocument{}, vexValidationError("openvex JSON is malformed")
	}
	parsed, err := vexparser.ParseOpenVEX(raw, vexparser.DefaultLimits(EvidenceDocumentLimit))
	if err != nil {
		return openVEXDocument{}, vexValidationError("openvex JSON is malformed or violates required OpenVEX fields")
	}
	doc := openVEXDocument{Author: parsed.Author, Version: parsed.Version, Warnings: parsed.Warnings}
	for _, statement := range parsed.Statements {
		products := make([]openVEXProduct, 0, len(statement.Products))
		for _, product := range statement.Products {
			products = append(products, openVEXProduct{ID: product})
		}
		doc.Statements = append(doc.Statements, openVEXStatement{Vulnerability: openVEXVulnerability{Name: statement.Vulnerability}, Products: products, Status: statement.Status, Justification: statement.Justification, ImpactStatement: statement.ImpactStatement, ActionStatement: statement.ActionStatement})
	}
	return doc, nil
}

func vexValidationError(detail string) error {
	return fmt.Errorf("%s: %w", detail, ErrValidation)
}

func validDecisionStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case decisionStatusAffected, decisionStatusNotAffected, decisionStatusFixed, decisionStatusUnderInvestigation:
		return true
	default:
		return false
	}
}

func openVEXProductIDs(products []openVEXProduct) map[string]struct{} {
	out := map[string]struct{}{}
	var walk func([]openVEXProduct)
	walk = func(items []openVEXProduct) {
		for _, item := range items {
			if id := strings.TrimSpace(item.ID); id != "" {
				out[id] = struct{}{}
			}
			walk(item.Subcomponents)
		}
	}
	walk(products)
	return out
}

func decisionEvidenceIDs(primary string, extra []string) []string {
	ids := append([]string(nil), extra...)
	if strings.TrimSpace(primary) != "" {
		ids = append(ids, strings.TrimSpace(primary))
	}
	return sortedUniqueNonEmptyStrings(ids)
}

func vexImportIssue(statementIndex int, code, detail string) domain.VEXImportIssue {
	return domain.VEXImportIssue{StatementIndex: statementIndex, Code: code, Detail: detail}
}

func vexImportPreviewAssumptions() []string {
	return evidencedomain.VEXPreviewAssumptions()
}

func vexImportPreviewLimitations() []string {
	return evidencedomain.VEXPreviewLimitations()
}

func sortedUniqueNonEmptyStrings(in []string) []string {
	set := map[string]struct{}{}
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

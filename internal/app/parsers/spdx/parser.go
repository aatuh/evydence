// Package spdx parses the bounded SPDX JSON subset Evydence normalizes. It
// preserves the source document as immutable evidence; values outside this
// subset are reported as warnings instead of being discarded silently.
package spdx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const ParserVersion = "spdx-json.v2.0.0"

var ErrInvalid = errors.New("invalid SPDX document")

type Limits struct {
	MaxBytes                                                                                          int64
	MaxDepth, MaxPackages, MaxRelationships, MaxChecksums, MaxExternalRefs, MaxStringBytes, MaxValues int
}

func DefaultLimits(maxBytes int64) Limits {
	return Limits{MaxBytes: maxBytes, MaxDepth: 64, MaxPackages: 100000, MaxRelationships: 200000, MaxChecksums: 500000, MaxExternalRefs: 500000, MaxStringBytes: 1 << 20, MaxValues: 1000000}
}

type Package struct {
	SPDXID, Name, Version, PURL, Identity string
}

type Relationship struct{ From, Type, To string }

type Result struct {
	SpecVersion                                         string
	Packages                                            []Package
	Relationships                                       []Relationship
	ChecksumCount, LicenseCount, ExternalReferenceCount int
	Warnings, UnsupportedPaths                          []string
}

func ParseBounded(raw []byte, limits Limits) (Result, error) {
	return ParseBoundedReader(bytes.NewReader(raw), limits)
}

func ParseBoundedReader(reader io.Reader, limits Limits) (Result, error) {
	if reader == nil || !validLimits(limits) {
		return Result{}, ErrInvalid
	}
	limited := &io.LimitedReader{R: reader, N: limits.MaxBytes + 1}
	var raw bytes.Buffer
	if err := preflight(io.TeeReader(limited, &raw), limits); err != nil || limited.N == 0 {
		return Result{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw.Bytes()))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil || !requireEOF(dec) {
		return Result{}, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Result{}, ErrInvalid
	}
	return parseRoot(root, limits)
}

func validLimits(l Limits) bool {
	return l.MaxBytes > 0 && l.MaxDepth > 0 && l.MaxPackages > 0 && l.MaxRelationships > 0 && l.MaxChecksums > 0 && l.MaxExternalRefs > 0 && l.MaxStringBytes > 0 && l.MaxValues > 0
}

func preflight(reader io.Reader, limits Limits) error {
	dec := json.NewDecoder(reader)
	dec.UseNumber()
	token, err := dec.Token()
	if err != nil {
		return ErrInvalid
	}
	count := 0
	if err := scanValue(dec, token, 1, limits, &count); err != nil {
		return err
	}
	_, err = dec.Token()
	if !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanValue(dec *json.Decoder, token json.Token, depth int, limits Limits, count *int) error {
	*count++
	if *count > limits.MaxValues || depth > limits.MaxDepth {
		return ErrInvalid
	}
	if text, ok := token.(string); ok && len(text) > limits.MaxStringBytes {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	for dec.More() {
		if depth >= limits.MaxDepth || *count >= limits.MaxValues {
			return ErrInvalid
		}
		var next json.Token
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return ErrInvalid
			}
			var keyOK bool
			next, keyOK = key.(string)
			if !keyOK || len(next.(string)) > limits.MaxStringBytes {
				return ErrInvalid
			}
			if _, exists := seen[next.(string)]; exists {
				return ErrInvalid
			}
			seen[next.(string)] = struct{}{}
		}
		value, err := dec.Token()
		if err != nil {
			return ErrInvalid
		}
		if err := scanValue(dec, value, depth+1, limits, count); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || end != matchingEnd(delim) {
		return ErrInvalid
	}
	return nil
}

func matchingEnd(start json.Delim) json.Delim {
	if start == '{' {
		return '}'
	}
	if start == '[' {
		return ']'
	}
	return 0
}

func requireEOF(dec *json.Decoder) bool {
	var extra any
	return errors.Is(dec.Decode(&extra), io.EOF)
}

func parseRoot(root map[string]any, limits Limits) (Result, error) {
	version := stringValue(root["spdxVersion"])
	if (version != "SPDX-2.2" && version != "SPDX-2.3") || !rootPackagesAreValid(root, limits) {
		return Result{}, ErrInvalid
	}
	if creationInfo := root["creationInfo"]; creationInfo != nil && !validCreationInfo(creationInfo) {
		return Result{}, ErrInvalid
	}
	packages := root["packages"].([]any)
	result := Result{SpecVersion: version}
	for i, item := range packages {
		pkg, checksums, externalRefs, licenses, paths, err := parsePackage(item, i, limits)
		if err != nil {
			return Result{}, err
		}
		result.Packages = append(result.Packages, pkg)
		result.ChecksumCount += checksums
		result.ExternalReferenceCount += externalRefs
		result.LicenseCount += licenses
		result.UnsupportedPaths = append(result.UnsupportedPaths, paths...)
	}
	relationships, paths, err := parseRelationships(root["relationships"], limits)
	if err != nil {
		return Result{}, err
	}
	result.Relationships = relationships
	result.UnsupportedPaths = append(result.UnsupportedPaths, unknownPaths(root, "$", knownRootFields)...)
	result.UnsupportedPaths = append(result.UnsupportedPaths, paths...)
	sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].Identity < result.Packages[j].Identity })
	sort.Slice(result.Relationships, func(i, j int) bool {
		return relationshipKey(result.Relationships[i]) < relationshipKey(result.Relationships[j])
	})
	sort.Strings(result.UnsupportedPaths)
	for _, path := range result.UnsupportedPaths {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%s is preserved in raw evidence but is not normalized by parser %s", path, ParserVersion))
	}
	return result, nil
}

func rootPackagesAreValid(root map[string]any, limits Limits) bool {
	packages, ok := root["packages"].([]any)
	return ok && len(packages) <= limits.MaxPackages
}

func validCreationInfo(value any) bool {
	info, ok := value.(map[string]any)
	if !ok || !nonEmpty(info["created"]) {
		return false
	}
	if _, err := time.Parse(time.RFC3339, stringValue(info["created"])); err != nil {
		return false
	}
	creators, ok := info["creators"].([]any)
	if !ok || len(creators) == 0 {
		return false
	}
	for _, creator := range creators {
		if !nonEmpty(creator) {
			return false
		}
	}
	return true
}

func parsePackage(value any, index int, limits Limits) (Package, int, int, int, []string, error) {
	pkg, ok := value.(map[string]any)
	if !ok || !nonEmpty(pkg["name"]) {
		return Package{}, 0, 0, 0, nil, ErrInvalid
	}
	checksums, err := countObjects(pkg["checksums"], limits.MaxChecksums, []string{"algorithm", "checksumValue"})
	if err != nil {
		return Package{}, 0, 0, 0, nil, err
	}
	externalRefs, err := countObjects(pkg["externalRefs"], limits.MaxExternalRefs, []string{"referenceType", "referenceLocator"})
	if err != nil {
		return Package{}, 0, 0, 0, nil, err
	}
	purl := ""
	if refs, _ := pkg["externalRefs"].([]any); refs != nil {
		for _, row := range refs {
			ref, _ := row.(map[string]any)
			if strings.EqualFold(stringValue(ref["referenceType"]), "purl") && nonEmpty(ref["referenceLocator"]) {
				purl = strings.TrimSpace(stringValue(ref["referenceLocator"]))
				break
			}
		}
	}
	spdxID := strings.TrimSpace(stringValue(pkg["SPDXID"]))
	identity := "spdx:legacy:" + strings.TrimSpace(stringValue(pkg["name"])) + "@" + strings.TrimSpace(stringValue(pkg["versionInfo"]))
	if spdxID != "" {
		identity = "spdx:" + spdxID
	}
	if purl != "" {
		identity = "purl:" + purl
	}
	licenses := 0
	if nonEmpty(pkg["licenseConcluded"]) {
		licenses++
	}
	if nonEmpty(pkg["licenseDeclared"]) {
		licenses++
	}
	return Package{SPDXID: spdxID, Name: strings.TrimSpace(stringValue(pkg["name"])), Version: strings.TrimSpace(stringValue(pkg["versionInfo"])), PURL: purl, Identity: identity}, checksums, externalRefs, licenses, unknownPaths(pkg, fmt.Sprintf("$.packages[%d]", index), knownPackageFields), nil
}

func parseRelationships(value any, limits Limits) ([]Relationship, []string, error) {
	if value == nil {
		return nil, nil, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limits.MaxRelationships {
		return nil, nil, ErrInvalid
	}
	result, paths := make([]Relationship, 0, len(rows)), []string{}
	for i, value := range rows {
		row, ok := value.(map[string]any)
		if !ok || !nonEmpty(row["spdxElementId"]) || !nonEmpty(row["relationshipType"]) || !nonEmpty(row["relatedSpdxElement"]) {
			return nil, nil, ErrInvalid
		}
		result = append(result, Relationship{From: strings.TrimSpace(stringValue(row["spdxElementId"])), Type: strings.TrimSpace(stringValue(row["relationshipType"])), To: strings.TrimSpace(stringValue(row["relatedSpdxElement"]))})
		paths = append(paths, unknownPaths(row, fmt.Sprintf("$.relationships[%d]", i), knownRelationshipFields)...)
	}
	return result, paths, nil
}

func countObjects(value any, limit int, required []string) (int, error) {
	if value == nil {
		return 0, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > limit {
		return 0, ErrInvalid
	}
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return 0, ErrInvalid
		}
		for _, key := range required {
			if !nonEmpty(row[key]) {
				return 0, ErrInvalid
			}
		}
	}
	return len(rows), nil
}

func stringValue(value any) string          { text, _ := value.(string); return text }
func nonEmpty(value any) bool               { return strings.TrimSpace(stringValue(value)) != "" }
func relationshipKey(r Relationship) string { return r.From + "\x00" + r.Type + "\x00" + r.To }
func unknownPaths(object map[string]any, prefix string, known map[string]struct{}) []string {
	paths := []string{}
	for key := range object {
		if _, ok := known[key]; !ok {
			paths = append(paths, prefix+"."+key)
		}
	}
	return paths
}

var knownRootFields = keys("spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages", "files", "snippets", "relationships", "annotations", "documentDescribes", "externalDocumentRefs", "hasExtractedLicensingInfos", "revieweds", "comment", "licenseListVersion")
var knownPackageFields = keys("SPDXID", "name", "versionInfo", "downloadLocation", "filesAnalyzed", "packageVerificationCode", "checksums", "homepage", "sourceInfo", "licenseConcluded", "licenseInfoFromFiles", "licenseDeclared", "licenseComments", "copyrightText", "summary", "description", "comment", "externalRefs", "attributionTexts", "primaryPackagePurpose", "releaseDate", "builtDate", "validUntilDate", "supplier", "originator", "packageFileName")
var knownRelationshipFields = keys("spdxElementId", "relationshipType", "relatedSpdxElement", "comment")

func keys(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

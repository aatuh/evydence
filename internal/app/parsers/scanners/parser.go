// Package scanners parses bounded, versioned vulnerability scanner envelopes.
// Native reports are preserved as raw evidence; this package only produces a
// deterministic normalized projection and never treats a scanner as authority.
package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

const ParserVersion = "scanner-adapters-json.v1.0.0"

var ErrInvalid = errors.New("invalid vulnerability scanner document")

type Limits struct {
	MaxBytes                                         int64
	MaxDepth, MaxFindings, MaxStringBytes, MaxValues int
}

func DefaultLimits(maxBytes int64) Limits {
	return Limits{MaxBytes: maxBytes, MaxDepth: 64, MaxFindings: 100000, MaxStringBytes: 1 << 20, MaxValues: 1000000}
}

type Identity struct {
	CVE            string `json:"cve,omitempty"`
	GHSA           string `json:"ghsa,omitempty"`
	OSV            string `json:"osv,omitempty"`
	VendorAdvisory string `json:"vendor_advisory,omitempty"`
	PURL           string `json:"purl,omitempty"`
	CPE            string `json:"cpe,omitempty"`
}

type Finding struct {
	Vulnerability  string   `json:"vulnerability"`
	Component      string   `json:"component,omitempty"`
	Severity       string   `json:"severity"`
	State          string   `json:"state"`
	SeveritySource string   `json:"severity_source,omitempty"`
	FixVersion     string   `json:"fix_version,omitempty"`
	Identity       Identity `json:"identity"`
}

type Result struct {
	Scanner        string    `json:"scanner"`
	TargetRef      string    `json:"target_ref"`
	ReleaseID      string    `json:"release_id"`
	Adapter        string    `json:"adapter"`
	AdapterVersion string    `json:"adapter_version"`
	SourceSchema   string    `json:"source_schema"`
	Findings       []Finding `json:"findings"`
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
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) {
		return Result{}, ErrInvalid
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Result{}, ErrInvalid
	}
	return parseRoot(root, limits)
}

// ProbeReleaseIDBoundedReader extracts the top-level release scope without
// materializing or normalizing scanner findings. It deliberately traverses the
// complete JSON token stream so release_id can appear in any field order while
// duplicate fields and the parser's byte, depth, value, string, and selected
// adapter finding limits still fail closed.
func ProbeReleaseIDBoundedReader(reader io.Reader, limits Limits) (string, error) {
	if reader == nil || !validLimits(limits) {
		return "", ErrInvalid
	}
	limited := &io.LimitedReader{R: reader, N: limits.MaxBytes + 1}
	dec := json.NewDecoder(limited)
	dec.UseNumber()
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return "", ErrInvalid
	}
	probe := vulnerabilityScopeProbe{}
	count := 0
	if err := scanValueWithProbe(dec, start, 1, limits, &count, probeRoot, &probe); err != nil {
		return "", err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) || limited.N == 0 || probe.releaseID == "" || probe.findingCount() > limits.MaxFindings {
		return "", ErrInvalid
	}
	return probe.releaseID, nil
}

func validLimits(limits Limits) bool {
	return limits.MaxBytes > 0 && limits.MaxDepth > 0 && limits.MaxFindings > 0 && limits.MaxStringBytes > 0 && limits.MaxValues > 0
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
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
func scanValue(dec *json.Decoder, token json.Token, depth int, limits Limits, count *int) error {
	return scanValueWithProbe(dec, token, depth, limits, count, probeOther, nil)
}

type probeLocation uint8

const (
	probeOther probeLocation = iota
	probeRoot
	probePayload
	probeGenericFindings
	probeGrypeMatches
	probeTrivyResults
	probeTrivyResult
	probeTrivyVulnerabilities
	probeOSVResults
	probeOSVResult
	probeOSVPackages
	probeOSVPackage
	probeOSVVulnerabilities
	probeDependencyTrackFindings
)

type vulnerabilityScopeProbe struct {
	releaseID               string
	scanner                 string
	hasPayload              bool
	genericFindings         int
	grypeMatches            int
	trivyVulnerabilities    int
	osvVulnerabilities      int
	dependencyTrackFindings int
}

func (p *vulnerabilityScopeProbe) observeRootField(key string, value json.Token) error {
	switch key {
	case "release_id":
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return ErrInvalid
		}
		p.releaseID = strings.TrimSpace(text)
	case "scanner":
		if text, ok := value.(string); ok {
			p.scanner = strings.ToLower(strings.TrimSpace(text))
		}
	case "payload":
		p.hasPayload = true
	}
	return nil
}

func (p vulnerabilityScopeProbe) findingCount() int {
	if !p.hasPayload {
		return p.genericFindings
	}
	switch p.scanner {
	case "grype":
		return p.grypeMatches
	case "trivy":
		return p.trivyVulnerabilities
	case "osv-scanner":
		return p.osvVulnerabilities
	case "dependency-track":
		return p.dependencyTrackFindings
	default:
		return 0
	}
}

func probeChildLocation(parent probeLocation, key string) probeLocation {
	switch parent {
	case probeRoot:
		switch key {
		case "payload":
			return probePayload
		case "findings":
			return probeGenericFindings
		}
	case probePayload:
		switch key {
		case "matches":
			return probeGrypeMatches
		case "Results":
			return probeTrivyResults
		case "results":
			return probeOSVResults
		case "findings":
			return probeDependencyTrackFindings
		}
	case probeTrivyResult:
		if key == "Vulnerabilities" {
			return probeTrivyVulnerabilities
		}
	case probeOSVResult:
		if key == "packages" {
			return probeOSVPackages
		}
	case probeOSVPackage:
		if key == "vulnerabilities" {
			return probeOSVVulnerabilities
		}
	}
	return probeOther
}

func probeElementLocation(parent probeLocation) probeLocation {
	switch parent {
	case probeTrivyResults:
		return probeTrivyResult
	case probeOSVResults:
		return probeOSVResult
	case probeOSVPackages:
		return probeOSVPackage
	default:
		return probeOther
	}
}

func (p *vulnerabilityScopeProbe) observeArrayElement(location probeLocation) {
	switch location {
	case probeGenericFindings:
		p.genericFindings++
	case probeGrypeMatches:
		p.grypeMatches++
	case probeTrivyVulnerabilities:
		p.trivyVulnerabilities++
	case probeOSVVulnerabilities:
		p.osvVulnerabilities++
	case probeDependencyTrackFindings:
		p.dependencyTrackFindings++
	}
}

func scanValueWithProbe(dec *json.Decoder, token json.Token, depth int, limits Limits, count *int, location probeLocation, probe *vulnerabilityScopeProbe) error {
	*count++
	if *count > limits.MaxValues || depth > limits.MaxDepth {
		return ErrInvalid
	}
	if s, ok := token.(string); ok && len(s) > limits.MaxStringBytes {
		return ErrInvalid
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	for dec.More() {
		if depth >= limits.MaxDepth {
			return ErrInvalid
		}
		key := ""
		if delim == '{' {
			keyToken, err := dec.Token()
			if err != nil {
				return ErrInvalid
			}
			text, ok := keyToken.(string)
			if !ok || len(text) > limits.MaxStringBytes {
				return ErrInvalid
			}
			if _, duplicate := seen[text]; duplicate {
				return ErrInvalid
			}
			seen[text] = struct{}{}
			key = text
		}
		next, err := dec.Token()
		if err != nil {
			return ErrInvalid
		}
		childLocation := probeOther
		if probe != nil {
			switch delim {
			case '{':
				if location == probeRoot {
					if err := probe.observeRootField(key, next); err != nil {
						return err
					}
				}
				childLocation = probeChildLocation(location, key)
			case '[':
				probe.observeArrayElement(location)
				childLocation = probeElementLocation(location)
			}
		}
		if err := scanValueWithProbe(dec, next, depth+1, limits, count, childLocation, probe); err != nil {
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

func parseRoot(root map[string]any, limits Limits) (Result, error) {
	if payload, envelope := root["payload"]; envelope {
		return parseEnvelope(root, payload, limits)
	}
	return parseGeneric(root, limits)
}

func parseEnvelope(root map[string]any, payload any, limits Limits) (Result, error) {
	if !only(root, "scanner", "target_ref", "release_id", "source_schema", "payload") {
		return Result{}, ErrInvalid
	}
	scanner, target, release, schema := text(root["scanner"]), text(root["target_ref"]), text(root["release_id"]), text(root["source_schema"])
	if scanner == "" || target == "" || release == "" || schema == "" {
		return Result{}, ErrInvalid
	}
	native, ok := payload.(map[string]any)
	if !ok {
		return Result{}, ErrInvalid
	}
	var findings []Finding
	var err error
	adapter := strings.ToLower(scanner)
	switch adapter {
	case "grype":
		if schema != "grype-json.v1" {
			return Result{}, ErrInvalid
		}
		findings, err = parseGrype(native, limits)
	case "trivy":
		if schema != "trivy-json.v1" {
			return Result{}, ErrInvalid
		}
		findings, err = parseTrivy(native, limits)
	case "osv-scanner":
		if schema != "osv-scanner-json.v1" {
			return Result{}, ErrInvalid
		}
		findings, err = parseOSV(native, limits)
	case "dependency-track":
		if schema != "dependency-track-json.v1" {
			return Result{}, ErrInvalid
		}
		findings, err = parseDependencyTrack(native, limits)
	default:
		return Result{}, ErrInvalid
	}
	if err != nil {
		return Result{}, ErrInvalid
	}
	return Result{Scanner: scanner, TargetRef: target, ReleaseID: release, Adapter: adapter, AdapterVersion: ParserVersion, SourceSchema: schema, Findings: findings}, nil
}

func parseGeneric(root map[string]any, limits Limits) (Result, error) {
	if !only(root, "scanner", "target_ref", "release_id", "findings") {
		return Result{}, ErrInvalid
	}
	scanner, target, release := text(root["scanner"]), text(root["target_ref"]), text(root["release_id"])
	rows, ok := root["findings"].([]any)
	if scanner == "" || target == "" || release == "" || !ok || len(rows) > limits.MaxFindings {
		return Result{}, ErrInvalid
	}
	findings := make([]Finding, 0, len(rows))
	for _, row := range rows {
		f, err := parseGenericFinding(row)
		if err != nil {
			return Result{}, ErrInvalid
		}
		findings = append(findings, f)
	}
	return Result{Scanner: scanner, TargetRef: target, ReleaseID: release, Adapter: "generic", AdapterVersion: ParserVersion, SourceSchema: "generic-vulnerability-scan-json.v1", Findings: findings}, nil
}

func parseGenericFinding(value any) (Finding, error) {
	row, ok := value.(map[string]any)
	if !ok || !only(row, "vulnerability", "component", "severity", "state", "severity_source", "fix_version", "identity") {
		return Finding{}, ErrInvalid
	}
	f := Finding{Vulnerability: text(row["vulnerability"]), Component: text(row["component"]), Severity: severity(row["severity"]), State: nonEmpty(text(row["state"]), "open"), SeveritySource: text(row["severity_source"]), FixVersion: text(row["fix_version"])}
	if f.Vulnerability == "" || f.Severity == "" {
		return Finding{}, ErrInvalid
	}
	if identity, set := row["identity"]; set {
		parsed, err := parseIdentity(identity, nil, f.Component)
		if err != nil {
			return Finding{}, err
		}
		f.Identity = parsed
	} else {
		parsed, err := parseIdentity(nil, []string{f.Vulnerability}, f.Component)
		if err != nil {
			return Finding{}, err
		}
		f.Identity = parsed
	}
	return f, nil
}

func parseGrype(root map[string]any, limits Limits) ([]Finding, error) {
	rows, ok := root["matches"].([]any)
	if !ok || len(rows) > limits.MaxFindings {
		return nil, ErrInvalid
	}
	out := make([]Finding, 0, len(rows))
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		vuln, ok := row["vulnerability"].(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		artifact, ok := row["artifact"].(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		aliases, err := stringsList(vuln["aliases"])
		if err != nil {
			return nil, err
		}
		ids, err := parseIdentity(nil, append([]string{text(vuln["id"])}, aliases...), text(artifact["purl"]))
		if err != nil {
			return nil, err
		}
		cpes, err := stringsList(artifact["cpes"])
		if err != nil {
			return nil, err
		}
		if ids.CPE == "" && len(cpes) > 0 {
			ids.CPE = cpes[0]
		}
		fix := ""
		if info, _ := vuln["fix"].(map[string]any); info != nil {
			versions, err := stringsList(info["versions"])
			if err != nil {
				return nil, err
			}
			if len(versions) > 0 {
				fix = versions[0]
			}
		}
		out = append(out, finding(ids, severity(vuln["severity"]), "open", "grype", fix))
	}
	return out, nil
}

func parseTrivy(root map[string]any, limits Limits) ([]Finding, error) {
	results, ok := root["Results"].([]any)
	if !ok || len(results) > limits.MaxFindings {
		return nil, ErrInvalid
	}
	out := []Finding{}
	for _, result := range results {
		section, ok := result.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		rows, ok := section["Vulnerabilities"]
		if !ok {
			continue
		}
		vulnerabilities, ok := rows.([]any)
		if !ok || len(out)+len(vulnerabilities) > limits.MaxFindings {
			return nil, ErrInvalid
		}
		for _, value := range vulnerabilities {
			vuln, ok := value.(map[string]any)
			if !ok {
				return nil, ErrInvalid
			}
			packageID, _ := vuln["PkgIdentifier"].(map[string]any)
			purl := text(packageID["PURL"])
			ids, err := parseIdentity(nil, []string{text(vuln["VulnerabilityID"])}, purl)
			if err != nil {
				return nil, err
			}
			out = append(out, finding(ids, severity(vuln["Severity"]), nonEmpty(strings.ToLower(text(vuln["Status"])), "open"), "trivy", text(vuln["FixedVersion"])))
		}
	}
	return out, nil
}

func parseOSV(root map[string]any, limits Limits) ([]Finding, error) {
	results, ok := root["results"].([]any)
	if !ok || len(results) > limits.MaxFindings {
		return nil, ErrInvalid
	}
	out := []Finding{}
	for _, result := range results {
		section, ok := result.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		packages, ok := section["packages"].([]any)
		if !ok {
			return nil, ErrInvalid
		}
		for _, value := range packages {
			pkg, ok := value.(map[string]any)
			if !ok {
				return nil, ErrInvalid
			}
			packageInfo, _ := pkg["package"].(map[string]any)
			purl := text(packageInfo["purl"])
			vulnerabilities, ok := pkg["vulnerabilities"].([]any)
			if !ok || len(out)+len(vulnerabilities) > limits.MaxFindings {
				return nil, ErrInvalid
			}
			for _, value := range vulnerabilities {
				vuln, ok := value.(map[string]any)
				if !ok {
					return nil, ErrInvalid
				}
				aliases, err := stringsList(vuln["aliases"])
				if err != nil {
					return nil, err
				}
				ids, err := parseIdentity(nil, append([]string{text(vuln["id"])}, aliases...), purl)
				if err != nil {
					return nil, err
				}
				out = append(out, finding(ids, osvSeverity(vuln["severity"]), "open", "osv-scanner", text(vuln["fixed_version"])))
			}
		}
	}
	return out, nil
}

func parseDependencyTrack(root map[string]any, limits Limits) ([]Finding, error) {
	rows, ok := root["findings"].([]any)
	if !ok || len(rows) > limits.MaxFindings {
		return nil, ErrInvalid
	}
	out := make([]Finding, 0, len(rows))
	for _, value := range rows {
		row, ok := value.(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		vuln, ok := row["vulnerability"].(map[string]any)
		if !ok {
			return nil, ErrInvalid
		}
		component, _ := row["component"].(map[string]any)
		ids, err := parseIdentity(nil, []string{text(vuln["vulnId"])}, text(component["purl"]))
		if err != nil {
			return nil, err
		}
		if ids.VendorAdvisory == "" {
			ids.VendorAdvisory = text(vuln["source"]) + ":" + text(vuln["vulnId"])
		}
		out = append(out, finding(ids, severity(vuln["severity"]), nonEmpty(strings.ToLower(text(row["state"])), "open"), "dependency-track", text(row["fixedVersion"])))
	}
	return out, nil
}

func finding(id Identity, severityValue, state, source, fix string) Finding {
	return Finding{Vulnerability: primary(id), Component: component(id), Severity: severityValue, State: state, SeveritySource: source, FixVersion: fix, Identity: id}
}
func component(id Identity) string {
	if id.PURL != "" {
		return id.PURL
	}
	return id.CPE
}
func primary(id Identity) string {
	for _, candidate := range []string{id.CVE, id.GHSA, id.OSV, id.VendorAdvisory} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func parseIdentity(value any, identifiers []string, componentValue string) (Identity, error) {
	id := Identity{}
	if strings.HasPrefix(componentValue, "pkg:") {
		id.PURL = componentValue
	} else if strings.HasPrefix(componentValue, "cpe:") {
		id.CPE = componentValue
	}
	if value != nil {
		row, ok := value.(map[string]any)
		if !ok || !only(row, "cve", "ghsa", "osv", "vendor_advisory", "purl", "cpe") {
			return Identity{}, ErrInvalid
		}
		id.CVE, id.GHSA, id.OSV, id.VendorAdvisory, id.PURL, id.CPE = text(row["cve"]), text(row["ghsa"]), text(row["osv"]), text(row["vendor_advisory"]), nonEmpty(text(row["purl"]), id.PURL), nonEmpty(text(row["cpe"]), id.CPE)
	}
	for _, raw := range identifiers {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		switch {
		case strings.HasPrefix(v, "CVE-"):
			if id.CVE != "" && id.CVE != v {
				return Identity{}, ErrInvalid
			}
			id.CVE = v
		case strings.HasPrefix(v, "GHSA-"):
			if id.GHSA != "" && id.GHSA != v {
				return Identity{}, ErrInvalid
			}
			id.GHSA = v
		case strings.HasPrefix(v, "OSV-") || strings.Contains(v, "/"):
			if id.OSV != "" && id.OSV != v {
				return Identity{}, ErrInvalid
			}
			id.OSV = v
		default:
			if id.VendorAdvisory != "" && id.VendorAdvisory != v {
				return Identity{}, ErrInvalid
			}
			id.VendorAdvisory = v
		}
	}
	if primary(id) == "" {
		return Identity{}, ErrInvalid
	}
	return id, nil
}
func only(row map[string]any, fields ...string) bool {
	allowed := map[string]struct{}{}
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	for key := range row {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}
func text(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}
func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
func severity(value any) string {
	text := strings.ToLower(text(value))
	if text == "" {
		return "unknown"
	}
	return text
}

func osvSeverity(value any) string {
	if text := severity(value); text != "unknown" {
		return text
	}
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return "unknown"
	}
	for _, value := range values {
		row, ok := value.(map[string]any)
		if !ok || text(row["score"]) == "" {
			return "unknown"
		}
	}
	return "unknown"
}
func stringsList(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	raw, ok := value.([]any)
	if !ok {
		return nil, ErrInvalid
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		v := text(item)
		if v == "" {
			return nil, ErrInvalid
		}
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}

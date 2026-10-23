// Command license-inventory classifies bounded license bytes from stdin.
// Its heuristic candidates do not establish license compatibility or approval.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/licensecheck"
)

const maxBatchBytes = 8 * 1024 * 1024
const maxLicenseBytes = 1024 * 1024
const maxBatchRecords = 64

var invalidInput = errors.New("invalid or unsupported license scan input")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type classification struct {
	SHA256   string   `json:"sha256"`
	License  *string  `json:"license"`
	Coverage float64  `json:"coverage_percent"`
	IDs      []string `json:"ids"`
	Status   string   `json:"status"`
}

func readRequest(decoder *json.Decoder) (string, []byte, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", nil, invalidInput
	}
	fields := make(map[string]string, 2)
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "sha256" && key != "content_base64") {
			return "", nil, invalidInput
		}
		if _, exists := fields[key]; exists {
			return "", nil, invalidInput
		}
		token, err = decoder.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return "", nil, invalidInput
		}
		fields[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(fields) != 2 {
		return "", nil, invalidInput
	}
	digest, encoded := fields["sha256"], fields["content_base64"]
	if !digestPattern.MatchString(digest) || len(encoded) > base64.StdEncoding.EncodedLen(maxLicenseBytes) {
		return "", nil, invalidInput
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > maxLicenseBytes || base64.StdEncoding.EncodeToString(raw) != encoded || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return "", nil, invalidInput
	}
	actual := sha256.Sum256(raw)
	if hex.EncodeToString(actual[:]) != digest {
		return "", nil, invalidInput
	}
	return digest, raw, nil
}

func classify(digest string, raw []byte) (classification, error) {
	coverage := licensecheck.Scan(raw)
	if math.IsNaN(coverage.Percent) || math.IsInf(coverage.Percent, 0) || coverage.Percent < 0 || coverage.Percent > 100 {
		return classification{}, invalidInput
	}
	result := classification{SHA256: digest, Coverage: coverage.Percent, IDs: []string{}, Status: "unknown"}
	seen := make(map[string]bool)
	hasText := false
	for _, match := range coverage.Match {
		if match.ID == "" || len(match.ID) > 128 || strings.ContainsAny(match.ID, "\x00\r\n") {
			return classification{}, invalidInput
		}
		seen[match.ID] = true
		// Match.Type is an optional obligations classification, not a text
		// recognition flag; the pinned library leaves it unset for MIT.
		if !match.IsURL {
			hasText = true
		}
	}
	for identifier := range seen {
		result.IDs = append(result.IDs, identifier)
	}
	sort.Strings(result.IDs)
	switch {
	case len(result.IDs) > 1:
		// A concatenation does not tell us whether its terms are AND or OR.
		result.Status = "ambiguous"
	case len(result.IDs) == 1 && hasText && coverage.Percent >= 95:
		result.Status = "candidate"
		result.License = &result.IDs[0]
	}
	return result, nil
}

func run(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, maxBatchBytes+1))
	if err != nil || len(raw) > maxBatchBytes || !utf8.Valid(raw) {
		return invalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return invalidInput
	}
	results := make([]classification, 0)
	seen := make(map[string]bool)
	for decoder.More() {
		if len(results) >= maxBatchRecords {
			return invalidInput
		}
		digest, content, err := readRequest(decoder)
		if err != nil || seen[digest] {
			return invalidInput
		}
		result, err := classify(digest, content)
		if err != nil {
			return invalidInput
		}
		seen[digest] = true
		results = append(results, result)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim(']') || len(results) == 0 {
		return invalidInput
	}
	if _, err = decoder.Token(); err != io.EOF {
		return invalidInput
	}
	report := struct {
		Schema  string           `json:"schema"`
		Results []classification `json:"results"`
	}{Schema: "evydence-license-classification.v1", Results: results}
	// No output is written until every input record has passed validation.
	encoded, err := json.Marshal(report)
	if err != nil {
		return invalidInput
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}

func main() {
	if len(os.Args) != 1 || run(os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(os.Stderr, "license-inventory: invalid or unsupported scan input")
		os.Exit(2)
	}
}

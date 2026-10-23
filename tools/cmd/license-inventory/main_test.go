package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type scanRequest struct {
	SHA256  string `json:"sha256"`
	Content string `json:"content_base64"`
}

func request(raw []byte) scanRequest {
	digest := sha256.Sum256(raw)
	return scanRequest{SHA256: hex.EncodeToString(digest[:]), Content: base64.StdEncoding.EncodeToString(raw)}
}

func input(t *testing.T, rows []scanRequest) []byte {
	t.Helper()
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// Existing committed license texts: MIT for the pgx-derived DSN helper,
	// and the project's AGPL license. No ambient module cache or network.
	paths := map[string]string{
		"mit":  "../../../internal/platform/config/database_dsn.LICENSE",
		"agpl": "../../../LICENSE",
	}
	raw, err := os.ReadFile(paths[name])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func execute(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var output bytes.Buffer
	if err := run(bytes.NewReader(raw), &output); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func rejection(t *testing.T, raw []byte) {
	t.Helper()
	var output bytes.Buffer
	err := run(bytes.NewReader(raw), &output)
	if err == nil {
		t.Fatal("malformed scan request succeeded")
	}
	if output.Len() != 0 {
		t.Fatal("failed batch emitted a partial inventory")
	}
	if strings.Contains(err.Error(), "PRIVATE_CANARY") {
		t.Fatal("error disclosed raw input")
	}
}

func TestRecognizedTextHasDigestCoverageAndCandidateIdentifier(t *testing.T) {
	raw := fixture(t, "mit")
	result := execute(t, input(t, []scanRequest{request(raw)}))
	if result["schema"] != "evydence-license-classification.v1" {
		t.Fatal("missing classification schema")
	}
	rows, ok := result["results"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatal("scan did not produce exactly one result")
	}
	row := rows[0].(map[string]any)
	if row["sha256"] != request(raw).SHA256 || row["license"] != "MIT" || row["status"] != "candidate" {
		t.Fatalf("unexpected bounded MIT classification: %#v", row)
	}
	coverage, ok := row["coverage_percent"].(float64)
	if !ok || coverage < 95 || coverage > 100 {
		t.Fatal("unrecognized or invalid license coverage")
	}
	if len(row) != 5 {
		t.Fatal("unexpected raw content or path fields")
	}
}

func TestUnrecognizedAndURLOnlyTextAreUnknown(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("PRIVATE_CANARY: all copying requires a paid private agreement."),
		[]byte("https://opensource.org/licenses/MIT"),
		nil,
	} {
		result := execute(t, input(t, []scanRequest{request(raw)}))
		row := result["results"].([]any)[0].(map[string]any)
		if row["license"] != nil || row["status"] != "unknown" {
			t.Fatal("unknown or URL-only text received a license decision")
		}
	}
}

func TestDifferentLicenseTextsAreAmbiguousRatherThanInferredAsOR(t *testing.T) {
	raw := append(append(fixture(t, "mit"), '\n'), fixture(t, "agpl")...)
	result := execute(t, input(t, []scanRequest{request(raw)}))
	row := result["results"].([]any)[0].(map[string]any)
	if row["license"] != nil || row["status"] != "ambiguous" || len(row["ids"].([]any)) < 2 {
		t.Fatal("multiple license texts were silently combined or admitted")
	}
}

func TestDigestMismatchDuplicateIdentityAndLateFailureEmitNothing(t *testing.T) {
	valid := request(fixture(t, "mit"))
	wrong := request([]byte("different bytes"))
	wrong.SHA256 = strings.Repeat("0", 64)
	rejection(t, input(t, []scanRequest{wrong}))
	rejection(t, input(t, []scanRequest{valid, valid}))
	rejection(t, input(t, []scanRequest{valid, wrong}))
}

func TestMalformedShapesAndDuplicateFieldsAreRejected(t *testing.T) {
	valid := request(fixture(t, "mit"))
	for _, raw := range []string{
		`{}`, `null`, `[]`, `[[{}]]`, `[true]`, `[{"sha256":42}]`,
		`[{"sha256":null,"content_base64":""}]`,
		`[{"sha256":"` + request(nil).SHA256 + `","content_base64":null}]`,
		`[{"sha256":"` + valid.SHA256 + `"}]`,
		`[{"content_base64":"` + valid.Content + `"}]`,
		`[{"sha256":"` + valid.SHA256 + `","content_base64":"` + valid.Content + `","ignored":true}]`,
		`[{"sha256":"PRIVATE_CANARY","sha256":"` + valid.SHA256 + `","content_base64":"` + valid.Content + `"}]`,
		`[{"sha256":"` + valid.SHA256 + `","content_base64":"","content_base64":"` + valid.Content + `"}]`,
		string(input(t, []scanRequest{valid})) + `{}`,
		`[{"sha256":"PRIVATE_CANARY`,
	} {
		t.Run(fmt.Sprintf("case-%x", sha256.Sum256([]byte(raw))), func(t *testing.T) {
			rejection(t, []byte(raw))
		})
	}
}

func TestNoncanonicalBase64AndInvalidTextAreRejected(t *testing.T) {
	for _, mutate := range []func(*scanRequest){
		func(row *scanRequest) { row.Content = "PRIVATE_CANARY!" },
		func(row *scanRequest) { row.Content = row.Content[:4] + "\n" + row.Content[4:] },
		func(row *scanRequest) { row.SHA256 = strings.ToUpper(row.SHA256) },
	} {
		row := request(fixture(t, "mit"))
		mutate(&row)
		rejection(t, input(t, []scanRequest{row}))
	}
	rejection(t, input(t, []scanRequest{request([]byte{0xff, 0xfe})}))
	rejection(t, input(t, []scanRequest{request([]byte("PRIVATE_CANARY\x00"))}))
	rejection(t, []byte{'[', '"', 0xff, '"', ']'})
}

func TestBatchRecordByteAndFileBudgetsAreEnforced(t *testing.T) {
	rejection(t, []byte(strings.Repeat(" ", 8*1024*1024+1)))
	rejection(t, input(t, []scanRequest{request(bytes.Repeat([]byte("x"), 1024*1024+1))}))
	rows := make([]scanRequest, 65)
	for index := range rows {
		rows[index] = request([]byte(fmt.Sprintf("Synthetic unknown license %d", index)))
	}
	rejection(t, input(t, rows))
}

func TestClassificationIsDeterministicAndPreservesBatchOrder(t *testing.T) {
	rows := []scanRequest{request(fixture(t, "mit")), request([]byte("Unknown synthetic license"))}
	raw := input(t, rows)
	var first, second bytes.Buffer
	if err := run(bytes.NewReader(raw), &first); err != nil {
		t.Fatal(err)
	}
	if err := run(bytes.NewReader(raw), &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("same inputs produced different classifications")
	}
	result := execute(t, raw)["results"].([]any)
	for index, value := range result {
		if value.(map[string]any)["sha256"] != rows[index].SHA256 {
			t.Fatal("classification lost input/digest order")
		}
	}
	if bytes.Contains(first.Bytes(), []byte("Unknown synthetic license")) {
		t.Fatal("classification echoed raw license input")
	}
}

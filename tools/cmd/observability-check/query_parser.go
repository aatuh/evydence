package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type matcherFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Op    string `json:"op"`
}

type selectorFact struct {
	Name     string        `json:"name"`
	Matchers []matcherFact `json:"matchers"`
	Sum      bool          `json:"sum"`
	Counter  bool          `json:"counter"`
}

type callFact struct {
	Name         string `json:"name"`
	DirectMatrix bool   `json:"directMatrix"`
}

type durationFact struct {
	Text     string `json:"text"`
	Positive bool   `json:"positive"`
}

type queryFacts struct {
	Schema      string         `json:"schema"`
	Valid       bool           `json:"valid"`
	Reason      string         `json:"reason"`
	Selectors   []selectorFact `json:"selectors"`
	Grouping    []string       `json:"grouping"`
	Matching    []string       `json:"matching"`
	Calls       []callFact     `json:"calls"`
	Durations   []durationFact `json:"durations"`
	Strings     []string       `json:"strings"`
	Numbers     []string       `json:"numbers"`
	Functions   []string       `json:"functions"`
	Unsupported []string       `json:"unsupported"`
}

var errParserProtocol = errors.New("invalid or oversized PromQL parser response")
var errParserUnavailable = errors.New("PromQL parser unavailable; use Node 22 and run make observability-tools")
var errQuerySyntax = errors.New("invalid PromQL syntax, type or disabled feature")

func decodeQueryFacts(raw []byte) (queryFacts, error) {
	var facts queryFacts
	if len(raw) > 1<<20 {
		return facts, errParserProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&facts) != nil || facts.Schema != "evydence-promql-facts.v1" {
		return queryFacts{}, errParserProtocol
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return queryFacts{}, errParserProtocol
	}
	if !facts.Valid {
		if facts.Reason == "unavailable" {
			return queryFacts{}, errParserUnavailable
		}
		return queryFacts{}, errQuerySyntax
	}
	if len(facts.Selectors) > 128 || len(facts.Grouping) > 128 || len(facts.Matching) > 128 || len(facts.Calls) > 128 || len(facts.Durations) > 128 || len(facts.Strings) > 512 || len(facts.Numbers) > 512 || len(facts.Functions) > 128 {
		return queryFacts{}, errParserProtocol
	}
	return facts, nil
}

// Do not pass credentials, NODE_OPTIONS/NODE_PATH preloads, proxy configuration
// or the parent application's settings into the offline parser process.
func parserEnvironment() []string {
	return []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
}

type boundedParserOutput struct {
	bytes.Buffer
	limit int
}

func (w *boundedParserOutput) Write(data []byte) (int, error) {
	if len(data) > w.limit-w.Len() {
		return 0, errParserProtocol
	}
	return w.Buffer.Write(data)
}

func parseQueryFacts(ctx context.Context, root, query string) (queryFacts, error) {
	if ctx == nil {
		return queryFacts{}, errParserProtocol
	}
	if err := ctx.Err(); err != nil {
		return queryFacts{}, err
	}
	if len(query) == 0 || len(query) > 16384 {
		return queryFacts{}, errQuerySyntax
	}
	if _, err := readRepositoryFile(root, "site/marketing/package.json"); err != nil {
		return queryFacts{}, errParserUnavailable
	}
	if _, err := readRepositoryFile(root, "tools/cmd/observability-check/query_parser.cjs"); err != nil {
		return queryFacts{}, errParserUnavailable
	}
	input, err := json.Marshal(struct {
		Query string `json:"query"`
	}{query})
	if err != nil {
		return queryFacts{}, errParserProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Execute only the fixed, repository-owned program. Query data stays on
	// stdin; neither it nor the repository path becomes shell/program source.
	command := exec.CommandContext(ctx, "node", "--max-old-space-size=128", "../../tools/cmd/observability-check/query_parser.cjs")
	command.Dir = filepath.Join(root, "site", "marketing")
	command.Env = parserEnvironment()
	command.Stdin = bytes.NewReader(input)
	output := &boundedParserOutput{limit: 1 << 20}
	diagnostic := &boundedParserOutput{limit: 32 << 10}
	command.Stdout, command.Stderr = output, diagnostic
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if cause := ctx.Err(); cause != nil {
			return queryFacts{}, cause
		}
		return queryFacts{}, errParserUnavailable
	}
	facts, err := decodeQueryFacts(output.Bytes())
	if err == nil {
		err = validateQuerySyntax(facts)
	}
	return facts, err
}

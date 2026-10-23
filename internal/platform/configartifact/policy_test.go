package configartifact

import (
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/platform/config"
)

func TestRenderShowsNativePolicyAndCLIApplicability(t *testing.T) {
	definitions := []config.Definition{{
		Name: "EVYDENCE_SAMPLE_CLI", Kind: config.Text, Roles: config.CLI,
		CLICommands: config.CLIGitHubBuild | config.CLIPreflight, CLIFlag: "sample",
		Secret: true, FileOption: "EVYDENCE_SAMPLE_CLI_FILE",
		Description: "Command-specific sample input.",
	}}
	native := []config.NativeDefinition{{
		Definition: config.Definition{Name: "NATIVE_SAMPLE", Kind: config.Choice, Roles: config.API, Allowed: []string{"exact", "Mixed"}},
		Boundary:   config.NativeAzure, Parameter: "sample_parameter", Source: "pinned/native.go",
		Syntax: config.NativeAuthSchemes, ExactChoices: []string{"exact"}, RejectEmpty: true, RejectControl: true,
	}}
	artifacts, err := Render(definitions, native)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{ConfigurationReferencePath, HelmReferencePath} {
		body := string(artifacts[target])
		for _, required := range []string{"Native parameter: `sample_parameter`", "Syntax: `auth-schemes`", "Exact-case choices: `exact`", "Present empty input is rejected.", "Control characters are rejected."} {
			if !strings.Contains(body, required) {
				t.Errorf("%s lost native policy %q", target, required)
			}
		}
	}
	for _, name := range []string{"EVYDENCE_SAMPLE_CLI", "EVYDENCE_SAMPLE_CLI_FILE"} {
		found := false
		for line := range strings.SplitSeq(string(artifacts[ConfigurationReferencePath]), "\n") {
			if strings.HasPrefix(line, "| `"+name+"` |") {
				found = true
				if !strings.Contains(line, "CLI commands: `github-actions upload-build`, `ci preflight`") {
					t.Errorf("%s lost its applicable CLI commands", name)
				}
			}
		}
		if !found {
			t.Errorf("%s was omitted from the canonical reference", name)
		}
	}
	if strings.Contains(string(artifacts[HelmReferencePath]), "EVYDENCE_SAMPLE_CLI") {
		t.Fatal("CLI-only options leaked into the Helm reference")
	}
}

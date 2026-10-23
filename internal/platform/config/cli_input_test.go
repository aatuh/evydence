package config

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCLICommandUsesCapturedSchemaValuesAndExplicitFlags(t *testing.T) {
	environment, err := Capture([]string{"EVYDENCE_API_URL=https://captured.example.test/base", "EVYDENCE_API_KEY=PRIVATE_CAPTURED_KEY", "EVYDENCE_BUILD_STARTED_AT=2026-10-16T12:00:00Z", "GITHUB_RUN_ATTEMPT= 3 "})
	if err != nil {
		t.Fatal(err)
	}
	flags := map[string]string{"url": "https://explicit.example.test/api", "status": "failed"}
	input, err := PrepareCLI(environment, CLIGitHubBuild, flags)
	if err != nil {
		t.Fatal(err)
	}
	flags["url"] = "PRIVATE_MUTATION"
	t.Setenv("EVYDENCE_API_URL", "PRIVATE_AMBIENT")
	configuration, err := Resolve(t.Context(), input, true)
	if err != nil {
		t.Fatal(err)
	}
	got := configuration.CLI()
	if got.APIURL != "https://explicit.example.test/api" || got.APIKey.Reveal() != "PRIVATE_CAPTURED_KEY" || got.BuildStatus != "failed" || got.GitHubRunAttempt.Number() != 3 || !got.BuildStartedAt.Equal(time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("CLI recaptured or failed to project effective schema settings")
	}
	original, err := Parse(environment, CLI)
	if err != nil || original.CLI().APIURL != "https://captured.example.test/base" {
		t.Fatal("CLI override mutated its captured source")
	}
}

func TestCLICommandScopesIgnoreUnusedBuildAndLiveInputs(t *testing.T) {
	environment, err := Capture([]string{"EVYDENCE_API_URL=http://localhost:8080", "EVYDENCE_BUILD_STARTED_AT=PRIVATE_UNUSED", "GITHUB_RUN_ATTEMPT=PRIVATE_UNUSED", "EVYDENCE_DATABASE_URL=PRIVATE_UNUSED", "EVYDENCE_DATABASE_URL_FILE=/PRIVATE_UNUSED", "EVYDENCE_SIGNING_EXECUTOR_URL=PRIVATE_UNUSED"})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []CLICommand{CLIUpload, CLIPreflight} {
		input, err := PrepareCLI(environment, command, nil)
		if err != nil {
			t.Fatal("unused build/live inputs became dependencies", err)
		}
		cfg, err := Resolve(t.Context(), input, true)
		if err != nil || cfg.Runtime().DatabaseURL.IsSet() || cfg.CLI().APIURL != "http://localhost:8080" {
			t.Fatal("unused live input was resolved")
		}
	}
	if _, err := PrepareCLI(environment, CLIGitHubBuild, nil); err == nil {
		t.Fatal("active malformed build settings accepted")
	}
	empty, _ := Capture(nil)
	input, err := PrepareCLI(empty, CLIGitHubBuild, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Resolve(t.Context(), input, true)
	if err != nil || !cfg.CLI().BuildStartedAt.IsZero() || cfg.CLI().BuildStatus != "passed" || cfg.CLI().GitHubRunAttempt.Number() != 1 {
		t.Fatal("dynamic command clock was frozen or canonical defaults lost")
	}
}

func TestCLICommandFlagsRejectUnknownInactiveConflictingAndUnboundedInputs(t *testing.T) {
	for _, tc := range []struct {
		command CLICommand
		env     []string
		flags   map[string]string
		want    error
	}{
		{0, nil, nil, ErrInvalidCLICommand},
		{CLIUpload | CLIGitHubBuild, nil, nil, ErrInvalidCLICommand},
		{CLIUpload, nil, map[string]string{"PRIVATE_FLAG": "PRIVATE_VALUE"}, ErrInvalidCLICommand},
		{CLIUpload, nil, map[string]string{"started-at": "2026-10-16T12:00:00Z"}, ErrInvalidCLICommand},
		{CLIUpload, []string{"EVYDENCE_API_KEY_FILE=/PRIVATE_MISSING_FILE"}, map[string]string{"api-key": "PRIVATE_KEY"}, ErrConflictingSecretSources},
		{CLIUpload, []string{"EVYDENCE_API_KEY_FILE=/PRIVATE_MISSING_FILE"}, map[string]string{"api-key": ""}, ErrConflictingSecretSources},
		{CLIUpload, nil, map[string]string{"api-key": "PRIVATE\x00KEY"}, ErrInvalidEnvironment},
		{CLIUpload, nil, map[string]string{"api-key": "PRIVATE\r\nKEY"}, ErrInvalidValue},
		{CLIUpload, nil, map[string]string{"api-key": "PRIVATE KEY"}, ErrInvalidValue},
		{CLIGitHubBuild, nil, map[string]string{"started-at": "0001-01-01T00:00:00Z"}, ErrInvalidValue},
		{CLIUpload, nil, map[string]string{"api-key": strings.Repeat("x", maxEnvironmentBytes+1)}, ErrInvalidEnvironment},
		{CLIUpload, []string{"ENV=production", "EVYDENCE_PRIVATE_UNKNOWN=PRIVATE_VALUE"}, nil, ErrUnknownOption},
	} {
		environment, err := Capture(tc.env)
		if err != nil {
			t.Fatal(err)
		}
		input, err := PrepareCLI(environment, tc.command, tc.flags)
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "PRIVATE") || input.role != 0 {
			t.Fatal("invalid CLI input exposed data or partial settings")
		}
	}
}

func TestCLIBuildRunAttemptIsStrictBoundedInteger(t *testing.T) {
	for _, raw := range []string{"0", "-1", "2tail", "2147483648"} {
		environment, _ := Capture([]string{"GITHUB_RUN_ATTEMPT=" + raw})
		if _, err := PrepareCLI(environment, CLIGitHubBuild, nil); !errors.Is(err, ErrInvalidValue) {
			t.Fatal("malformed run attempt accepted")
		}
	}
	environment, _ := Capture([]string{"GITHUB_RUN_ATTEMPT=2147483647"})
	input, err := PrepareCLI(environment, CLIGitHubBuild, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Resolve(ctx, input, true); !errors.Is(err, context.Canceled) {
		t.Fatal("CLI resolution ignored cancellation")
	}
}

func TestCLINumericIdentityPreservesExistingBuildIdempotencyKeys(t *testing.T) {
	for _, raw := range []string{"02", "+2", " 2 "} {
		environment, _ := Capture([]string{"GITHUB_RUN_ATTEMPT=" + raw})
		prepared, err := PrepareCLI(environment, CLIGitHubBuild, nil)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Resolve(t.Context(), prepared, true)
		if err != nil || cfg.CLI().GitHubRunAttempt.Number() != 2 || cfg.CLI().GitHubRunAttempt.Identity() != strings.TrimSpace(raw) {
			t.Fatal("validated numeric projection changed an existing build idempotency identity")
		}
	}
}

func TestCLISchemaOwnsUniqueApplicableFlagBindings(t *testing.T) {
	flags := make(map[string]bool)
	for _, d := range Definitions() {
		if d.CLICommands & ^allCLICommands != 0 || (d.CLICommands != 0 && d.Roles != CLI) {
			t.Fatal("command applicability escaped the CLI schema")
		}
		if d.CLIFlag != "" {
			if d.CLICommands == 0 || flags[d.CLIFlag] {
				t.Fatal("CLI flag missing applicability or bound more than once")
			}
			flags[d.CLIFlag] = true
		}
	}
}

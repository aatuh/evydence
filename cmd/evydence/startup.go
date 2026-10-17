package main

import (
	"context"
	"errors"
	"flag"
	"io"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

var errCLIConfiguration = errors.New("CLI configuration is invalid")

// The process captures once. Flag parsing can still return help without
// applying a capture failure or resolving unused credential files.
type cliInput struct {
	environment config.Environment
	captureErr  error
}

func isOnlineCLICommand(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "github-actions":
		return args[1] == "upload-build"
	case "ci":
		return args[1] == "preflight"
	case "import-bundle":
		return args[1] == "upload"
	case "upload":
		return args[1] == "manifest"
	case "release":
		return args[1] == "upload-evidence"
	default:
		return false
	}
}

func registerCLIConnectionFlags(fs *flag.FlagSet) {
	fs.String("url", "", "Evydence API URL")
	fs.String("api-key", "", "Evydence API key")
}

// All applicable configuration and private credential resolution precedes the
// operation callback, including its payload reads and network requests.
func runConfiguredCLI(ctx context.Context, input cliInput, output io.Writer, fs *flag.FlagSet, command config.CLICommand, operation func(context.Context, config.CLISettings) error) error {
	reject := func() error {
		logging.RejectStartup(ctx, "cli", runtimeinfo.Current(), output)
		return errCLIConfiguration
	}
	if input.captureErr != nil {
		return reject()
	}
	flags := make(map[string]string)
	bindings := make(map[string]bool)
	for _, definition := range config.Definitions() {
		if definition.CLIFlag != "" && definition.CLICommands&command != 0 {
			bindings[definition.CLIFlag] = true
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if bindings[f.Name] {
			flags[f.Name] = f.Value.String()
		}
	})
	prepared, err := config.PrepareCLI(input.environment, command, flags)
	if err != nil {
		return reject()
	}
	settings, err := config.Resolve(ctx, prepared, true)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return reject()
	}
	runtime := settings.Runtime()
	return logging.RunConfigured(ctx, "cli", runtimeinfo.Current(), output, logging.Config{Level: runtime.LogLevel, Format: runtime.LogFormat}, func(ctx context.Context) error { return operation(ctx, settings.CLI()) })
}

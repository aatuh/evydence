// Command config-artifacts checks or regenerates the owned configuration sections.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aatuh/evydence/internal/platform/config"
	"github.com/aatuh/evydence/internal/platform/configartifact"
)

var artifactPaths = []string{
	configartifact.ProductionEnvironmentPath,
	configartifact.ConfigurationReferencePath,
	configartifact.HelmReferencePath,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, func() (*os.Root, error) {
		return os.OpenRoot(".")
	}))
}

func run(args []string, stdout, stderr io.Writer, openRoot func() (*os.Root, error)) (code int) {
	flags := flag.NewFlagSet("config-artifacts", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Flag errors can contain operator-provided values.
	check := flags.Bool("check", false, "check generated sections without writing (default)")
	write := flags.Bool("write", false, "replace generated sections, preserving operator prose")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: config-artifacts [--check | --write]\nRun from the repository root. Check is the default; only --write changes files.")
			return 0
		}
		fmt.Fprintln(stderr, "invalid config-artifacts arguments; use --help")
		return 2
	}
	if flags.NArg() != 0 || (*check && *write) {
		fmt.Fprintln(stderr, "invalid config-artifacts arguments; use --help")
		return 2
	}
	root, err := openRoot()
	if err != nil || root == nil {
		fmt.Fprintln(stderr, "cannot open repository root")
		return 1
	}
	defer func() {
		if root.Close() != nil {
			fmt.Fprintln(stderr, "cannot close repository root")
			code = 1
		}
	}()
	if err := processArtifacts(root, *write); err != nil {
		// All errors below are fixed diagnostics with code-owned target names.
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, "configuration artifacts are current")
	return 0
}

func processArtifacts(root *os.Root, write bool) (result error) {
	generated, err := configartifact.Render(config.Definitions(), config.NativeDefinitions())
	if err != nil {
		return errors.New("cannot render configuration schema")
	}
	var artifacts []*managedArtifact
	defer func() {
		for _, artifact := range artifacts {
			if artifact.close() != nil {
				result = errors.New("cannot clean up configuration artifact resources")
			}
		}
	}()
	// Preflight every input before creating temporary files or replacing targets.
	for _, target := range artifactPaths {
		artifact, err := openArtifact(root, target)
		if err != nil {
			return fmt.Errorf("cannot read configuration artifact: %s", target)
		}
		artifacts = append(artifacts, artifact)
		artifact.after, err = configartifact.Merge(target, artifact.before, generated[target])
		if err != nil {
			return fmt.Errorf("invalid generated section: %s", target)
		}
	}
	var changed []*managedArtifact
	for _, artifact := range artifacts {
		if !bytes.Equal(artifact.before, artifact.after) {
			changed = append(changed, artifact)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	if !write {
		return errors.New("configuration artifacts have drifted; run config-artifacts --write")
	}
	// Stage all replacements before renaming any target. Each rename is atomic
	// on supported local filesystems; the three-file update is not a transaction.
	for _, artifact := range changed {
		if artifact.stage() != nil {
			return errors.New("cannot stage configuration artifacts")
		}
	}
	for _, artifact := range artifacts {
		if !artifact.unchanged() {
			return errors.New("configuration artifact changed during generation; retry")
		}
	}
	for _, artifact := range changed {
		if artifact.parent.Rename(artifact.temporary, artifact.name) != nil {
			return errors.New("cannot replace configuration artifact")
		}
		artifact.temporary = ""
	}
	return nil
}

// architecture-inspect emits a read-only AST inventory for repository checks.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/aatuh/evydence/internal/architecturecheck"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	flags := flag.NewFlagSet("architecture-inspect", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	root := flags.String("root", ".", "repository source root (never executed)")
	module := flags.String("module", "github.com/aatuh/evydence", "repository Go module path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("architecture-inspect accepts flags only")
	}
	files, err := architecturecheck.ScanSources(ctx, *root, *module)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Version int                            `json:"version"`
		Files   []architecturecheck.SourceFile `json:"files"`
	}{Version: 1, Files: files})
}

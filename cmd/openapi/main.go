package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, redaction.Error(err))
		os.Exit(1)
	}
}

func run(out io.Writer) error {
	doc, err := httpapi.GenerateOpenAPI()
	if err != nil {
		return err
	}
	if _, err := out.Write(doc); err != nil {
		return err
	}
	_, err = out.Write([]byte("\n"))
	return err
}

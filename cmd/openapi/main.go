package main

import (
	"fmt"
	"io"
	"os"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(out io.Writer) error {
	server, err := httpapi.NewServer(app.NewLedger(app.Config{APIKeyPepper: "openapi-generation"}))
	if err != nil {
		return err
	}
	doc, err := server.OpenAPI()
	if err != nil {
		return err
	}
	if _, err := out.Write(doc); err != nil {
		return err
	}
	_, err = out.Write([]byte("\n"))
	return err
}

package main

import (
	"fmt"
	"os"

	"github.com/aatuh/evydence/internal/adapters/httpapi"
	"github.com/aatuh/evydence/internal/app"
)

func main() {
	server, err := httpapi.NewServer(app.NewLedger(app.Config{APIKeyPepper: "openapi-generation"}))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	doc, err := server.OpenAPI()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(doc)
	_, _ = os.Stdout.Write([]byte("\n"))
}

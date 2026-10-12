package httpapi

import (
	"net/http"

	"github.com/aatuh/api-toolkit/v3/routecontracts"
	"github.com/aatuh/api-toolkit/v3/specs"
)

// GenerateOpenAPI renders and validates the same route contracts as the running
// API, without constructing application services, credentials, cursors or a
// Ledger. It returns only a document, never an incompletely wired HTTP server.
func GenerateOpenAPI() ([]byte, error) {
	mux, specification, routes := newContractRegistries()
	contract := &Server{mux: mux, specs: specification, routes: routes}
	if err := contract.registerRoutes(); err != nil {
		return nil, err
	}
	if err := contract.ValidateRoutes(); err != nil {
		return nil, err
	}
	return specification.OpenAPI()
}

func newContractRegistries() (*http.ServeMux, *specs.Registry, *routecontracts.Registry) {
	mux := http.NewServeMux()
	specification := NewSpecRegistry()
	router := &serveMuxRouter{mux: mux}
	return mux, specification, routecontracts.NewRegistry(router, specification)
}

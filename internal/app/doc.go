// Package app contains shared Evydence transaction/storage ports and stateless helpers.
//
// Context-owned services own production use cases. The historical Ledger
// aggregate is test-only; native adapters use these bounded ports without its
// maps, locks or snapshot/replay facade. This package stays independent of
// HTTP routers, SQL drivers, object storage SDKs and provider clients.
package app

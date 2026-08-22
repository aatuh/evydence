package app

// Keep the pre-existing in-package compatibility shim referenced while old
// package-local tests and integrations move to UploadSPDXSBOMPayload.
var _ = (*Ledger).uploadSPDXSBOMLegacy

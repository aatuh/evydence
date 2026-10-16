# ADR 0005: Validated Runtime Configuration

Status: accepted for the immutable-input foundation of EVY-1214, reviewed
2026-10-16. Schema completion, secret resolution, command adoption and generated
deployment documentation remain pending in EVY-1214 through EVY-1217. This is an
explanation for developers maintaining startup and configuration boundaries.

## Decision

Build the project-owned configuration schema and typed loader under
`internal/platform/config`. Capture the supplied process environment once,
without consulting ambient environment variables inside the input object.
Parsing must finish before an enabled runtime opens listeners, starts providers
or mutates storage. Secret resolution follows validated references and has an
explicit filesystem/provider owner.

The input foundation retains selected values privately and preserves explicit
empty values and raw whitespace for the eventual field-specific parser. It
captures `ENV`, `CI`, `EVYDENCE_*` and the AWS, Google, Azure and GitHub namespaces.
Unrelated host settings are not configuration values. Capture bounds total input
to 4096 entries and 8 MiB, selected settings to 1024, and selected names to 256
bytes. Selected names use uppercase ASCII environment syntax; NUL and malformed
UTF-8 selected input are rejected. Duplicate selected names fail instead of
depending on process-environment ordering.

The input's string, Go-syntax and JSON representations disclose neither names
nor values. Validation failures use fixed diagnostics. An internal fingerprint
supports change detection; it is not an evidence digest, credential identifier
or public configuration dump. Captured input and returned metadata remain owned
by the configuration package.

## Required Toolkit Boundary

The pinned `github.com/aatuh/api-toolkit/contrib/v3 v3.1.2` configuration helper
was inspected before choosing this boundary. Its `NewLoader` binds the default
ambient environment adapter. Its boolean, integer, duration and enum errors can
include the supplied value; its generic application settings also use a different
environment-variable contract. It does not supply Evydence's role-aware schema,
generated operator references, secret-reference policy or pre-startup validation
of the entire applicable configuration.

Using that loader would therefore preserve ambient reads and permit sensitive
configuration in errors. The project-specific input/validation layer addresses
those requirements with the standard library and adds no dependency. This
decision does not replace the required toolkit HTTP foundation, middleware,
ports, Problem Details or route/OpenAPI contract facilities.

## Delivery And Compatibility

EVY-1214 owns the inventory, schema, typed parsing and safe diagnostics.
EVY-1215 owns bounded secret references. EVY-1216 must adopt those definitions in
all applicable commands and retire duplicate defaults, parsers and hot-path
ambient reads. EVY-1217 owns generated examples/references, deployment parity and
the final runtime evidence required by parent EVY-1205.

Current commands retain their existing parsing until adoption. An input helper
alone does not prove that startup validates every field or that generated docs
match production behavior. Changes to accepted values, defaults, aliases or
production constraints require characterization tests and explicit compatibility
notes. Offline verification, help and version commands must remain independent
of unused live dependencies.

The canonical operator reference remains
[`docs/reference/configuration.md`](../reference/configuration.md). This ADR
records the implementation boundary rather than duplicating its variable table.

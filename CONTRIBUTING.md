# Contributing

Evydence accepts contributions selectively. The project uses an AGPL public
license plus optional commercial license exceptions, so contribution rights must
be handled deliberately.

## License Requirement

By default, Evydence is licensed under `AGPL-3.0-only`.

Substantive external contributions require explicit maintainer approval and a
contributor license agreement before merge. The purpose is to preserve the
ability to offer commercial license exceptions while keeping the public
repository available under AGPL. Issue reports and high-level discussion do not
require a contributor license agreement.

Do not submit code, docs, tests, schemas, generated artifacts, provider
fixtures, or release evidence unless you have the right to license them to the
project under terms compatible with this model.

## Development Rules

Before opening a change:

1. Read `AGENTS.md`, `.initial_design.md`, `README.md`, `openapi.yaml`, and the
   relevant docs under `docs/`.
2. Keep OpenAPI, tests, migrations, docs, SDK artifacts, examples, deployment
   files, and release evidence aligned when behavior changes.
3. Preserve tenant isolation, append-only evidence behavior, idempotency,
   canonical hashing, verification receipts, safe Problem Details responses,
   secret redaction, and conservative product language.
4. Do not introduce claims that Evydence provides legal compliance,
   certification, complete SBOMs, authoritative scanner results, secure
   releases, regulator acceptance, or auditor acceptance.

Useful checks:

```sh
make docs-check
make fast-check
make finalize
```

For release-readiness changes, also run:

```sh
make release-acceptance
make release-check
```

Database-backed checks require `EVYDENCE_TEST_DATABASE_URL`. Do not point test
commands at production databases, production object stores, KMS keys, or live
provider accounts.

Do not include API keys, collector keys, bearer tokens, session tokens, portal
tokens, private keys, provider credentials, database URLs, raw evidence
payloads, customer data, backup files, or release evidence artifacts in commits.

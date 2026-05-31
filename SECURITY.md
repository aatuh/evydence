# Security Policy

Evydence is high-trust compliance-readiness and release-evidence
infrastructure. Security reports are welcome, especially around tenant isolation,
authorization, API keys, SSO sessions, collector identity, evidence
immutability, canonical hashes, signatures, audit chains, release bundles,
object storage, reports, exports, and release evidence.

## Reporting A Vulnerability

If you believe you found a vulnerability, use GitHub private vulnerability
reporting for this repository when the "Report a vulnerability" button is
available on GitHub. The expected intake URL is
<https://github.com/aatuh/evydence/security/advisories/new>. If the button or
URL is unavailable for your account or region, use the private security intake
channel listed for the current release notes or request a private channel from
the maintainer without including vulnerability details in the first contact.

The repository file cannot itself prove that GitHub private vulnerability
reporting or a dedicated mailbox is enabled; that is an operator setting that
must be verified on the public repository before relying on it.

Do not include API keys, collector secrets, bearer tokens, session tokens,
portal tokens, private keys, provider credentials, database URLs, raw evidence
payloads, customer data, exploit payloads against third-party systems, or other
sensitive material in public issues, pull requests, screenshots, logs, or first
contact messages.

## What To Include

Once a private channel is established, include:

- affected commit, tag, image digest, or deployment profile,
- concise impact statement,
- reproduction steps or proof of concept,
- affected endpoints, commands, packages, collectors, workers, or report paths,
- whether secrets, tenant data, raw payloads, release evidence, audit records,
  customer packages, or exports are exposed,
- whether object storage, PostgreSQL, signing keys, SSO, provider metadata, or
  CI collectors are involved,
- suggested fix if known.

## Supported Versions And Scope

Security support focuses on the current `master` branch and current release
candidate or release tags. Older releases are best effort unless a commercial
support agreement says otherwise. Reports should identify the affected commit,
tag, image digest, Helm chart version, or deployment profile so triage can
reproduce the issue without production data.

## Advisory And Disclosure Expectations

Evydence handles tenant-scoped evidence, credentials, signing metadata, object
payload references, and customer-package boundaries. Security fixes should be
coordinated privately until maintainers have a reasonable opportunity to
triage, patch, publish release evidence, and document upgrade guidance. Public
advisories should avoid raw exploit payloads, customer evidence, secrets, or
instructions that increase exposure before users can update.

Out of scope:

- denial-of-service reports that require unrealistic local resource access,
- issues caused only by unsupported production configuration,
- findings that depend on publishing secrets or raw customer payloads in public
  channels,
- reports that rely on live third-party provider abuse rather than local
  reproduction or responsible provider disclosure,
- requests for legal compliance, certification, complete SBOM, scanner
  authority, secure-release, regulator-acceptance, or auditor-acceptance claims.

Do not post secrets, raw evidence payloads, private keys, provider credentials,
session tokens, bearer tokens, database URLs, customer data, or unredacted
customer package contents in public issues, pull requests, screenshots, logs,
or release evidence.

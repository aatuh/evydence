# Security Policy

Evydence is high-trust compliance-readiness and release-evidence
infrastructure. Security reports are welcome, especially around tenant isolation,
authorization, API keys, SSO sessions, collector identity, evidence
immutability, canonical hashes, signatures, audit chains, release bundles,
object storage, reports, exports, and release evidence.

## Reporting A Vulnerability

If you believe you found a vulnerability, contact Aatu Harju through LinkedIn:

<https://www.linkedin.com/in/aatu-harju>

Use the initial message to request a private reporting channel. Do not include
API keys, collector secrets, bearer tokens, session tokens, portal tokens,
private keys, provider credentials, database URLs, raw evidence payloads,
customer data, exploit payloads against third-party systems, or other sensitive
material in the first message.

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

## Supported Scope

Security support focuses on the current `master` branch and current release
tags. Older releases are best effort unless a commercial support agreement says
otherwise.

Out of scope:

- denial-of-service reports that require unrealistic local resource access,
- issues caused only by unsupported production configuration,
- findings that depend on publishing secrets or raw customer payloads in public
  channels,
- reports that rely on live third-party provider abuse rather than local
  reproduction or responsible provider disclosure,
- requests for legal compliance, certification, complete SBOM, scanner
  authority, secure-release, regulator-acceptance, or auditor-acceptance claims.

## Disclosure

Please allow time for triage and remediation before public disclosure. Public
fixes should avoid exposing exploit details before affected users have a
reasonable update path.

Do not post secrets, raw evidence payloads, private keys, provider credentials,
session tokens, bearer tokens, database URLs, customer data, or unredacted
customer package contents in public issues, pull requests, screenshots, logs,
or release evidence.

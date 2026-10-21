# Security Policy

Evydence is high-trust compliance-readiness and release-evidence
infrastructure. Security reports are welcome, especially around tenant isolation,
authorization, API keys, SSO sessions, collector identity, evidence
immutability, canonical hashes, signatures, audit chains, release bundles,
object storage, reports, exports, and release evidence.

## Security Model And Release Review

The repository's [threat model](docs/security/threat-model.md) and
[security requirements matrix](docs/security/security-requirements.md) define
the current trust boundaries, implemented evidence, open P0/P1 repository
work, and operator/provider/review-owned controls. They are versioned with the
code and must be reviewed for a release that changes a trust boundary,
authentication method, provider, storage profile, parser, package format, or
deployment topology.

Those documents do not claim protection against a privileged operator who can
rewrite every database, object, signing-key, and checkpoint record, or prove
provider truth, legal compliance, certification, complete SBOM coverage,
authoritative vulnerability results, or release security. Deployment IAM,
network controls, identity-provider configuration, key custody, backups, and
external review remain outside this repository's unilateral control.

## Public Release Verification

For public artifact publisher identity, use the versioned
[release signing policy](docs/release-signing.md). A byte-consistent signature
with an embedded key alone does not authenticate a publisher. The policy binds
new releases to the expected repository, workflow, protected ref, issuer and
source commit, with a narrow pinned historical exception and explicit revoked
sources. Its custody, incident and rotation instructions distinguish implemented
verification from required live provider controls and publication evidence.

## Reporting A Vulnerability


Use the private security intake:
[GitHub private vulnerability reporting](https://github.com/aatuh/evydence/security/advisories/new).
Sign in to GitHub, open the form, and submit the affected version, impact and a
sanitized reproduction. Reports stay in GitHub's private advisory workflow; see
[GitHub's reporting instructions](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

Private reporting was enabled in the
[2026-10-21 provider check](docs/reference/repository-controls-2026-10-21T115552Z.json).
Settings can change. If the form is unavailable, open an issue asking only for a
private contact route; do not include vulnerability details. No dedicated
security mailbox is currently advertised. LinkedIn is not the security intake.

Aatu Harju (`@aatuh`) owns security response. Evydence is maintained by one
person: acknowledgement, triage and patches are best effort, with no scheduled
on-call coverage or guaranteed response time. The
[security response procedure](docs/reference/security-response.md) describes
triage, emergency fixes, disclosure and the limits of the provider check.

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

Security support focuses on `master` and the current public release selected in
[`release/current.json`](release/current.json), until superseded or withdrawn.
Older releases are best effort unless a commercial support agreement says
otherwise. Reports should identify the affected commit,
tag, image digest, Helm chart version, or deployment profile so triage can
reproduce the issue without production data.

The versioned [support and withdrawal reference](docs/reference/release-support.md)
records this event-based window and the selected public release. Its
[machine-readable policy](release/lifecycle-policy.json) does not promise a
fixed security support end date or response SLA. Maintainers follow the
[withdrawal procedure](docs/reference/release-revocation.md) to preserve
historical evidence while removing a release from default selection.

## Advisory And Disclosure Expectations

Evydence handles tenant-scoped evidence, credentials, signing metadata, object
payload references, and customer-package boundaries. Security fixes should be
coordinated privately with the reporter while the maintainer triages, patches,
verifies release evidence and prepares upgrade guidance. Agree disclosure timing
case by case; there is no blanket embargo duration or guaranteed patch date.
Active exploitation may require mitigation guidance before a fix is available.
The response procedure records advisory contents and reporter-credit consent. Public
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

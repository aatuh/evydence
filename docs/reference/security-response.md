# Security Response

This reference is for the maintainer handling an Evydence vulnerability report.
Reporters start at [SECURITY.md](../../SECURITY.md). Aatu Harju (`@aatuh`) owns
triage, release and disclosure decisions. Availability is best effort, without
scheduled on-call coverage, a response SLA or a backup maintainer.

## Receive And Triage

1. Review private reports in the repository's Security and quality → Advisories
   area. Keep GitHub security-alert notifications enabled and check this inbox
   directly when available; provider enablement does not prove notification
   delivery. Ask for missing impact, affected version and sanitized reproduction
   in the private report, never a public issue.
2. Acknowledge receipt when available and say what information or investigation
   comes next. Acknowledge a report separately from confirming a vulnerability.
   Accept a confirmed report as a draft advisory; explain duplicate or
   non-security closures privately. See [GitHub's report-management guide](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/manage-vulnerability-reports).
3. Record affected tags/commits, deployment assumptions, tenant/data or signing
   impact, exploit prerequisites and any observed exploitation. Reproduce with
   synthetic data and determine affected versions; a failure on unpublished
   `master` does not establish that the current public candidate is affected.

Use these impact categories to order work; they are triage guidance, not a
scanner verdict or guaranteed repair schedule.

| Severity | Example impact | Response priority |
| --- | --- | --- |
| Critical | Active compromise, unauthenticated cross-tenant access, publisher takeover | Contain exposure first; assess urgent mitigation and withdrawal |
| High | Reproducible tenant-boundary, credential or evidence-integrity failure | Prioritize a private fix and operator mitigation |
| Medium | Restricted exploitation or meaningful availability/privacy impact | Plan a fix after higher-impact exposure is contained |
| Low | Limited impact with strong prerequisites | Track and explain the disposition |

Reassess severity as evidence changes. Record uncertainty rather than rejecting
a report because it lacks a ready-made exploit. Ordinary support questions go
to [SUPPORT.md](../../SUPPORT.md); sensitive reports stay private.

## Patch, Release And Disclose

Fuzz failures follow the same private triage procedure. The
[fuzz corpus and artifact policy](test-strategy.md#fuzz-runner-and-corpus-policy)
permits only synthetic/public fixtures, but hosted artifacts can still expose a
new failure before its security impact is understood. Inspect the exact-source
summary and retained input privately, reproduce with the recorded toolchain and
target, and establish impact before adding a public regression. Do not paste raw
logs or a suspected exploit into a public issue. A crash alone does not establish
severity or affected public releases; no runner automatically files a report.

1. Agree disclosure timing with the reporter case by case. Record an intended
   next update and any embargo privately; revise it when facts or availability
   change. Do not promise a fixed patch deadline or indefinite secrecy. Active
   exploitation may require publishing safe mitigations before a patch exists.
2. Prepare the fix privately where needed, add a regression test and run the
   affected checks and required project release gates. Use the normal protected
   PR/CI path; an emergency does not authorize a check bypass. Development on a
   private branch or fork does not itself verify the protected release source.
3. Follow [release validation](release-validation.md) and
   [publisher custody](../release-signing.md) for an authorized release. Preserve
   published tags and assets. If publisher trust or an artifact is compromised,
   use [incident response](../runbooks/incident-response.md) and
   [withdrawal](release-revocation.md); suspend affected publication, revoke the
   affected authority and retain historical evidence. A code fix alone does not
   repair compromised credentials or remove an unsafe default install.
4. Prepare an advisory with affected and fixed versions (or explicitly no fix
   yet), impact, prerequisites, mitigations and upgrade/verification instructions.
   Ask the reporter which public name or alias, if any, to credit; do not expose
   private identity or report contents without agreement. Publish through
   [GitHub advisories](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/fix-reported-vulnerabilities/publish-repository-advisory)
   only with maintainer authorization. Update release notes and support guidance
   to match the actual publication; keep secrets and customer evidence private.
5. Close the private investigation with links to the actual fix, release and
   advisory, remaining limitations and follow-up work. Local drafts or simulations
   are not publication receipts.

## Supported Versions

[`release/lifecycle-policy.json`](../../release/lifecycle-policy.json) owns the
machine-readable support window; [`release/current.json`](../../release/current.json)
selects the public release. [Release support](release-support.md) renders both.
Development support covers `master`; public-release support starts at publication
and ends when superseded or withdrawn. Older versions are best effort unless a
separate support agreement applies. There is no fixed end date or response SLA.
Do not invent calendar commitments or copy a second version list into this file.

## Verification And Desk Exercise — 2026-10-21

The [read-only controls check](repository-controls-2026-10-21T115552Z.json) passed
all 18 observations, including private reporting, for remote `master`
`d77b612bc72192f9ef97283c83aa5e9d7bb26aab`. It ran from clean local
`a1205e2b4129b6a7c789744d0625d056955790cf`. GitHub's public release list also
matched the selected `v0.1.0-rc.7`, published `2026-06-01T17:00:46Z`.
These observations do not prove notification delivery or hosted CI for local work.

Codex walked these synthetic tabletop cases against the linked policies:

| Case | Decision checked | Result / remaining limit |
| --- | --- | --- |
| Suspected tenant-data leak in the current candidate | Keep the report private; owner triages critical/high impact, reproduces with synthetic data, tests the fix and coordinates a verified release/advisory | Intake, ownership, release checks and disclosure routes are documented; no real report or patch was submitted |
| Possible publisher compromise, with no replacement release | Suspend publication, recover/revoke authority, preserve evidence and withdraw the affected release; do not silently select an older candidate | Withdrawal procedure explicitly covers no default install and separately approved provider notices; no real credential or release was changed |
| Reporter cannot use the form, or maintainer is unavailable | Request a private route without public details; response may wait for the sole maintainer | No invented mailbox, second responder or response-time guarantee |

This was a Codex desk exercise, not a human on-call drill, notification-delivery
test or independent review. No reports, advisory drafts, messages or publications
were created. Revisit the procedure before a security release and after an intake,
ownership or support-policy change; follow the controls guide to refresh settings.

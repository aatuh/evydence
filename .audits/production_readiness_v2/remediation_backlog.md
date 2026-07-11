# Backlog

Project: Evydence production-readiness public repo audit v2

Status legend:

- [ ] not done
- [x] done
- [e] external/provider/customer dependency

Execution rules:

- Preserve conservative product language and the controlled self-hosted
  production-candidate status until stronger evidence exists.
- Run `make production-check`, `make release-acceptance`, and
  `make public-release-verify TAG=<current-rc>` before any release-status
  change.
- Treat external items as tracked dependencies, not source-repository failures.

## Epic E1 - Publish Local Trust Fixes [x]

### Ticket E1-T1 - Push productization commits and rerun public checks [x]

Description: Push the local E1-E9 productization commits so public GitHub state
matches the audited local checkout.

Validation:

- Public `CI` succeeds.
- Public `CodeQL` succeeds.
- Public `OpenSSF Scorecard` reruns.
- Public code-scanning alerts are reviewed after the rerun.

Status: complete. Commit `77ab18e5ad8b3ba3a9f4745e7f6437e5e3e1f596` is pushed
to `origin/master`; public CI run `26765669971`, CodeQL run `26765669269`,
Scorecard SARIF run `26765714988`, and Scorecard run `26765723736` all passed.

### Ticket E1-T2 - Verify Scorecard token-permission alert closure [x]

Description: Confirm the two public Scorecard `TokenPermissionsID` alerts close
after the workflow permission fixes are pushed.

External reason:

- Alert lifecycle is GitHub/Scorecard provider state.

Status: complete. `gh api repos/aatuh/evydence/code-scanning/alerts` returned
zero open alerts after Scorecard SARIF run `26765714988`.

## Epic E2 - External Repository Settings [e]

### Ticket E2-T1 - Verify private vulnerability reporting and secret scanning [x]

Description: Confirm private vulnerability reporting, secret scanning, and push
protection are enabled where available.

External reason:

- These are GitHub account/repository settings.

Status: verified with GitHub API on 2026-06-01. Dependabot security updates,
secret scanning, secret scanning push protection, and private vulnerability
reporting are enabled; secret-scanning alerts returned zero open alerts.

### Ticket E2-T2 - Update public GitHub description [x]

Description: Change the repository description to the VEX-first positioning.

Suggested wording:

`Self-hosted VEX-first release evidence ledger for customer CVE, SBOM, provenance, and release-review questions.`

External reason:

- Repository description is provider metadata.

Status: complete. The public description now uses the VEX-first release
evidence positioning.

## Epic E3 - Adoption Proof [e]

### Ticket E3-T1 - [e] Run one design-partner pilot [e]

Description: Use Evydence on one non-maintainer release and generate a
customer-safe package.

External reason:

- Requires external organization participation and permission.

### Ticket E3-T2 - [e] Publish sanitized pilot report [e]

Description: Publish a sanitized case study or lessons-learned note if the
design partner approves.

External reason:

- Requires external approval and careful disclosure review.

## Epic E4 - Next Release Evidence [e]

### Ticket E4-T1 - Cut the next public RC after E7/E9 push [e]

Description: Produce and publish the next release-candidate evidence package
after the productization commits are public and public checks pass.

Validation:

- `make production-check`
- `make release-candidate-check TAG=<next-rc>`
- `make public-release-verify TAG=<next-rc>`

External reason:

- Public release/container publication depends on external
  `EVYDENCE_RELEASE_PUBLISH_TOKEN` and `EVYDENCE_GHCR_PUBLISH_TOKEN` secret
  values after the workflow permission hardening.

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

## Epic E1 - Publish Local Trust Fixes [ ]

### Ticket E1-T1 - Push productization commits and rerun public checks [ ]

Description: Push the local E1-E9 productization commits so public GitHub state
matches the audited local checkout.

Validation:

- Public `CI` succeeds.
- Public `CodeQL` succeeds.
- Public `OpenSSF Scorecard` reruns.
- Public code-scanning alerts are reviewed after the rerun.

### Ticket E1-T2 - [e] Verify Scorecard token-permission alert closure [e]

Description: Confirm the two public Scorecard `TokenPermissionsID` alerts close
after the workflow permission fixes are pushed.

External reason:

- Alert lifecycle is GitHub/Scorecard provider state.

## Epic E2 - External Repository Settings [e]

### Ticket E2-T1 - [e] Verify private vulnerability reporting and secret scanning [e]

Description: Confirm private vulnerability reporting, secret scanning, and push
protection are enabled where available.

External reason:

- These are GitHub account/repository settings.

### Ticket E2-T2 - [e] Update public GitHub description [e]

Description: Change the repository description to the VEX-first positioning.

Suggested wording:

`Self-hosted VEX-first release evidence ledger for customer CVE, SBOM, provenance, and release-review questions.`

External reason:

- Repository description is provider metadata.

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

## Epic E4 - Next Release Evidence [ ]

### Ticket E4-T1 - Cut the next public RC after E7/E9 push [ ]

Description: Produce and publish the next release-candidate evidence package
after the productization commits are public and public checks pass.

Validation:

- `make production-check`
- `make release-candidate-check TAG=<next-rc>`
- `make public-release-verify TAG=<next-rc>`

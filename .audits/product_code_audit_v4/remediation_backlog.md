# Backlog

Project: Evydence product-code audit v4 remediation

Status legend:

- [ ] not done
- [x] done
- [e] external/customer/provider dependency

## Epic E1 - Public State Alignment [ ]

### Ticket E1-T1 - Push local productization commits [ ]

Description: Publish the local E1-E9 productization work so the public
repository exposes the audited VEX-first reviewer path.

Validation:

- `gh run list --repo aatuh/evydence`
- public `CI` and `CodeQL` pass
- public Scorecard reruns

### Ticket E1-T2 - Cut next public release candidate [ ]

Description: Generate and publish the next RC so release assets include the
portal/reviewer workflow and latest audit/status docs.

Validation:

- `make production-check`
- `make release-candidate-check TAG=<next-rc>`
- `make public-release-verify TAG=<next-rc>`

## Epic E2 - External Product Proof [e]

### Ticket E2-T1 - [e] Run non-maintainer pilot [e]

Description: Have a non-maintainer team use Evydence to answer one real
release-review question.

External reason:

- Requires external participation and permission.

### Ticket E2-T2 - [e] Publish sanitized pilot result [e]

Description: Publish an approved case study or lessons-learned note.

External reason:

- Requires permission and disclosure review.

## Epic E3 - Provider Metadata [e]

### Ticket E3-T1 - [e] Update public GitHub description [e]

Description: Align provider metadata with the README's VEX-first buyer story.

External reason:

- GitHub description is provider metadata.

## Epic E4 - Product Status Discipline [x]

### Ticket E4-T1 - Keep controlled self-hosted candidate wording [x]

Description: Based on audit v4, keep the release status at controlled
self-hosted production candidate and avoid stronger production/compliance
claims.

Validation:

- `make docs-check`
- `make release-acceptance`

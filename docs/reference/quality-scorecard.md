# Quality Scorecard

This scorecard records the evidence supporting the 9/10 execution programme.
It is an engineering assessment, not release marketing, legal compliance proof,
certification, complete SBOM proof, authoritative vulnerability coverage, or a
secure-release guarantee.

Last verified commit: `f845be1428d47ff83ee12503d75d7cecef3c836c`

Overall evidence score: `4.0/10`

## Dimensions

| Dimension | Current score | Target score | Repository evidence | External evidence | Blockers |
| --- | ---: | ---: | --- | --- | --- |
| Dependency-worthiness | 4.0/10 | 9.0/10 | [Persistence inventory](persistence-decomposition.md) | Open: independent deployment evidence | EVY-201 through EVY-405 |
| Code and architecture | 3.0/10 | 9.0/10 | [Architecture](../architecture.md) | Open: independent architecture review | EVY-901 through EVY-906 |
| Tests | 5.0/10 | 9.0/10 | [Release validation](release-validation.md) | Open: target-environment test evidence | EVY-1101 through EVY-1106 |
| Documentation | 6.0/10 | 9.0/10 | [Documentation source map](source-of-truth.md) | Open: design-partner feedback | EVY-1501 through EVY-1506 |
| Open-source trust | 4.0/10 | 9.0/10 | [Security policy](../../SECURITY.md) | Open: repository-control and external-review evidence | EVY-1406, EVY-1601 through EVY-1605 |
| Ecosystem fit | 2.0/10 | 9.0/10 | [Roadmap](roadmap.md) | Open: two independent design-partner pilots | EVY-1606 |
| Feature completeness | 4.0/10 | 9.0/10 | [Capability map](capability-map.md) | Open: customer workflow evidence | EVY-401 through EVY-606 |
| API design | 4.0/10 | 9.0/10 | [API contract matrix](api-contract-matrix.md) | Open: stable-client adoption evidence | EVY-701 through EVY-805 |

Repository evidence demonstrates only the cited implementation, test, or
documentation surface. It does not substitute for the external evidence column.

## Required External Evidence

- [ ] Maintainer-verified repository controls and private vulnerability intake.
- [ ] Independent security and architecture review with findings disposition.
- [ ] At least two sanitized design-partner pilot outcomes.
- [ ] Target deployment, backup, restore, upgrade, and provider-control evidence.
- [ ] Public release and SDK verification from a clean external environment.

## Scoring Rule

Each row must name a repository evidence link, external status, and blocker
disposition. The checker validates local links and rejects an overall score of
9.0/10 or higher while any required external-evidence item is open. Update the
last verified commit only after the listed evidence is rechecked.

The current score is intentionally conservative because the tracked backlog's
known verification, persistence, concurrency, parser, API, architecture, and
external-evidence gaps remain open.

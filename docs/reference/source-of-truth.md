# Documentation Source Of Truth

Use this map to avoid duplicating long command lists, release criteria, or
product-boundary language across the docs.

| Topic | Canonical Source | Notes |
| --- | --- | --- |
| Product positioning and current status | `README.md` and `docs/reference/production-readiness.md` | Other docs should link here instead of redefining release status. |
| Runtime configuration | `docs/reference/configuration.md` | How-to guides may show a short example, then link here for variables. |
| API routes, scopes, idempotency, schemas | `openapi.yaml`, `docs/api.md`, `docs/reference/api-contract-matrix.md` | `openapi.yaml` is generated; the matrix is generated from it. |
| Local startup | `docs/tutorials/getting-started.md` | Uses in-process state only. |
| Durable operation | `docs/how-to/install-and-operate.md` | Includes PostgreSQL/object storage and production-like Compose rehearsal. |
| Kubernetes | `docs/kubernetes.md` | Helm-specific operator interface. |
| Release validation | `docs/reference/release-validation.md` | Canonical release gate behavior. |
| Release-candidate evidence | `docs/reference/release-candidate.md` | Canonical release-candidate artifact checklist. |
| Release evidence artifact map | `docs/reference/release-evidence-index.md` | Maps each release artifact to generation and verification commands. |
| Production profiles and exit criteria | `docs/reference/production-readiness.md` and `docs/reference/production-exit-review.md` | Do not broaden status elsewhere without updating these. |
| Design-partner pilot checklist | `docs/how-to/pilot-deployment-checklist.md` | Narrow copy-paste checklist for one controlled self-hosted pilot profile. |
| Maintainer review ownership | `CODEOWNERS` and `docs/reference/maintainer-review-policy.md` | Branch protection or repository rules must enforce this before it is a merge gate. |
| Roadmap and cadence | `docs/reference/roadmap.md` | Public roadmap, supported release line, and cadence expectations. |
| Backup/restore | `docs/runbooks/backup-restore.md` | Operator rehearsal steps and evidence to keep. |
| Upgrade | `docs/runbooks/upgrade.md` | Migration and release artifact verification steps. |
| Incident response | `docs/runbooks/incident-response.md` | Secrets, tenant, object-store, signing, provider, and package boundaries. |
| Capacity and failure modes | `docs/reference/capacity-and-failures.md` and `docs/reference/benchmark-results.md` | Benchmark results are narrow and local. |
| Security reporting | `SECURITY.md` | Repository settings for private reporting must be verified on GitHub. |
| Support expectations | `SUPPORT.md` | Public support boundaries and sanitized-report rules. |
| Commercial pilot positioning | `docs/commercial/design-partner-pilot.md` and `COMMERCIAL.md` | Pilot docs must not imply legal compliance, certification, scanner authority, SBOM completeness, or secure releases. |
| Reusable product copy | `docs/commercial/product-landing-copy.md` | Website, outreach, and README excerpts should start from this conservative copy. |
| Category comparison | `docs/commercial/category-comparison.md` | Keep comparisons fair, non-hostile, and focused on category boundaries. |

## Repetition Policy

Repeat non-claims briefly where a document can be read alone, but keep detailed
wording in the canonical source. Prefer links over copying full checklists.

Allowed short boundary wording:

> Evydence supports compliance readiness and technical evidence organization;
> it does not make legal compliance conclusions, grant certification, prove SBOM
> completeness, treat scanner output as authoritative, or guarantee release
> security.

Do not create new variants of release status, production profiles, or supported
deployment modes outside the canonical sources above.

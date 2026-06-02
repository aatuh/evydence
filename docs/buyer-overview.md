# Buyer Evaluation Overview

This overview is for product security, AppSec, platform, release, procurement,
and customer-security-review readers who want to understand what Evydence can
show before operating it.

Evydence supports compliance readiness and technical evidence organization. It
does not make legal compliance conclusions, grant certification, prove SBOM
completeness, treat scanner output as authoritative, or guarantee release
security.

## Fastest Buyer Path

1. Run the [customer CVE review demo](tutorials/customer-cve-review-demo.md) to
   inspect one release, one SBOM component, one vulnerability finding, one
   decision, one approval, one package, and one offline verification path.
2. Open the [package viewer guide](how-to/view-packages.md) to see the
   customer-safe package review surface and screenshots.
3. Follow [Evaluate Evydence in 10 minutes](tutorials/evaluate-in-10-minutes.md)
   to verify public release artifacts and inspect package fixtures.
4. Review the [release evidence index](reference/release-evidence-index.md) to
   see what the current public release candidate publishes as reproducible
   engineering evidence.
5. Read the [capability map](reference/capability-map.md) to separate
   implemented behavior from implemented-but-partial areas and external
   controls.

## Questions To Answer

Use the buyer path to answer:

- Which release and artifact are being reviewed?
- Which SBOM and vulnerability scan raised the finding?
- What VEX or manual decision was recorded?
- Who approved or recorded the decision?
- What package can be shared safely?
- What can be verified offline?
- What gaps, assumptions, exceptions, and limitations remain?

## When To Switch To Operator Docs

Move to [Operator Overview](operator-overview.md) when you need to run the API,
worker, PostgreSQL, object storage, release gates, backup/restore rehearsal,
Kubernetes deployment, or production-readiness checks.

For public API integration review, use [OpenAPI contract](reference/openapi.md)
and [API reference](api.md). For production status, use
[Production readiness](reference/production-readiness.md) and
[Production exit review](reference/production-exit-review.md).

# Evydence Documentation

This documentation is organized by task type so roadmap intent and implemented behavior stay separate.

## Tutorials

- [Getting started](tutorials/getting-started.md) walks through a local API run and a small release evidence flow.

## How-To Guides

- [Install and operate](how-to/install-and-operate.md) covers local dependencies, migrations, and runtime choices.

## Reference

- [API reference](api.md) describes the implemented `/v1` HTTP surface.
- [OpenAPI contract](reference/openapi.md) explains how `openapi.yaml` is generated and checked.
- [Worker outbox contract](reference/worker-outbox.md) documents durable job inputs, idempotency, and safe failure behavior.

## Explanation

- [Architecture](architecture.md) explains ports, adapters, storage, worker, and trust boundaries.
- [Trust model](explanation/trust-model.md) summarizes what Evydence verifies and what remains an assumption.

Evydence supports compliance readiness and technical evidence organization. The documentation intentionally avoids legal compliance, certification, complete-SBOM, authoritative scanner, and secure-release claims.

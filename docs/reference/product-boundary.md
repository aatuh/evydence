# Product Boundary And API Stability

This reference defines the intended release-evidence product boundary. It is a
planning and compatibility aid, not evidence of production status, security
assurance, legal conclusions, or support in every deployment.

## Core Outcome

The differentiated core is a release-scoped evidence flow:

1. Create a product, project, release, and artifact.
2. Record build provenance and evidence.
3. Upload SBOM, vulnerability scan, and VEX evidence.
4. Record a VEX/manual decision, approval, or approved exception.
5. Evaluate release readiness.
6. Create, retrieve, and verify a release bundle.
7. Create a scoped customer package and verify its evidence.

## Stability Classes

Every public operation has a generated `x-evydence-stability` value in
`openapi.yaml`. The generated [API contract matrix](api-contract-matrix.md) and
SDK route catalog are the complete operation-level inventory.

| Class | Meaning | Compatibility stance |
| --- | --- | --- |
| `core` | Required by the differentiated release-evidence flow. | Candidate stable surface; a formal compatibility promise follows EVY-705. |
| `supported` | Necessary system or identity support for the core flow. | Maintained with the core, but not a differentiated workflow by itself. |
| `experimental` | Implemented surface outside the current product wedge. | May change, be isolated, or be removed through the documented API process. |
| `deprecated` | A retained operation with a documented replacement and removal path. | No operation currently has this class. |

The current generated inventory contains 43 `core`, 12 `supported`, and 131
`experimental` operations. The counts are not a quality score or a compatibility
promise; review the generated matrix after route changes.

## Experimental Surface

Generic source/deployment/incident tracking, broad controls and questionnaires,
SaaS profiles, marketplace collectors, provider-management records, public
transparency services, custom reporting, and similar adjacent surfaces are
classified `experimental`. They must not be represented as stable SDK coverage
or as the reason to adopt Evydence.

Experimental classification does not weaken authorization, tenant isolation,
append-only history, validation, redaction, or release gates. A future decision
to deprecate or remove a persisted surface requires export, migration, OpenAPI,
SDK, documentation, and changelog treatment.

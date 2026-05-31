# Product Landing Copy

This page is reusable copy for README sections, a website, outreach, or pilot
materials. Keep the wording aligned with repository evidence and avoid legal
compliance, certification, complete SBOM, scanner-authority, or release-security
guarantees.

## Headline

Release evidence customers can verify without handing control to another SaaS.

## One-Sentence Pitch

Evydence is a self-hosted API evidence ledger that organizes release artifacts,
SBOMs, vulnerability decisions, VEX, build provenance, controls, exceptions, and
customer-safe packages into reproducible, tamper-evident records.

## Problem

Software teams are asked for release evidence by customers, procurement,
security review, and internal leadership. The evidence usually lives across CI,
artifact stores, scanners, spreadsheets, tickets, GRC tools, and ad hoc folders.

That makes it hard to answer practical questions:

- what shipped in this release;
- which SBOM, scan, build, VEX, exception, and approval records support it;
- what is missing or explicitly assumed;
- what can be shared with a customer without exposing raw internal evidence;
- how a reviewer can verify the package later.

## How It Works

1. Model products, releases, artifacts, collectors, and controls.
2. Ingest evidence from APIs, CI workflows, SBOMs, scans, OpenVEX, source
   snapshots, and build attestations.
3. Preserve raw payload hashes and tenant-scoped object references while
   normalizing reviewer-safe summaries.
4. Record decisions, exceptions, approvals, lifecycle events, and audit-chain
   entries append-only.
5. Generate release-readiness reports, signed bundles, evidence bundles, and
   customer-safe packages with limitations and verification material.

## Why Self-Hosted

Evydence is designed for teams that need evidence custody, tenant-local storage,
operator-controlled secrets, private package workflows, and deployment-specific
trust decisions.

Self-hosting lets the operator choose PostgreSQL, object storage, signing mode,
backup strategy, network boundaries, and customer-sharing policy. It also keeps
Evydence out of the path of claiming legal or audit conclusions on the
operator's behalf.

## What It Is Not

- Not a vulnerability scanner.
- Not an SBOM generator.
- Not a broad SaaS GRC platform.
- Not a public trust center.
- Not a legal compliance determination.
- Not a certification service.
- Not a guarantee that a release is secure.
- Not a substitute for customer review, external audit, or legal advice.

## Pilot CTA

Design-partner pilot: connect one product release, ingest SBOM plus vulnerability
scan plus VEX/provenance evidence, produce one signed customer-safe evidence
bundle, and review the self-hosted deployment profile.

See [Design Partner Pilot](design-partner-pilot.md) for scope, deliverables,
non-deliverables, support boundaries, and the AGPL/commercial license path.


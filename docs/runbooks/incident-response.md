# Incident Response Runbook

Use this runbook for self-hosted Evydence operational incidents. It does not
replace the operator's security incident process.

## First 15 Minutes

1. Preserve logs, metrics, release evidence, and relevant configuration names.
2. Do not paste secrets, raw evidence payloads, customer data, bearer tokens,
   private keys, provider credentials, or database URLs into public channels.
3. Identify the affected boundary:
   API, tenant isolation, collector identity, SSO/session, object storage,
   signing provider, release package, customer portal, provider integration, or
   deployment infrastructure.
4. If API write integrity is uncertain, stop additional API writer processes and
   keep worker processing paused until object/database consistency is reviewed.
5. If a secret may be exposed, revoke or rotate the affected key/token before
   collecting broader diagnostics.

## Containment Checklist

- API key or collector key exposure: revoke the key, create a new scoped key,
  and review audit-chain entries for the affected actor.
- SSO/session exposure: revoke sessions, refresh trust material if needed, and
  review provider verification receipts.
- Object-store exposure: rotate object-store credentials, review bucket policy,
  and verify tenant-prefixed object access.
- Signing provider exposure: disable the provider, rotate/revoke keys according
  to provider policy, and verify valid-at-signing behavior for historical
  signatures.
- Customer package exposure: expire portal access, create a new redaction
  profile if required, and review package access records.
- Release artifact concern: verify `SHA256SUMS`, manifest signature, OpenAPI
  checksum, migration checksum, SBOM metadata, and provenance metadata.

## Capture Bounded Operator Evidence

Use binaries from the deployment's authenticated release. Configure
`EVYDENCE_API_URL` and `EVYDENCE_API_KEY_FILE` for a private operator key with
explicit `instance:admin`, following the [outbox CLI reference](../reference/worker-outbox.md#operator-cli).
Do not pass the secret on command lines. Capture bounded receipts in a
restricted incident folder:

```sh
umask 077
incident_dir=/srv/evydence/operations/INC-example
mkdir -p "$incident_dir"
evydence outbox backlog > "$incident_dir/outbox-backlog.json"
evydence outbox dead-letters --page-size 50 > "$incident_dir/dead-letters.json"
curl --disable --fail --silent --show-error --max-time 10 \
  "${EVYDENCE_API_URL}/v1/ready" > "$incident_dir/readiness.json"
```

Readiness can return nonzero/503 during the incident; retain that failure and
check process logs rather than treating an empty file as healthy. Follow
dead-letter continuation explicitly when more pages exist. A 409 rejects the
whole page because stored metadata cannot be safely projected; investigate
without editing rows. These payload-free receipts can still be sensitive.

Use the [observability runbook](observability.md) to correlate eligible/overdue
work, expired leases, database waits, object/provider outcomes and known migration
expectations. Detailed metrics/readiness diagnostics require their documented
authority. For containment, use the [stop/drain procedure](upgrade.md#stop-and-restart-the-reference-deployment)
before migrations or paired recovery. Record successful drain or forced
termination with an uncertain job outcome.

After correcting a terminal job's cause, replay only the reviewed job:

```sh
evydence outbox replay --job-id job_example --idempotency-key INC-example-replay-001
evydence outbox backlog
```

Choose one operation key for that intended replay and reuse it if the request
outcome is uncertain. Server authorization and the append-only replay audit
remain mandatory. Confirm durable processing outcomes and the audit entry;
replay acceptance alone is insufficient. Do not alter leases or attempt counts
or create bulk SQL replays.

## Communication

Use concise, factual updates. Do not claim legal compliance, certification,
complete SBOM coverage, scanner authority, or secure releases. State what is
known, what evidence was checked, what remains under review, and what operators
should do next.

## Post-Incident Evidence

- Incident timeline and remediation tasks in Evydence when the deployment is
  trusted again.
- Audit-chain verification result.
- Backup/restore verification if data integrity was in scope.
- Secret rotation evidence.
- Release or customer package re-issue evidence when affected.
- Limitations and assumptions for any report shared externally.

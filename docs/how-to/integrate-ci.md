# Integrate CI Collectors

Use this guide to connect CI systems to Evydence. The examples submit CI metadata and artifacts as tenant-scoped evidence; they do not make Evydence the source of truth for provider-side policy, identity, or workflow state.

## Prerequisites

- An Evydence API URL.
- A tenant admin API key for creating collectors, or an existing collector key with the required write scopes.
- Product, project, release, and artifact IDs for the release being recorded.
- Provider secrets stored in the CI secret store, not committed to the repository.

## Create A Collector

Create a collector with an admin key:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/collectors" \
  -H "Authorization: Bearer $EVYDENCE_ADMIN_API_KEY" \
  -H "Idempotency-Key: collector-github-actions-main" \
  -H "Content-Type: application/json" \
  --data '{"name":"github-actions-main","type":"github_actions","version":"1.0.0"}' \
  | jq .
```

Expected status is `201`. The response returns the collector API key secret once. Store it as a CI secret such as `EVYDENCE_API_KEY`.

## GitHub Actions

The full example workflow is [docs/github-actions/release-evidence-workflow.yml](../github-actions/release-evidence-workflow.yml). The composite upload action is [docs/github-actions/upload-build/action.yml](../github-actions/upload-build/action.yml).

Required CI inputs:

- `EVYDENCE_API_URL`
- `EVYDENCE_API_KEY`
- `EVYDENCE_PROJECT_ID`
- `EVYDENCE_RELEASE_ID`
- `EVYDENCE_ARTIFACT_ID`
- `EVYDENCE_ARTIFACT_DIGEST`
- a DSSE attestation file when uploading build attestation evidence

The CLI command used by the workflow reads GitHub-provided environment variables such as `GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF`, `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_REF`, and `GITHUB_SHA`.

`EVYDENCE_GITHUB_OIDC_SUBJECT` or `--oidc-subject` can record an OIDC subject string when the workflow already has one. This implementation records the value as evidence metadata; it does not request or verify a GitHub OIDC token.

## GitLab CI

The GitLab template is [docs/gitlab/evydence-release-evidence.gitlab-ci.yml](../gitlab/evydence-release-evidence.gitlab-ci.yml).

Required CI variables mirror the GitHub flow:

- `EVYDENCE_API_URL`
- `EVYDENCE_API_KEY`
- `EVYDENCE_PROJECT_ID`
- `EVYDENCE_RELEASE_ID`
- `EVYDENCE_ARTIFACT_ID`
- `EVYDENCE_ARTIFACT_DIGEST`

GitLab-provided variables such as `CI_PROJECT_PATH`, `CI_COMMIT_SHA`, `CI_PIPELINE_ID`, and `CI_JOB_ID` can be included in source snapshots or build evidence.

## Source Snapshots

Use [Source snapshot collectors](../collectors/source-snapshots.md) to upload repository, commit, branch-protection, and pull-request metadata from GitHub or GitLab:

- `POST /v1/collectors/github/source-snapshots`
- `POST /v1/collectors/gitlab/source-snapshots`

Do not include bearer tokens, private repository credentials, or raw provider secret dumps in snapshot payloads. Commit messages are stored as hashes by the API service.

## Collector Supply Chain

Use [Collector supply chain](../collectors/supply-chain.md) to record collector release evidence and health checks:

- `POST /v1/collectors/{id}/releases`
- `GET /v1/collectors/{id}/health`

Collector health reports show whether release evidence exists and whether a collector version is pinned. They do not prove that a collector is free of vulnerabilities or safe to run.

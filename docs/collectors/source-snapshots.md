# Source Snapshot Collectors

This how-to shows the first source-control collector payloads. These endpoints capture provider metadata as evidence; they do not call GitHub or GitLab APIs, verify OIDC tokens, or prove provider-side policy state.

## GitHub

Upload a strict source snapshot with a collector or admin API key that has `source:write`:

```sh
curl -sS -X POST "$EVYDENCE_URL/v1/collectors/github/source-snapshots" \
  -H "Authorization: Bearer $EVYDENCE_API_KEY" \
  -H "Idempotency-Key: github-source-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" \
  -H "Content-Type: application/json" \
  --data @github-source-snapshot.json
```

Minimum useful payload:

```json
{
  "project_id": "proj_...",
  "repository": {
    "full_name": "owner/repo",
    "clone_url": "https://github.com/owner/repo.git",
    "default_branch": "main"
  },
  "commit": {
    "sha": "0123456789abcdef0123456789abcdef01234567",
    "author": "developer@example.test",
    "message": "release change",
    "committed_at": "2026-05-28T10:00:00Z"
  },
  "branch": {
    "name": "main",
    "protected": true,
    "protection_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  },
  "pull_request": {
    "provider_id": "42",
    "title": "Release change",
    "state": "merged",
    "source_branch": "release",
    "target_branch": "main",
    "review_decision": "approved"
  }
}
```

## GitLab

GitLab collectors use the same shape at `/v1/collectors/gitlab/source-snapshots`. A CI job can construct the file from GitLab-provided environment variables, then upload it with a collector API key:

```yaml
evydence-source-snapshot:
  image: curlimages/curl:8.8.0
  script:
    - |
      cat > gitlab-source-snapshot.json <<JSON
      {
        "project_id": "$EVYDENCE_PROJECT_ID",
        "repository": {
          "full_name": "$CI_PROJECT_PATH",
          "clone_url": "$CI_REPOSITORY_URL",
          "default_branch": "$CI_DEFAULT_BRANCH"
        },
        "commit": {
          "sha": "$CI_COMMIT_SHA",
          "author": "$GITLAB_USER_EMAIL",
          "message": "$CI_COMMIT_TITLE",
          "committed_at": "$CI_COMMIT_TIMESTAMP"
        },
        "branch": {
          "name": "$CI_COMMIT_REF_NAME",
          "protected": false
        }
      }
      JSON
    - |
      curl -sS -X POST "$EVYDENCE_URL/v1/collectors/gitlab/source-snapshots" \
        -H "Authorization: Bearer $EVYDENCE_API_KEY" \
        -H "Idempotency-Key: gitlab-source-$CI_PIPELINE_ID-$CI_JOB_ID" \
        -H "Content-Type: application/json" \
        --data @gitlab-source-snapshot.json
```

Do not put bearer tokens or raw provider secrets in the snapshot. Commit messages are stored as hashes by the API service.

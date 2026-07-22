#!/usr/bin/env python3
"""Validate public docs and helper defaults against release/current.json."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
METADATA_PATH = ROOT / "release/current.json"
MAINTENANCE_COMMIT_TYPES = frozenset({"build", "chore", "ci", "merge", "refactor", "test"})


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def require_text(path: str, text: str, failures: list[str]) -> None:
    content = read(path)
    require(text in content, f"{path} missing release-truth text: {text}", failures)


def reject_current_stale(path: str, stale_tags: set[str], failures: list[str]) -> None:
    content = read(path)
    found = sorted(tag for tag in stale_tags if tag in content)
    require(not found, f"{path} contains stale current-release tag(s): {', '.join(found)}", failures)


def unreleased_section_has_entries(changelog: str) -> bool:
    """Return whether the Unreleased section contains a user-visible entry."""

    match = re.search(r"^## Unreleased\s*$([\s\S]*?)(?=^## |\Z)", changelog, re.MULTILINE)
    if match is None:
        return False
    return any(
        line.startswith("- ") and line.strip() != "- No unreleased changes."
        for line in match.group(1).splitlines()
    )


def has_user_visible_commit(subjects: list[str]) -> bool:
    """Conservatively distinguish conventional maintenance commits from release-note work."""

    for subject in subjects:
        match = re.match(r"^([a-z]+)(?:\([^)]*\))?!?:", subject)
        if match is None or match.group(1) not in MAINTENANCE_COMMIT_TYPES:
            return True
    return False


def run_git(*args: str) -> subprocess.CompletedProcess[str]:
    """Run a repository-local Git command without invoking a shell."""

    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def user_visible_commits_since(tag: str) -> tuple[list[str], str | None]:
    """Return user-visible subjects after an ancestor release tag, or a validation error."""

    ancestor = run_git("merge-base", "--is-ancestor", tag, "HEAD")
    if ancestor.returncode != 0:
        detail = ancestor.stderr.strip()
        if ancestor.returncode == 1:
            return [], f"current release tag {tag} is not an ancestor of HEAD"
        return [], f"could not compare current release tag {tag} to HEAD: {detail}"

    log = run_git("log", "--format=%s", f"{tag}..HEAD")
    if log.returncode != 0:
        return [], f"could not read commits after current release tag {tag}: {log.stderr.strip()}"
    subjects = [subject for subject in log.stdout.splitlines() if subject]
    return [subject for subject in subjects if has_user_visible_commit([subject])], None


def git_commit_exists(commit: str) -> bool:
    return run_git("cat-file", "-e", f"{commit}^{{commit}}").returncode == 0


def main() -> int:
    metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    current = metadata["current_public_release"]
    image = metadata["last_verified_project_image"]
    source_snapshot = metadata.get("latest_source_snapshot", {})
    tag = current["tag"]
    repo = metadata["repository"]
    release_date = current["release_date"]
    release_url = current["release_url"]
    commit = current["source_commit"]
    release_run = current["release_artifacts_workflow_run"]
    ci_run = current["production_check_workflow_run"]
    codeql_run = current["codeql_workflow_run"]
    image_tag = image["tag"]
    image_digest = image["digest"]
    snapshot_branch = source_snapshot.get("branch") if isinstance(source_snapshot, dict) else None
    snapshot_commit = source_snapshot.get("commit") if isinstance(source_snapshot, dict) else None
    snapshot_recorded_at = source_snapshot.get("recorded_at") if isinstance(source_snapshot, dict) else None

    failures: list[str] = []
    require(metadata.get("schema") == "evydence-current-release.v1", "release/current.json has unexpected schema", failures)
    require(re.fullmatch(r"v\d+\.\d+\.\d+-rc\.\d+", tag) is not None, f"invalid current release tag: {tag}", failures)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", release_date) is not None, f"invalid release date: {release_date}", failures)
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, f"invalid source commit: {commit}", failures)
    require(isinstance(source_snapshot, dict), "latest_source_snapshot must be an object", failures)
    require(isinstance(snapshot_branch, str) and snapshot_branch, "latest source branch is missing", failures)
    require(
        isinstance(snapshot_commit, str) and re.fullmatch(r"[0-9a-f]{40}", snapshot_commit) is not None,
        "latest source commit is missing or invalid",
        failures,
    )
    require(
        isinstance(snapshot_recorded_at, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", snapshot_recorded_at) is not None,
        "latest source snapshot recorded_at is missing or invalid",
        failures,
    )
    if isinstance(snapshot_commit, str) and re.fullmatch(r"[0-9a-f]{40}", snapshot_commit) is not None:
        require(git_commit_exists(snapshot_commit), f"latest source commit is not available locally: {snapshot_commit}", failures)

    current_command = f"make public-release-verify TAG={tag}"
    release_link = f"[`{tag}`]({release_url})"

    required_current_refs = {
        "README.md": [
            "Current Status",
            "Best for: evaluation, pilots, and controlled internal self-hosted use after operator review.",
            release_link,
            current_command,
        ],
        "docs/tutorials/evaluate-in-10-minutes.md": [current_command],
        "docs/tutorials/getting-started.md": [release_link],
        "docs/how-to/install-and-operate.md": [
            release_link,
            f"mkdir -p dist/{tag}",
            f"gh release download {tag} --repo {repo} --dir dist/{tag}",
            current_command,
        ],
        "docs/reference/release-evidence-index.md": [
            release_link,
            f"tag `{tag}` at commit",
            commit,
            release_run,
            ci_run,
            codeql_run,
            f"gh release download {tag} --repo {repo} --dir dist/{tag}",
            current_command,
        ],
        "docs/reference/release-candidate.md": [release_link],
        "docs/reference/production-exit-review.md": [tag, current_command],
        "docs/reference/production-gate-troubleshooting.md": [current_command],
        "examples/end-to-end-release-evidence/README.md": [current_command],
        ".github/workflows/container-image.yml": [
            f"such as {tag}",
            f'default: "{tag}"',
        ],
        "scripts/public_release_verify.sh": [
            f'TAG:-{tag}',
            f"release candidate tag must look like {tag}",
        ],
        "CHANGELOG.md": [f"## {tag} - {release_date}"],
    }

    for path, texts in required_current_refs.items():
        for text in texts:
            require_text(path, text, failures)

    require_text("README.md", "source snapshot (which is not a release)", failures)
    require_text(
        "RELEASE_EVIDENCE.md",
        "separate provenance facts. A source snapshot\nis not a public release",
        failures,
    )
    if isinstance(snapshot_commit, str) and re.fullmatch(r"[0-9a-f]{40}", snapshot_commit) is not None:
        require_text("docs/reference/release-evidence-index.md", snapshot_commit, failures)

    changelog = read("CHANGELOG.md")
    user_visible_commits, commit_error = user_visible_commits_since(tag)
    if commit_error is not None:
        failures.append(commit_error)
    elif user_visible_commits and not unreleased_section_has_entries(changelog):
        failures.append(
            "CHANGELOG.md says there are no unreleased changes while user-visible commits exist after "
            f"{tag}: {', '.join(user_visible_commits[:3])}"
        )

    stale_tags = {"v0.1.0-rc.1", "v0.1.0-rc.2", "v0.1.0-rc.3", "v0.1.0-rc.4", "v0.1.0-rc.5", "v0.1.0-rc.6"} - {tag}
    for path in [
        "README.md",
        "docs/tutorials/evaluate-in-10-minutes.md",
        "docs/tutorials/getting-started.md",
        "docs/how-to/install-and-operate.md",
        "docs/reference/production-exit-review.md",
        "docs/reference/production-gate-troubleshooting.md",
        "examples/end-to-end-release-evidence/README.md",
        ".github/workflows/container-image.yml",
        "scripts/public_release_verify.sh",
    ]:
        reject_current_stale(path, stale_tags, failures)

    require_text("docs/reference/release-evidence-index.md", image_tag, failures)
    require_text("docs/reference/release-evidence-index.md", image_digest, failures)
    require_text("deploy/airgap/manifest.yaml", image_tag, failures)
    require_text("deploy/airgap/manifest.yaml", image_digest, failures)

    if failures:
        for failure in failures:
            print(f"release-truth-check: {failure}", file=sys.stderr)
        return 1
    print(f"release-truth-check: passed ({tag})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

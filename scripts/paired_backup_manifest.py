#!/usr/bin/env python3
"""Create or verify a paired PostgreSQL/object-store backup manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

SCHEMA_VERSION = "evydence-paired-backup.v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def file_identity(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as src:
        for chunk in iter(lambda: src.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return "sha256:" + h.hexdigest(), size


def migration_identity(root: Path) -> dict[str, object]:
    if not root.is_dir():
        raise ValueError("migration directory does not exist")
    rows: list[str] = []
    latest = ""
    for path in sorted(root.glob("*.sql")):
        if not path.is_file():
            continue
        digest, size = file_identity(path)
        rows.append(f"{path.name}\t{size}\t{digest}\n")
        if path.name.endswith(".up.sql"):
            latest = path.name
    if not rows or not latest:
        raise ValueError("migration directory has no versioned SQL migrations")
    return {
        "migration_set_sha256": "sha256:" + hashlib.sha256("".join(rows).encode()).hexdigest(),
        "latest_migration": latest,
        "file_count": len(rows),
    }


def object_inventory(root: Path) -> dict[str, object]:
    if not root.is_dir():
        raise ValueError("object backup directory does not exist")
    rows: list[str] = []
    count = size_total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f"object backup contains symlink: {relative}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"object backup contains unsupported file type: {relative}")
        digest, size = file_identity(path)
        rows.append(f"{relative}\t{size}\t{digest}\n")
        count += 1
        size_total += size
    return {
        "inventory_sha256": "sha256:" + hashlib.sha256("".join(rows).encode()).hexdigest(),
        "file_count": count,
        "bytes": size_total,
    }


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def validate_checkpoint(checkpoint_id: str, state_hash: str) -> None:
    if not checkpoint_id or checkpoint_id != checkpoint_id.strip() or len(checkpoint_id) > 200:
        raise ValueError("consistency checkpoint id is invalid")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in checkpoint_id):
        raise ValueError("consistency checkpoint id contains control characters")
    if not SHA256_RE.fullmatch(state_hash):
        raise ValueError("consistency checkpoint state hash is invalid")


def build_manifest(db: Path, objects: Path, migrations: Path, commit: str, checkpoint_id: str, state_hash: str) -> dict[str, object]:
    if not db.is_file():
        raise ValueError("database backup file does not exist")
    if not COMMIT_RE.fullmatch(commit):
        raise ValueError("release commit must be a 40-character lowercase Git SHA-1")
    validate_checkpoint(checkpoint_id, state_hash)
    db_digest, db_size = file_identity(db)
    core: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "database": {"file": db.name, "sha256": db_digest, "bytes": db_size},
        "objects": object_inventory(objects),
        "schema": migration_identity(migrations),
        "release_commit": commit,
        "consistency_checkpoint": {"id": checkpoint_id, "state_hash": state_hash},
    }
    core["generation_id"] = "sha256:" + hashlib.sha256(canonical_json(core)).hexdigest()
    return core


def require_manifest(manifest: dict[str, object]) -> None:
    if manifest.get("schema_version") != SCHEMA_VERSION or not SHA256_RE.fullmatch(str(manifest.get("generation_id", ""))):
        raise ValueError("invalid paired backup manifest header")
    for section, key in (("database", "sha256"), ("objects", "inventory_sha256"), ("schema", "migration_set_sha256"), ("consistency_checkpoint", "state_hash")):
        value = manifest.get(section)
        if not isinstance(value, dict) or not SHA256_RE.fullmatch(str(value.get(key, ""))):
            raise ValueError(f"invalid paired backup manifest {section}")
    if not COMMIT_RE.fullmatch(str(manifest.get("release_commit", ""))):
        raise ValueError("invalid paired backup release commit")


def verify_manifest(manifest: dict[str, object], db: Path, objects: Path, migrations: Path, commit: str | None) -> list[str]:
    require_manifest(manifest)
    failures: list[str] = []
    db_digest, db_size = file_identity(db)
    expected_db = manifest["database"]
    assert isinstance(expected_db, dict)
    if db_digest != expected_db.get("sha256") or db_size != expected_db.get("bytes"):
        failures.append("database backup does not match paired generation")
    if object_inventory(objects) != manifest["objects"]:
        failures.append("object backup does not match paired generation")
    if migration_identity(migrations) != manifest["schema"]:
        failures.append("migration/schema identity does not match paired generation")
    if commit is not None and commit != manifest["release_commit"]:
        failures.append("release commit does not match paired generation")
    core = {k: v for k, v in manifest.items() if k != "generation_id"}
    generation = "sha256:" + hashlib.sha256(canonical_json(core)).hexdigest()
    if generation != manifest["generation_id"]:
        failures.append("paired backup manifest generation id is invalid")
    return failures


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    verify = commands.add_parser("verify")
    for command in (create, verify):
        command.add_argument("--database-dump", required=True, type=Path)
        command.add_argument("--objects-dir", required=True, type=Path)
        command.add_argument("--migrations-dir", required=True, type=Path)
        command.add_argument("--release-commit")
    create.add_argument("--checkpoint-id", required=True)
    create.add_argument("--checkpoint-state-hash", required=True)
    create.add_argument("--output", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    try:
        if args.command == "create":
            if args.release_commit is None:
                raise ValueError("release commit is required when creating a manifest")
            manifest = build_manifest(args.database_dump, args.objects_dir, args.migrations_dir, args.release_commit, args.checkpoint_id, args.checkpoint_state_hash)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            print(f"paired backup manifest written: {args.output}")
            return 0
        manifest = json.loads(args.manifest.read_text())
        failures = verify_manifest(manifest, args.database_dump, args.objects_dir, args.migrations_dir, args.release_commit)
        if failures:
            for failure in failures:
                print(f"paired backup preflight failed: {failure}", file=sys.stderr)
            print("safe decision: do not start Evydence; restore a matching trusted database/object generation before dry-run reconciliation", file=sys.stderr)
            return 2
        print(f"paired backup preflight passed: {manifest['generation_id']}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"paired backup preflight error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: not valid JSON: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def severity(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text else "unknown"


def grype_findings(doc: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for match in doc.get("matches", []):
        vulnerability = match.get("vulnerability", {}) if isinstance(match, dict) else {}
        artifact = match.get("artifact", {}) if isinstance(match, dict) else {}
        vuln_id = str(vulnerability.get("id", "")).strip()
        if not vuln_id:
            continue
        component = str(artifact.get("purl") or artifact.get("name") or "").strip()
        findings.append(
            {
                "vulnerability": vuln_id,
                "component": component,
                "severity": severity(vulnerability.get("severity")),
                "state": "open",
            }
        )
    return findings


def trivy_findings(doc: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for result in doc.get("Results", []):
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = str(vuln.get("VulnerabilityID", "")).strip()
            if not vuln_id:
                continue
            component = str(vuln.get("PkgIdentifier", {}).get("PURL") or vuln.get("PkgName") or "").strip()
            findings.append(
                {
                    "vulnerability": vuln_id,
                    "component": component,
                    "severity": severity(vuln.get("Severity")),
                    "state": "open",
                }
            )
    return findings


def request(path: str, idempotency_key: str, payload_file: str, kind: str) -> dict[str, str]:
    return {"kind": kind, "path": path, "idempotency_key": idempotency_key, "payload_file": payload_file}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an Evydence GitHub release evidence upload manifest.")
    parser.add_argument("--out", default=".evydence/upload-manifest.json")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--artifact-id", default="")
    parser.add_argument("--target-ref", required=True)
    parser.add_argument("--idempotency-prefix", required=True)
    parser.add_argument("--cyclonedx-sbom")
    parser.add_argument("--grype-json")
    parser.add_argument("--trivy-json")
    parser.add_argument("--openvex-json")
    parser.add_argument("--include-release-bundle", action="store_true")
    parser.add_argument("--customer-package-product-id", default="")
    parser.add_argument("--customer-package-redaction-profile-id", default="")
    parser.add_argument("--customer-package-title", default="")
    parser.add_argument("--customer-package-expires-at", default="")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out = Path(args.out)
    base = out.parent
    requests: list[dict[str, str]] = []

    if args.cyclonedx_sbom:
        payload = {"release_id": args.release_id, "artifact_id": args.artifact_id, "payload": load_json(args.cyclonedx_sbom)}
        payload_path = base / "sbom-cyclonedx-upload.json"
        write_json(payload_path, payload)
        requests.append(request("/v1/sboms", f"{args.idempotency_prefix}-sbom-cyclonedx", payload_path.name, "sbom"))

    if args.grype_json:
        payload = {
            "scanner": "grype",
            "target_ref": args.target_ref,
            "release_id": args.release_id,
            "source_schema": "grype-json.v1",
            "payload": load_json(args.grype_json),
        }
        payload_path = base / "scan-grype-upload.json"
        write_json(payload_path, payload)
        requests.append(request("/v1/vulnerability-scans", f"{args.idempotency_prefix}-scan-grype", payload_path.name, "scan"))

    if args.trivy_json:
        payload = {
            "scanner": "trivy",
            "target_ref": args.target_ref,
            "release_id": args.release_id,
            "source_schema": "trivy-json.v1",
            "payload": load_json(args.trivy_json),
        }
        payload_path = base / "scan-trivy-upload.json"
        write_json(payload_path, payload)
        requests.append(request("/v1/vulnerability-scans", f"{args.idempotency_prefix}-scan-trivy", payload_path.name, "scan"))

    if args.openvex_json:
        payload = {"release_id": args.release_id, "artifact_id": args.artifact_id, "payload": load_json(args.openvex_json)}
        payload_path = base / "vex-openvex-upload.json"
        write_json(payload_path, payload)
        requests.append(request("/v1/vex", f"{args.idempotency_prefix}-vex-openvex", payload_path.name, "vex"))

    if args.include_release_bundle:
        payload_path = base / "release-bundle-upload.json"
        write_json(payload_path, {"release_id": args.release_id})
        requests.append(request("/v1/release-bundles", f"{args.idempotency_prefix}-release-bundle", payload_path.name, "release_bundle"))

    package_fields = [
        args.customer_package_product_id,
        args.customer_package_redaction_profile_id,
        args.customer_package_title,
        args.customer_package_expires_at,
    ]
    if any(package_fields):
        if not all(package_fields):
            raise SystemExit("customer package fields must be supplied together")
        try:
            datetime.fromisoformat(args.customer_package_expires_at.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as exc:
            raise SystemExit("customer package expires_at must be an RFC3339 timestamp") from exc
        payload_path = base / "customer-package-upload.json"
        write_json(
            payload_path,
            {
                "product_id": args.customer_package_product_id,
                "release_id": args.release_id,
                "redaction_profile_id": args.customer_package_redaction_profile_id,
                "title": args.customer_package_title,
                "expires_at": args.customer_package_expires_at,
            },
        )
        requests.append(request("/v1/customer-packages", f"{args.idempotency_prefix}-customer-package", payload_path.name, "package_export"))

    if not requests:
        raise SystemExit("no evidence inputs were supplied")
    write_json(out, {"schema_version": "evydence-upload-manifest.v1.0.0", "requests": requests})


if __name__ == "__main__":
    main()

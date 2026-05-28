#!/usr/bin/env python3
"""Fail when committed OpenAPI contract precision regresses."""

from __future__ import annotations

import json
import os
import pathlib
import sys

import openapi_contract_matrix


ROOT = pathlib.Path(__file__).resolve().parents[1]


def int_env(name: str, fallback: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return fallback
    try:
        parsed = int(value)
    except ValueError:
        print(f"openapi-precision-check: {name} must be an integer", file=sys.stderr)
        raise SystemExit(2)
    if parsed < 0:
        print(f"openapi-precision-check: {name} must be non-negative", file=sys.stderr)
        raise SystemExit(2)
    return parsed


def main() -> int:
    spec = json.loads((ROOT / "openapi.yaml").read_text(encoding="utf-8"))
    precise = 0
    broad = 0
    for path_item in spec["paths"].values():
        for method, operation in path_item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            if openapi_contract_matrix.precision_label(operation) == "precise":
                precise += 1
            else:
                broad += 1

    min_precise = int_env("EVYDENCE_OPENAPI_MIN_PRECISE", 118)
    max_broad = int_env("EVYDENCE_OPENAPI_MAX_BROAD", 42)
    if precise < min_precise:
        print(
            f"openapi-precision-check: precise operations {precise} below required {min_precise}",
            file=sys.stderr,
        )
        return 1
    if broad > max_broad:
        print(
            f"openapi-precision-check: broad operations {broad} above allowed {max_broad}",
            file=sys.stderr,
        )
        return 1
    print(
        f"openapi-precision-check: {precise} precise operations, {broad} broad operations "
        f"(minimum precise {min_precise}, maximum broad {max_broad})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

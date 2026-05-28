from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EvydenceClient:
    base_url: str
    api_key: str

    def post(self, path: str, idempotency_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not path.startswith("/v1/") or not idempotency_key.strip():
            raise ValueError("invalid Evydence path or idempotency key")
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base_url.rstrip("/") + path,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Idempotency-Key": idempotency_key,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Evydence request failed with status {exc.code}") from exc

    def get(self, path: str) -> dict[str, Any]:
        if not path.startswith("/v1/"):
            raise ValueError("invalid Evydence path")
        headers = {}
        if self.api_key.strip():
            headers["Authorization"] = f"Bearer {self.api_key.strip()}"
        request = urllib.request.Request(
            self.base_url.rstrip("/") + path,
            method="GET",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Evydence request failed with status {exc.code}") from exc

    def create_product(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/products", idempotency_key, payload)

    def create_release(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/releases", idempotency_key, payload)

    def register_artifact(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/artifacts", idempotency_key, payload)

    def create_build(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/builds", idempotency_key, payload)

    def readiness(self) -> dict[str, Any]:
        return self.get("/v1/ready")

    def release_readiness(self, release_id: str) -> dict[str, Any]:
        encoded_release_id = urllib.parse.quote(release_id, safe="")
        return self.get(f"/v1/reports/release-readiness?release_id={encoded_release_id}")

    def create_sso_provider(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/sso/providers", idempotency_key, payload)

    def verify_provider_identity(
        self,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        return self.post("/v1/provider-verifications", idempotency_key, payload)

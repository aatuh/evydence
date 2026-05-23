from __future__ import annotations

import json
import urllib.error
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

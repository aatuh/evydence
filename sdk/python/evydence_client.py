from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from error_codes import ErrorCode, FieldViolation, ProblemDetails, RetryClass


T = TypeVar("T")


@dataclass(frozen=True)
class PageMeta:
    api_version: str
    page_size: int
    sort: str
    direction: str
    next_cursor: str | None = None


@dataclass(frozen=True)
class PageEnvelope(Generic[T]):
    data: list[T]
    meta: PageMeta


class EvydenceProblemError(RuntimeError):
    """Typed RFC 9457 response error; switch on ``problem.code``."""

    def __init__(self, problem: ProblemDetails) -> None:
        self.problem = problem
        super().__init__(f"Evydence request failed with status {problem.status} ({problem.code.value})")


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
            raise _problem_error(exc) from exc

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
            raise _problem_error(exc) from exc

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


def _problem_error(exc: urllib.error.HTTPError) -> EvydenceProblemError:
    retry_after = _positive_int(exc.headers.get("Retry-After"))
    fallback = ProblemDetails(
        type="about:blank",
        title="Request failed",
        status=exc.code,
        detail="request failed",
        code=ErrorCode.INTERNAL_ERROR,
        request_id="",
        retryable=False,
        retry_class=RetryClass.NONE,
        retry_after_seconds=retry_after,
    )
    try:
        payload = json.loads(exc.read().decode("utf-8"))
        if not isinstance(payload, dict):
            return EvydenceProblemError(fallback)
        violations = tuple(
            FieldViolation(field=item["field"], code=item["code"])
            for item in payload.get("violations", [])
            if isinstance(item, dict) and isinstance(item.get("field"), str) and isinstance(item.get("code"), str)
        )
        code = ErrorCode(payload["code"])
        retry_class = RetryClass(payload.get("retry_class", "none"))
        problem = ProblemDetails(
            type=str(payload.get("type", fallback.type)),
            title=str(payload.get("title", fallback.title)),
            status=exc.code,
            detail=str(payload.get("detail", fallback.detail)),
            code=code,
            request_id=str(payload.get("request_id", "")),
            retryable=bool(payload.get("retryable", False)),
            retry_class=retry_class,
            instance=payload.get("instance") if isinstance(payload.get("instance"), str) else None,
            retry_after_seconds=retry_after or _positive_int(payload.get("retry_after_seconds")),
            violations=violations,
        )
        return EvydenceProblemError(problem)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return EvydenceProblemError(fallback)


def _positive_int(value: object) -> int | None:
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None

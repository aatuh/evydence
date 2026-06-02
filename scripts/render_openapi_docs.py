#!/usr/bin/env python3
"""Render a deterministic static OpenAPI reference page.

The renderer intentionally avoids remote assets and does not execute shell
commands. It reads the committed OpenAPI document and writes a static HTML page
that can be reviewed locally or hosted as a static artifact.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_PATH = ROOT / "openapi.yaml"
OUTPUT_PATHS = (
    ROOT / "docs" / "openapi" / "index.html",
    ROOT / "site" / "marketing" / "public" / "api" / "index.html",
)
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")


def escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def load_spec() -> dict[str, Any]:
    try:
        return json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{OPENAPI_PATH} is not valid JSON-compatible OpenAPI: {exc}") from exc


def ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def schema_label(schema: Any) -> str:
    if not isinstance(schema, dict):
        return "unspecified"
    if "$ref" in schema:
        return ref_name(schema["$ref"])
    if "oneOf" in schema:
        return "oneOf(" + ", ".join(schema_label(item) for item in schema["oneOf"]) + ")"
    if "anyOf" in schema:
        return "anyOf(" + ", ".join(schema_label(item) for item in schema["anyOf"]) + ")"
    if "allOf" in schema:
        return "allOf(" + ", ".join(schema_label(item) for item in schema["allOf"]) + ")"
    typ = schema.get("type")
    if typ == "array":
        return f"array[{schema_label(schema.get('items'))}]"
    if isinstance(typ, list):
        return "|".join(str(item) for item in typ)
    return str(typ or "object")


def sorted_response_codes(responses: dict[str, Any]) -> list[str]:
    def key(code: str) -> tuple[int, str]:
        if code.isdigit():
            return (int(code), code)
        return (9999, code)

    return sorted(responses, key=key)


def operation_security(operation: dict[str, Any]) -> str:
    security = operation.get("security")
    if security == []:
        return "Public"
    if not security:
        return "BearerAuth"
    schemes = []
    for entry in security:
        if isinstance(entry, dict):
            schemes.extend(entry.keys())
    return ", ".join(sorted(set(schemes))) or "BearerAuth"


def operation_scopes(operation: dict[str, Any]) -> str:
    scopes = operation.get("x-scopes") or []
    if not scopes:
        return "none"
    return ", ".join(str(scope) for scope in scopes)


def operation_idempotency(operation: dict[str, Any]) -> str:
    idempotency = operation.get("x-idempotency-key")
    if isinstance(idempotency, dict) and idempotency.get("required"):
        return str(idempotency.get("header") or "Idempotency-Key")
    return "not required"


def request_summary(operation: dict[str, Any]) -> str:
    body = operation.get("requestBody")
    if not isinstance(body, dict):
        return "none"
    content = body.get("content")
    if not isinstance(content, dict) or not content:
        return "present"
    pieces = []
    for media_type in sorted(content):
        media = content.get(media_type) or {}
        pieces.append(f"{media_type}: {schema_label(media.get('schema'))}")
    return "; ".join(pieces)


def response_summary(operation: dict[str, Any]) -> str:
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return "none"
    pieces = []
    for code in sorted_response_codes(responses):
        response = responses.get(code) or {}
        content = response.get("content") or {}
        schemas = []
        for media_type in sorted(content):
            media = content.get(media_type) or {}
            schemas.append(f"{media_type}: {schema_label(media.get('schema'))}")
        description = response.get("description") or ""
        detail = ", ".join(schemas) if schemas else description
        pieces.append(f"{code} {detail}".strip())
    return "; ".join(pieces)


def collect_operations(spec: dict[str, Any]) -> list[dict[str, str]]:
    operations: list[dict[str, str]] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise SystemExit("OpenAPI document is missing a paths object")

    for path in sorted(paths):
        item = paths[path]
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            operations.append(
                {
                    "method": method.upper(),
                    "path": path,
                    "summary": str(operation.get("summary") or ""),
                    "description": str(operation.get("description") or ""),
                    "operation_id": str(operation.get("operationId") or ""),
                    "tags": ", ".join(str(tag) for tag in operation.get("tags") or []),
                    "security": operation_security(operation),
                    "scopes": operation_scopes(operation),
                    "idempotency": operation_idempotency(operation),
                    "request": request_summary(operation),
                    "responses": response_summary(operation),
                    "search": " ".join(
                        str(part)
                        for part in (
                            method,
                            path,
                            operation.get("summary") or "",
                            operation.get("description") or "",
                            operation.get("operationId") or "",
                            " ".join(operation.get("tags") or []),
                            operation_scopes(operation),
                        )
                    ).lower(),
                }
            )
    return operations


def collect_schemas(spec: dict[str, Any]) -> list[dict[str, str]]:
    schemas = spec.get("components", {}).get("schemas", {})
    if not isinstance(schemas, dict):
        return []
    rows = []
    for name in sorted(schemas):
        schema = schemas[name]
        required = schema.get("required") if isinstance(schema, dict) else None
        rows.append(
            {
                "name": name,
                "type": schema_label(schema),
                "required": ", ".join(str(item) for item in required or []) or "none",
            }
        )
    return rows


def render(spec: dict[str, Any]) -> str:
    operations = collect_operations(spec)
    schemas = collect_schemas(spec)
    info = spec.get("info") or {}
    problem_schema = spec.get("components", {}).get("schemas", {}).get("Problem", {})
    problem_required = ", ".join(problem_schema.get("required") or []) if isinstance(problem_schema, dict) else "none"

    operation_html = []
    for op in operations:
        search = escape(op["search"])
        operation_html.append(
            f"""
          <article class="operation" data-operation data-search="{search}">
            <div class="operation-heading">
              <span class="method method-{escape(op['method'].lower())}">{escape(op['method'])}</span>
              <code>{escape(op['path'])}</code>
            </div>
            <h3>{escape(op['summary'] or op['operation_id'] or op['path'])}</h3>
            <p>{escape(op['description'] or 'No operation description is registered.')}</p>
            <dl>
              <div><dt>Operation ID</dt><dd><code>{escape(op['operation_id'] or 'not registered')}</code></dd></div>
              <div><dt>Tags</dt><dd>{escape(op['tags'] or 'none')}</dd></div>
              <div><dt>Auth</dt><dd>{escape(op['security'])}</dd></div>
              <div><dt>Scopes</dt><dd>{escape(op['scopes'])}</dd></div>
              <div><dt>Idempotency</dt><dd>{escape(op['idempotency'])}</dd></div>
              <div><dt>Request</dt><dd>{escape(op['request'])}</dd></div>
              <div><dt>Responses</dt><dd>{escape(op['responses'])}</dd></div>
            </dl>
          </article>"""
        )

    schema_html = []
    for schema in schemas:
        schema_html.append(
            f"""
          <tr>
            <td><code>{escape(schema['name'])}</code></td>
            <td>{escape(schema['type'])}</td>
            <td>{escape(schema['required'])}</td>
          </tr>"""
        )

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{escape(info.get('title') or 'Evydence API')} - Rendered OpenAPI Docs</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #f7f5ef;
        --ink: #0f1411;
        --muted: #51615b;
        --line: #d7d2c5;
        --panel: #fffdf7;
        --accent: #006d5b;
        --accent-soft: #d7eee8;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background: var(--bg);
        color: var(--ink);
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        line-height: 1.55;
      }}
      header {{
        border-bottom: 1px solid var(--line);
        padding: 40px clamp(20px, 5vw, 64px);
      }}
      main {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 28px clamp(16px, 4vw, 40px) 60px;
      }}
      h1 {{
        margin: 0 0 12px;
        font-size: clamp(2rem, 4vw, 4rem);
        line-height: 1;
      }}
      h2 {{ margin: 36px 0 16px; font-size: 1.5rem; }}
      h3 {{ margin: 14px 0 8px; font-size: 1.1rem; }}
      p {{ max-width: 76ch; color: var(--muted); }}
      a {{ color: var(--accent); }}
      code {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
        font-size: 0.95em;
        overflow-wrap: anywhere;
      }}
      .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-top: 24px;
      }}
      .summary-card, .operation, .schema-table {{
        background: var(--panel);
        border: 1px solid var(--line);
        border-radius: 8px;
      }}
      .summary-card {{ padding: 16px; }}
      .summary-card strong {{ display: block; font-size: 1.6rem; }}
      .controls {{
        display: grid;
        gap: 8px;
        margin: 24px 0;
      }}
      input[type="search"] {{
        width: 100%;
        border: 1px solid var(--line);
        border-radius: 8px;
        padding: 14px 16px;
        font: inherit;
        background: white;
      }}
      .operations {{
        display: grid;
        gap: 14px;
      }}
      .operation {{ padding: 18px; }}
      .operation[hidden] {{ display: none; }}
      .operation-heading {{
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
      }}
      .method {{
        display: inline-flex;
        min-width: 64px;
        justify-content: center;
        border-radius: 999px;
        padding: 4px 10px;
        background: var(--accent-soft);
        color: #003f35;
        font-weight: 700;
        font-size: 0.8rem;
        letter-spacing: 0;
      }}
      .method-post {{ background: #e7ecff; color: #23347b; }}
      .method-get {{ background: #d7eee8; color: #005345; }}
      .method-delete {{ background: #ffe6df; color: #80311e; }}
      .method-patch, .method-put {{ background: #fff0c2; color: #654600; }}
      dl {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 10px 18px;
        margin: 16px 0 0;
      }}
      dt {{
        color: var(--muted);
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
      }}
      dd {{ margin: 2px 0 0; overflow-wrap: anywhere; }}
      table {{
        width: 100%;
        border-collapse: collapse;
      }}
      th, td {{
        border-top: 1px solid var(--line);
        padding: 10px 12px;
        text-align: left;
        vertical-align: top;
      }}
      th {{ color: var(--muted); font-size: 0.82rem; text-transform: uppercase; }}
      .schema-table {{
        overflow-x: auto;
      }}
      .notice {{
        border-left: 4px solid var(--accent);
        padding: 12px 16px;
        background: var(--panel);
      }}
    </style>
  </head>
  <body>
    <header>
      <h1>{escape(info.get('title') or 'Evydence API')}</h1>
      <p>{escape(info.get('description') or 'Rendered OpenAPI reference for Evydence.')}</p>
      <p>This page is generated from <code>openapi.yaml</code>. It is a human-readable companion to the committed contract and does not replace route-contract tests.</p>
      <div class="summary-grid">
        <div class="summary-card"><strong>{escape(spec.get('openapi') or 'unknown')}</strong><span>OpenAPI version</span></div>
        <div class="summary-card"><strong>{len(spec.get('paths') or {})}</strong><span>registered paths</span></div>
        <div class="summary-card"><strong>{len(operations)}</strong><span>operations</span></div>
        <div class="summary-card"><strong>{len(schemas)}</strong><span>schemas</span></div>
      </div>
    </header>
    <main>
      <section class="notice" aria-label="Security and limitation note">
        <p>Runtime secrets, tenant data, raw evidence payloads, private keys, bearer tokens, and customer package contents are not embedded in this generated page. Admin-scoped routes appear only when they are part of the committed public contract.</p>
        <p>Error responses use RFC 9457-style Problem Details. The registered <code>Problem</code> schema currently requires: {escape(problem_required or 'none')}.</p>
      </section>

      <section>
        <h2>Operations</h2>
        <div class="controls">
          <label for="operation-search">Filter operations</label>
          <input id="operation-search" type="search" autocomplete="off" placeholder="Search by method, path, summary, tag, or scope" />
        </div>
        <div class="operations" id="operations">
          {''.join(operation_html)}
        </div>
      </section>

      <section>
        <h2>Schemas</h2>
        <div class="schema-table">
          <table>
            <thead>
              <tr><th>Name</th><th>Shape</th><th>Required fields</th></tr>
            </thead>
            <tbody>
              {''.join(schema_html)}
            </tbody>
          </table>
        </div>
      </section>
    </main>
    <script>
      const search = document.getElementById("operation-search");
      const operations = Array.from(document.querySelectorAll("[data-operation]"));
      search.addEventListener("input", () => {{
        const query = search.value.trim().toLowerCase();
        for (const operation of operations) {{
          operation.hidden = query.length > 0 && !operation.dataset.search.includes(query);
        }}
      }});
    </script>
  </body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Render or check static OpenAPI docs")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write docs/openapi/index.html")
    mode.add_argument("--check", action="store_true", help="fail if docs/openapi/index.html is stale")
    args = parser.parse_args()

    rendered = render(load_spec())
    if args.write:
        for path in OUTPUT_PATHS:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered, encoding="utf-8")
        return 0

    stale = False
    try:
        for path in OUTPUT_PATHS:
            current = path.read_text(encoding="utf-8")
            if current != rendered:
                print(f"{path} is stale; run scripts/render_openapi_docs.py --write", file=sys.stderr)
                stale = True
    except FileNotFoundError as exc:
        print(f"{exc.filename} is missing; run scripts/render_openapi_docs.py --write", file=sys.stderr)
        return 1
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())

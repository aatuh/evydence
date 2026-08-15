import os

from evydence_client import EvydenceClient


client = EvydenceClient(
    base_url=os.environ.get("EVYDENCE_URL", "http://localhost:8080"),
    api_key=os.environ["EVYDENCE_API_KEY"],
)

product = client.create_product(
    "example-python-product",
    {"name": "Example API", "slug": "example-api"},
)
product_id = product["data"]["id"]

release = client.create_release(
    "example-python-release",
    {"product_id": product_id, "version": "1.0.0"},
)
release_id = release["data"]["id"]

artifact = client.register_artifact(
    "example-python-artifact",
    {
        "release_id": release_id,
        "name": "example-api.tar.gz",
        "media_type": "application/gzip",
        "digest": "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "size": 42,
    },
)
artifact_id = artifact["data"]["id"]

client.post(
    "/v1/sboms",
    "example-python-sbom",
    {
        "release_id": release_id,
        "artifact_id": artifact_id,
        "payload": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"type": "library", "name": "openssl", "purl": "pkg:apk/openssl@3.1.0"}],
        },
    },
)

scan = client.post(
    "/v1/vulnerability-scans",
    "example-python-scan",
    {
        "release_id": release_id,
        "scanner": "grype",
        "target_ref": "pkg:oci/example-api",
        "findings": [
            {
                "vulnerability": "CVE-2026-0099",
                "component": "pkg:apk/openssl@3.1.0",
                "severity": "critical",
                "state": "open",
            }
        ],
    },
)
finding_id = scan["data"]["findings"][0]["id"]

client.post(
    f"/v1/vulnerability-findings/{finding_id}/decisions",
    "example-python-decision",
    {
        "status": "not_affected",
        "justification": "Example decision; replace with real technical analysis.",
    },
)

print(client.release_readiness(release_id)["data"])

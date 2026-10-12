import { EvydenceClient } from "../../sdk/typescript/client";

const client = new EvydenceClient({
  baseUrl: process.env.EVYDENCE_URL ?? "http://localhost:8080",
  apiKey: process.env.EVYDENCE_API_KEY ?? "",
});

const product = await client.createProduct<{ data: { id: string } }>(
  "example-typescript-product",
  { name: "Example API", slug: "example-api" },
);

const release = await client.createRelease<{ data: { id: string } }>(
  "example-typescript-release",
  { product_id: product.data.id, version: "1.0.0" },
);

const artifact = await client.registerArtifact<{ data: { id: string } }>(
  "example-typescript-artifact",
  {
    name: "example-api.tar.gz",
    media_type: "application/gzip",
    digest: "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    size: 42,
  },
);

await client.post("/v1/sboms", "example-typescript-sbom", {
  release_id: release.data.id,
  artifact_id: artifact.data.id,
  payload: {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    components: [{ name: "openssl", purl: "pkg:apk/openssl@3.1.0" }],
  },
});

const scan = await client.post<{ data: { findings: Array<{ id: string }> } }>(
  "/v1/vulnerability-scans",
  "example-typescript-scan",
  {
    release_id: release.data.id,
    scanner: "grype",
    target_ref: "pkg:oci/example-api",
    findings: [{
      vulnerability: "CVE-2026-0099",
      component: "pkg:apk/openssl@3.1.0",
      severity: "critical",
      state: "open",
    }],
  },
);

await client.post(
  `/v1/vulnerability-findings/${scan.data.findings[0].id}/decisions`,
  "example-typescript-decision",
  {
    status: "not_affected",
    justification: "Example decision; replace with real technical analysis.",
  },
);

console.log(await client.releaseReadiness(release.data.id));

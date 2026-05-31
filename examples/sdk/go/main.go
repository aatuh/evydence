package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aatuh/evydence/sdk/go/evydence"
)

func main() {
	client := evydence.Client{
		BaseURL: env("EVYDENCE_URL", "http://localhost:8080"),
		APIKey:  os.Getenv("EVYDENCE_API_KEY"),
	}

	ctx := context.Background()

	var product map[string]any
	if err := client.CreateProduct(context.Background(), "example-go-product", evydence.CreateProductRequest{
		Name: "Example API",
		Slug: "example-api",
	}, &product); err != nil {
		panic(err)
	}
	productID := id(product)

	var release map[string]any
	if err := client.CreateRelease(ctx, "example-go-release", evydence.CreateReleaseRequest{
		ProductID: productID,
		Version:   "1.0.0",
	}, &release); err != nil {
		panic(err)
	}
	releaseID := id(release)

	var artifact map[string]any
	if err := client.RegisterArtifact(ctx, "example-go-artifact", evydence.RegisterArtifactRequest{
		ReleaseID: releaseID,
		Name:      "example-api.tar.gz",
		MediaType: "application/gzip",
		Digest:    "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		Size:      42,
	}, &artifact); err != nil {
		panic(err)
	}
	artifactID := id(artifact)

	if err := client.Post(ctx, "/v1/sboms", "example-go-sbom", map[string]any{
		"release_id":  releaseID,
		"artifact_id": artifactID,
		"payload": map[string]any{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.6",
			"components": []map[string]string{{
				"name": "openssl",
				"purl": "pkg:apk/openssl@3.1.0",
			}},
		},
	}, nil); err != nil {
		panic(err)
	}

	var scan map[string]any
	if err := client.Post(ctx, "/v1/vulnerability-scans", "example-go-scan", map[string]any{
		"release_id": releaseID,
		"scanner":    "grype",
		"target_ref": "pkg:oci/example-api",
		"findings": []map[string]string{{
			"vulnerability": "CVE-2026-0099",
			"component":     "pkg:apk/openssl@3.1.0",
			"severity":      "critical",
			"state":         "open",
		}},
	}, &scan); err != nil {
		panic(err)
	}
	findingID := nestedID(scan, "findings")

	if err := client.Post(ctx, "/v1/vulnerability-findings/"+findingID+"/decisions", "example-go-decision", map[string]any{
		"status":        "not_affected",
		"justification": "Example decision; replace with real technical analysis.",
	}, nil); err != nil {
		panic(err)
	}

	var readiness map[string]any
	if err := client.ReleaseReadiness(ctx, releaseID, &readiness); err != nil {
		panic(err)
	}
	fmt.Printf("release readiness: %#v\n", readiness["data"])
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func id(envelope map[string]any) string {
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		panic("missing data envelope")
	}
	value, ok := data["id"].(string)
	if !ok || value == "" {
		panic("missing id")
	}
	return value
}

func nestedID(envelope map[string]any, field string) string {
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		panic("missing data envelope")
	}
	items, ok := data[field].([]any)
	if !ok || len(items) == 0 {
		panic("missing nested items")
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		panic("nested item has unexpected shape")
	}
	value, ok := first["id"].(string)
	if !ok || value == "" {
		panic("missing nested id")
	}
	return value
}

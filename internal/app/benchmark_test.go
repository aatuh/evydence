package app

import (
	"context"
	"strconv"
	"testing"
)

func BenchmarkReleaseEvidenceIngestion(b *testing.B) {
	ctx := context.Background()
	ledger := NewLedger(Config{APIKeyPepper: "benchmark-pepper"})
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Benchmark Tenant", "admin", []string{"*"})
	if err != nil {
		b.Fatal(err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		b.Fatal(err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "Benchmark Product", "bench-product")
	if err != nil {
		b.Fatal(err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
			ProductID:   product.ID,
			ReleaseID:   release.ID,
			Type:        "build",
			Subtype:     "benchmark",
			Title:       "Benchmark evidence " + strconv.Itoa(i),
			PayloadHash: "sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
			Tags:        []string{"benchmark"},
			Limitations: []string{"Local benchmark evidence only."},
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

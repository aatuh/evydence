package app

import packageapp "github.com/aatuh/evydence/internal/package/app"

// Request-body limits are expressed in bytes and are intentionally owned by
// the application layer. HTTP transports must use these values rather than
// carrying a second, divergent set of limits.
const (
	SmallJSONRequestLimit       int64 = 64 << 10
	EvidenceDocumentLimit       int64 = 20 << 20
	EvidenceArchiveRequestLimit int64 = 128 << 20
	ReportTemplateRequestLimit  int64 = packageapp.ReportTemplateRequestLimit
	// MaxGeneratedReportBytes bounds a report or materialized report view after
	// rendering, not merely its request template. This protects report outputs
	// from growing with stored tenant metadata.
	MaxGeneratedReportBytes = packageapp.MaxGeneratedReportBytes
	// Customer package generation stays within the archive shape accepted by
	// the offline verifier. Stored ZIP entries avoid compression-ratio drift.
	MaxCustomerPackageFileBytes     = 10 << 20
	MaxCustomerPackageArchiveBytes  = 32 << 20
	MaxCustomerPackageExpandedBytes = 40 << 20
	// MaxEvidenceSummaryItems caps report construction over a scoped release.
	MaxEvidenceSummaryItems = 512
	// Evidence graph snapshots are deliberately bounded materialized views,
	// never unbounded tenant graph traversals.
	MaxEvidenceGraphNodes = 4096
	MaxEvidenceGraphEdges = 8192
)

// ValidPayloadSize applies the size invariant before an ingestion service
// trusts a streamed payload's digest or stages it in object storage.
func ValidPayloadSize(size, limit int64) bool {
	return size > 0 && limit > 0 && size <= limit
}

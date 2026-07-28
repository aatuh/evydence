package app

// Request-body limits are expressed in bytes and are intentionally owned by
// the application layer. HTTP transports must use these values rather than
// carrying a second, divergent set of limits.
const (
	SmallJSONRequestLimit       int64 = 64 << 10
	EvidenceDocumentLimit       int64 = 20 << 20
	EvidenceArchiveRequestLimit int64 = 128 << 20
	ReportTemplateRequestLimit  int64 = 1 << 20
)

// ValidPayloadSize applies the size invariant before an ingestion service
// trusts a streamed payload's digest or stages it in object storage.
func ValidPayloadSize(size, limit int64) bool {
	return size > 0 && limit > 0 && size <= limit
}

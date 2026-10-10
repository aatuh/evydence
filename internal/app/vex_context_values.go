package app

import (
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// Pure detached values shared by active memory, worker and context adapters.
// These helpers own no Ledger, authorization or parser workflow.
func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := value.UTC()
	return &clone
}

func cloneSubjectRefs(refs []domain.SubjectRef) []domain.SubjectRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]domain.SubjectRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, domain.SubjectRef{Type: strings.TrimSpace(ref.Type), ID: strings.TrimSpace(ref.ID), Digest: strings.TrimSpace(ref.Digest)})
	}
	return out
}

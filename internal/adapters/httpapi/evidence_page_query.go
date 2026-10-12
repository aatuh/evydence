package httpapi

import (
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func evidencePageFromQuery(page appquery.Result[evidencedomain.EvidenceItem]) appquery.Result[domain.EvidenceItem] {
	items := make([]domain.EvidenceItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, domain.EvidenceFromContextModel(item))
	}
	return appquery.Result[domain.EvidenceItem]{Items: items, Next: page.Next}
}

package wiring

import (
	"time"

	"github.com/aatuh/evydence/internal/app"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	"github.com/aatuh/evydence/internal/platform/vexpreview"
)

func BuildVEXPreviewQuery(reader evidencequery.VEXPreviewReader) (*evidencequery.VEXPreviews, error) {
	return evidencequery.NewVEXPreviews(reader, app.VEXPayloadParser{}, vexpreview.MapEffects, time.Now)
}

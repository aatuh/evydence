package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (l *Ledger) SigningCustodyReviewReport(ctx context.Context, actor domain.Actor) (domain.SigningCustodyReviewReport, error) {
	value, err := l.verificationCommands.SigningCustodyReviewReport(ctx, actor)
	return signingCustodyReviewReportFromVerificationContext(value), fromVerificationContextError(err)
}

func signingCustodyReviewReportFromVerificationContext(value verificationdomain.SigningCustodyReviewReport) domain.SigningCustodyReviewReport {
	return domain.SigningCustodyReviewFromContextModel(value)
}

package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func cosignVerificationFromFocused(r verificationdomain.CosignVerification) domain.CosignVerification {
	return domain.CosignVerificationFromContextModel(r)
}

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestSAMLProviderReceiptRejectsUnboundAssertionBeforeVerification(t *testing.T) {
	c, f, a, in := newProviderReceiptFixture(t)
	f.provider.Type = "saml"
	in.ProviderType = "saml"
	in.SAMLAssertion = "historical-assertion"
	if v, err := c.VerifyProviderIdentity(t.Context(), a, in); !errors.Is(err, ErrUnauthorized) || v.ID != "" || f.localCalls != 0 || len(f.records)+len(f.audits) != 0 {
		t.Fatal("unbound SAML receipt reached credential authority", err)
	}
}

type samlReceiptTransactions struct {
	receipt *providerReceiptFixture
	proof   *exchangeCommandFixture
}
type samlReceiptTransaction struct {
	ProviderVerificationTransaction
	proof *exchangeCommandFixture
}

func (t samlReceiptTransactions) ExecuteProviderVerification(ctx context.Context, run func(context.Context, ProviderVerificationTransaction) error) error {
	oldRequest := t.proof.samlRequest
	oldUses := t.proof.samlUses
	t.proof.samlUses = make(map[string]bool, len(oldUses))
	for h, v := range oldUses {
		t.proof.samlUses[h] = v
	}
	err := t.receipt.ExecuteProviderVerification(ctx, func(ctx context.Context, tx ProviderVerificationTransaction) error {
		return run(ctx, samlReceiptTransaction{tx, t.proof})
	})
	if err != nil {
		t.proof.samlRequest, t.proof.samlUses = oldRequest, oldUses
	}
	return err
}
func (t samlReceiptTransaction) ConsumeSAMLAuthenticationRequest(ctx context.Context, r identitydomain.SAMLAuthenticationRequest, p identitydomain.SAMLAssertionUse, c application.Clock) (time.Time, error) {
	return t.proof.ConsumeSAMLAuthenticationRequest(ctx, r, p, c)
}
func boundSAMLProviderReceiptForTest(t *testing.T) (*ProviderVerificationCommands, *providerReceiptFixture, *exchangeCommandFixture, identitydomain.Actor, VerifyProviderIdentityInput) {
	t.Helper()
	exchange, proof, login, now := boundSAMLExchangeCommandsForTest(t)
	c, f, a, in := newProviderReceiptFixture(t)
	f.provider = cloneSSOProvider(proof.provider)
	f.local = proof.result
	c.config.Clock = application.ClockFunc(func() time.Time { return now })
	c.config.SAMLAuthentication = proof
	c.config.ProofCredentials = exchange.config.ProofCredentials
	c.config.Transactions = samlReceiptTransactions{f, proof}
	in.ProviderType, in.SAMLAssertion, in.AuthenticationRequestID, in.StateSecret = "saml", login.SAMLAssertion, login.AuthenticationRequestID, login.StateSecret
	return c, f, proof, a, in
}
func TestSAMLProviderReceiptConsumesProofWithoutSessionAuthority(t *testing.T) {
	c, f, proof, a, in := boundSAMLProviderReceiptForTest(t)
	v, err := c.VerifyProviderIdentity(t.Context(), a, in)
	if err != nil || v.Result != "passed" || len(f.records) != 1 || len(f.audits) != 2 || proof.samlRequest.ConsumedAt == nil || len(proof.samlUses) != 1 || len(proof.sessions) != 0 {
		t.Fatal("SAML receipt lost atomic proof consumption or issued a session", err)
	}
	if err := c.AuthorizeVerifyProviderIdentity(t.Context(), a, in); err != nil {
		t.Fatal("historical receipt replay guard demanded pending proof", err)
	}
	if _, err := c.VerifyProviderIdentity(t.Context(), a, in); !errors.Is(err, ErrUnauthorized) || len(f.records) != 1 || len(f.audits) != 2 {
		t.Fatal("fresh SAML receipt reused consumed proof", err)
	}
}
func TestSAMLProviderReceiptRollbackPreservesProofAndDeniedIdentityConsumesIt(t *testing.T) {
	for _, phase := range []string{"snapshot", "insert", "audit", "commit", "unverified link", "local failure"} {
		c, f, proof, a, in := boundSAMLProviderReceiptForTest(t)
		f.phase = phase
		if phase == "unverified link" {
			f.link.Verified = false
		}
		v, err := c.VerifyProviderIdentity(t.Context(), a, in)
		if phase == "unverified link" || phase == "local failure" {
			if !errors.Is(err, ErrVerificationFailed) || v.Result != "failed" || len(f.records) != 1 {
				t.Fatal("SAML receipt denial became authority", phase, err)
			}
			if (proof.samlRequest.ConsumedAt != nil) != (phase == "unverified link") {
				t.Fatal("SAML receipt consumed invalid or retained verified proof", phase)
			}
		} else if err == nil || v.ID != "" || len(f.records)+len(f.audits)+len(proof.samlUses) != 0 || proof.samlRequest.ConsumedAt != nil {
			t.Fatal("failed SAML receipt kept partial proof or history", phase, err)
		}
	}
}

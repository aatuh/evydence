package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type fixedExchangeAssessment struct{ result string }

func (p fixedExchangeAssessment) Assess(v identitydomain.ProviderVerification, _ identitydomain.SSOProvider, _ bool) identitydomain.ProviderVerification {
	v = cloneProviderVerification(v)
	v.Result = p.result
	return v
}
func (fixedExchangeAssessment) ReturnsFailure(result string) bool {
	return result == "failed" || result == "error"
}

func TestSSOExchangePolicyRequiresPassedAssessmentAndPositiveCredentialEvidence(t *testing.T) {
	for _, result := range []string{"pending", "skipped", "not_evaluated", "unknown", ""} {
		t.Run("assessment/"+result, func(t *testing.T) {
			c, f, in, _ := exchangeCommandsForTest(t)
			c.config.VerificationPolicy = fixedExchangeAssessment{result}
			v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrVerificationFailed) || v.ID == "" || session.ID != "" || secret != "" || f.generations != 0 || len(f.sessions) != 0 || len(f.verifications) != 1 || len(f.audits) != 1 {
				t.Fatal("non-passing credential assessment minted session authority", err)
			}
		})
	}
	for _, result := range []string{"pending", "skipped", "unknown", ""} {
		t.Run("credential-check/"+result, func(t *testing.T) {
			c, f, in, _ := exchangeCommandsForTest(t)
			f.result.Checks[0].Result = result
			v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
			if !errors.Is(err, ErrVerificationFailed) || v.ID == "" || session.ID != "" || secret != "" || f.generations != 0 || len(f.sessions) != 0 || len(f.verifications) != 1 || len(f.audits) != 1 {
				t.Fatal("unverified credential check minted session authority", err)
			}
		})
	}
	c, f, in, _ := exchangeCommandsForTest(t)
	f.result.Checks = nil
	if _, session, secret, err := c.ExchangeSSOCredential(t.Context(), in); !errors.Is(err, ErrVerificationFailed) || session.ID != "" || secret != "" || f.generations != 0 || len(f.verifications) != 1 || len(f.audits) != 1 {
		t.Fatal("missing cryptographic check evidence minted a session", err)
	}
}

func TestSSOExchangePolicyRejectsUnboundLinkBeforeUserReadsEvenWithPassingAssessment(t *testing.T) {
	for _, edit := range []func(*identitydomain.UserIdentityLink){
		func(l *identitydomain.UserIdentityLink) { l.TenantID = "foreign" },
		func(l *identitydomain.UserIdentityLink) { l.ProviderID = "foreign" },
		func(l *identitydomain.UserIdentityLink) { l.Subject = "foreign" },
		func(l *identitydomain.UserIdentityLink) { l.Verified = false },
	} {
		c, f, in, _ := exchangeCommandsForTest(t)
		edit(&f.link)
		c.config.VerificationPolicy = fixedExchangeAssessment{"passed"}
		v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
		if !errors.Is(err, ErrVerificationFailed) || v.ID == "" || session.ID != "" || secret != "" || f.reads != 2 || f.generations != 0 || len(f.verifications) != 1 || len(f.audits) != 1 || f.snapshot.UserLoaded {
			t.Fatal("permissive assessment bypassed the linked-identity boundary before user reads", err)
		}
	}
}

type cancelAfterExchangeCommit struct {
	base   SSOExchangeTransactions
	cancel context.CancelFunc
}

func (r cancelAfterExchangeCommit) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, SSOExchangeTransaction) error) error {
	if err := r.base.ExecuteSSOExchange(ctx, fn); err != nil {
		return err
	}
	r.cancel()
	return nil
}

func TestSSOExchangePolicyWithholdsSuccessAndDenialResultsAfterCommitCancellation(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		c, f, in, _ := exchangeCommandsForTest(t)
		if !accepted {
			f.result.Checks[0].Result = "failed"
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c.config.Transactions = cancelAfterExchangeCommit{f, cancel}
		v, session, secret, err := c.ExchangeSSOCredential(ctx, in)
		if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, identitydomain.ProviderVerification{}) || !reflect.DeepEqual(session, identitydomain.SSOSession{}) || secret != "" {
			t.Error("post-commit cancellation disclosed an exchange result or secret", err)
		}
		if len(f.verifications) != 1 || accepted && (len(f.sessions) != 1 || len(f.audits) != 2) || !accepted && (len(f.sessions) != 0 || len(f.audits) != 1) {
			t.Fatal("cancellation misreported already committed exchange effects")
		}
	}
}

type expiringExchangeTransactions struct {
	base    SSOExchangeTransactions
	advance func()
}

func (r expiringExchangeTransactions) ExecuteSSOExchange(ctx context.Context, fn func(context.Context, SSOExchangeTransaction) error) error {
	return r.base.ExecuteSSOExchange(ctx, func(ctx context.Context, tx SSOExchangeTransaction) error {
		return fn(ctx, expiringExchangeTransaction{tx, r.advance})
	})
}

type expiringExchangeTransaction struct {
	SSOExchangeTransaction
	advance func()
}

func (t expiringExchangeTransaction) ValidateSSOExchangeState(ctx context.Context, s SSOExchangeSnapshot) error {
	err := t.SSOExchangeTransaction.ValidateSSOExchangeState(ctx, s)
	t.advance()
	return err
}

func TestSSOExchangePolicyRejectsSessionExpiryWhileWaitingForSnapshotLocks(t *testing.T) {
	c, f, in, now := exchangeCommandsForTest(t)
	in.ExpiresAt = now.Add(time.Second)
	at := now
	c.config.Clock = application.ClockFunc(func() time.Time { return at })
	c.config.Transactions = expiringExchangeTransactions{f, func() { at = in.ExpiresAt }}
	v, session, secret, err := c.ExchangeSSOCredential(t.Context(), in)
	if !errors.Is(err, ErrValidation) || v.ID != "" || session.ID != "" || secret != "" || len(f.verifications)+len(f.sessions)+len(f.audits) != 0 {
		t.Fatal("expired requested session was committed or exposed after a storage wait", err)
	}
}

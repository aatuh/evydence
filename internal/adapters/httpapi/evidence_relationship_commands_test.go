package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type evidenceRelationshipHTTPFake struct {
	guards, calls                         int
	guardErr, err                         error
	id, replacement, reason, kind, target string
	in                                    evidenceapp.RecordLifecycleInput
}

func TestEvidenceRelationshipStrictPreflightBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, tc := range relationshipHTTPRequests {
			t.Run(fmt.Sprintf("%t/%s", native, tc.name), func(t *testing.T) {
				base, secret := testServer(t)
				s := base
				f := &evidenceRelationshipHTTPFake{}
				if native {
					var err error
					s, err = NewServerWithOptions(base.ledger, ServerOptions{EvidenceRelationshipCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
					if err != nil {
						t.Fatal(err)
					}
				}
				bad := []string{"", " ", "null", "[]", "{}", "{", tc.body + " {}", string([]byte{0xff}), strings.TrimSuffix(tc.body, "}") + `,"unknown":1}`, strings.TrimSuffix(tc.body, "}") + `,"reason":null}`}
				switch tc.name {
				case "supersede":
					bad = append(bad, `{"replacement_evidence_id":"original","reason":"review"}`, `{"replacement_evidence_id":null,"reason":"review"}`, `{"replacement_evidence_id":"new","reason":"\u0000"}`)
				case "link":
					bad = append(bad, `{"target_type":"project","target_id":"p"}`, `{"target_type":"product","target_id":null}`, `{"TARGET_TYPE":"product","target_id":"p"}`, `{"target_type":"product","target_id":"`+strings.Repeat(" ", 1025)+`p"}`)
				case "lifecycle":
					bad = append(bad, `{"action":"unknown","reason":"review"}`, `{"action":"amendment","reason":"review","details":null}`, `{"action":"amendment","reason":"review","details":{"`+evidencedomain.LegacyCanonicalOriginDetailKey+`":{}}}`, `{"action":"amendment","reason":"review","details":{"value":"\u0000"}}`)
				}
				for i, body := range bad {
					postRaw(t, s, secret, tc.path, fmt.Sprintf("invalid-%d", i), []byte(body), 400)
				}
				if f.guards+f.calls != 0 {
					t.Fatal("invalid request reached focused dependency", f)
				}
			})
		}
	}
}

func TestEvidenceRelationshipCookieOriginAndBearerPrecedenceBothProfiles(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, tc := range relationshipHTTPRequests {
			t.Run(fmt.Sprintf("%t/%s", native, tc.name), func(t *testing.T) {
				base, secret := testServer(t)
				s := base
				f := &evidenceRelationshipHTTPFake{}
				ids := make([]string, 2)
				for i := range ids {
					raw := postRaw(t, base, secret, "/v1/evidence", fmt.Sprintf("seed-%d", i), []byte(`{"type":"manual","title":"Evidence","payload_hash":"sha256:`+strings.Repeat("a", 64)+`"}`), 201)
					var value struct {
						Data struct {
							ID string `json:"id"`
						} `json:"data"`
					}
					if err := json.Unmarshal([]byte(raw), &value); err != nil || value.Data.ID == "" {
						t.Fatal(raw, err)
					}
					ids[i] = value.Data.ID
				}
				product := postRaw(t, base, secret, "/v1/products", "seed-product", []byte(`{"name":"Target","slug":"target"}`), 201)
				var value struct {
					Data struct {
						ID string `json:"id"`
					} `json:"data"`
				}
				if err := json.Unmarshal([]byte(product), &value); err != nil || value.Data.ID == "" {
					t.Fatal(product, err)
				}
				if native {
					var err error
					s, err = NewServerWithOptions(base.ledger, ServerOptions{EvidenceRelationshipCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
					if err != nil {
						t.Fatal(err)
					}
					s.ledger, s.evidenceIngestion, s.localEvidenceRelationships = nil, nil, nil
				}
				path := strings.Replace(tc.path, "original", ids[0], 1)
				body := strings.ReplaceAll(strings.ReplaceAll(tc.body, `" replacement "`, fmt.Sprintf("%q", ids[1])), `" target "`, fmt.Sprintf("%q", value.Data.ID))
				for _, origin := range []struct {
					origin string
					bearer bool
					want   int
				}{{"", false, 403}, {"https://attacker.example", false, 403}, {"http://api.example", false, 403}, {"https://api.example", false, 201}, {"https://attacker.example", true, 201}} {
					r := httptest.NewRequest("POST", "https://api.example"+path, strings.NewReader(body))
					r.AddCookie(&http.Cookie{Name: ssoSessionCookieName, Value: secret})
					r.Header.Set("Origin", origin.origin)
					r.Header.Set("Idempotency-Key", "cookie-action")
					if origin.bearer {
						r.Header.Set("Authorization", "Bearer "+secret)
					}
					w := httptest.NewRecorder()
					before := f.guards + f.calls
					s.Handler().ServeHTTP(w, r)
					if w.Code != origin.want || w.Header().Get("Set-Cookie") != "" || origin.want == 403 && before != f.guards+f.calls {
						t.Fatal("unsafe relationship cookie mutation", w.Code, w.Body.String())
					}
				}
			})
		}
	}
}

func (f *evidenceRelationshipHTTPFake) AuthorizeSupersedeEvidence(_ context.Context, _ identitydomain.Actor, id, replacement, reason string) error {
	f.guards++
	f.id, f.replacement, f.reason = id, replacement, reason
	return f.guardErr
}
func (f *evidenceRelationshipHTTPFake) AuthorizeLinkEvidence(_ context.Context, _ identitydomain.Actor, id, kind, target string) error {
	f.guards++
	f.id, f.kind, f.target = id, kind, target
	return f.guardErr
}
func (f *evidenceRelationshipHTTPFake) AuthorizeLifecycleEvent(_ context.Context, _ identitydomain.Actor, id string, in evidenceapp.RecordLifecycleInput) error {
	f.guards++
	f.id, f.in = id, in
	return f.guardErr
}
func (f *evidenceRelationshipHTTPFake) SupersedeEvidence(_ context.Context, a identitydomain.Actor, id, replacement, reason string) (evidencedomain.EvidenceItem, error) {
	f.calls++
	return evidencedomain.EvidenceItem{ID: id, TenantID: a.TenantID, SupersededBy: replacement}, f.err
}
func (f *evidenceRelationshipHTTPFake) LinkEvidence(_ context.Context, a identitydomain.Actor, id, kind, target string) (evidencedomain.EvidenceItem, error) {
	f.calls++
	return evidencedomain.EvidenceItem{ID: id, TenantID: a.TenantID, RelatedEvidenceRefs: []evidencedomain.EvidenceRef{{Type: kind, ID: target, Relationship: "linked_to"}}}, f.err
}
func (f *evidenceRelationshipHTTPFake) RecordLifecycleEvent(_ context.Context, a identitydomain.Actor, id string, in evidenceapp.RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error) {
	f.calls++
	action, _ := evidencedomain.ParseEvidenceLifecycleState(in.Action)
	return evidencedomain.EvidenceLifecycleEvent{ID: "event-focused", TenantID: a.TenantID, EvidenceID: id, Action: action, Reason: in.Reason, Details: in.Details, ReplacementID: in.ReplacementID}, f.err
}

var relationshipHTTPRequests = []struct{ name, path, body string }{
	{"supersede", "/v1/evidence/original/supersede", `{"replacement_evidence_id":" replacement ","reason":" reviewed "}`},
	{"link", "/v1/evidence/original/link", `{"target_type":" product ","target_id":" target "}`},
	{"lifecycle", "/v1/evidence/original/lifecycle-events", `{"action":" amendment ","reason":" reviewed ","replacement_id":" replacement ","details":{"sequence":9007199254740993}}`},
}

func TestEvidenceRelationshipsRequireDurableExecutionAndReauthorizeReplay(t *testing.T) {
	for _, tc := range relationshipHTTPRequests {
		t.Run(tc.name, func(t *testing.T) {
			base, secret := testServer(t)
			f := &evidenceRelationshipHTTPFake{}
			if s, err := NewServerWithOptions(base.ledger, ServerOptions{EvidenceRelationshipCommands: f}); err == nil || s != nil {
				t.Fatal("relationships accepted aggregate replay")
			}
			s, err := NewServerWithOptions(base.ledger, ServerOptions{EvidenceRelationshipCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
			s.ledger, s.evidenceIngestion, s.localEvidenceRelationships = nil, nil, nil
			one := postRaw(t, s, secret, tc.path, "relationship", []byte(tc.body), 201)
			assertTrustHTTPReplay(t, one, postRaw(t, s, secret, tc.path, "relationship", []byte(tc.body), 201))
			if f.id != "original" || tc.name == "supersede" && (f.replacement != "replacement" || f.reason != "reviewed") || tc.name == "link" && (f.kind != "product" || f.target != "target") || tc.name == "lifecycle" && (f.in.Action != "amendment" || f.in.Reason != "reviewed" || f.in.ReplacementID != "replacement" || f.in.Details["sequence"] != json.Number("9007199254740993")) {
				t.Fatal("normalized DTO or number changed", f)
			}
			postRaw(t, s, secret, tc.path, "relationship", append([]byte(tc.body), ' '), 409)
			f.guardErr = application.ErrForbidden
			postRaw(t, s, secret, tc.path, "relationship", []byte(tc.body), 403)
			if f.calls != 1 || f.guards != 4 {
				t.Fatal("replay repeated business work or omitted current authorization", f)
			}
		})
	}
}

func TestEvidenceRelationshipsMapErrorsWithoutLeakingResults(t *testing.T) {
	for _, tc := range relationshipHTTPRequests {
		t.Run(tc.name, func(t *testing.T) {
			base, secret := testServer(t)
			f := &evidenceRelationshipHTTPFake{}
			s, err := NewServerWithOptions(base.ledger, ServerOptions{EvidenceRelationshipCommands: f, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, base, secret)})
			if err != nil {
				t.Fatal(err)
			}
			for i, failure := range []struct {
				err    error
				status int
			}{{evidenceapp.ErrValidation, 400}, {evidenceapp.ErrNotFound, 404}, {evidenceapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private SQL secret"), 500}} {
				f.err = failure.err
				body := postRaw(t, s, secret, tc.path, fmt.Sprintf("failure-%d", i), []byte(tc.body), failure.status)
				if strings.Contains(body, "private SQL") || strings.Contains(body, "event-focused") {
					t.Fatal("error leaked result or internals", body)
				}
			}
		})
	}
}

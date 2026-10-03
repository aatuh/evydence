package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sort"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type QuestionnaireDraftCommands interface {
	AuthorizeCreateQuestionnaireDraft(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireDraftInput) error
	CreateQuestionnaireDraft(context.Context, identitydomain.Actor, packageapp.CreateQuestionnaireDraftInput) (packagedomain.QuestionnaireDraft, error)
}

func decodeQuestionnaireDraftRequest(body []byte) (packageapp.CreateQuestionnaireDraftInput, error) {
	var req struct {
		TemplateID string `json:"template_id"`
		ProductID  string `json:"product_id"`
		ReleaseID  string `json:"release_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateQuestionnaireDraftInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "template_id", "product_id", "release_id"); err != nil {
		return packageapp.CreateQuestionnaireDraftInput{}, err
	}
	in, err := packageapp.NormalizeQuestionnaireDraftInput(packageapp.CreateQuestionnaireDraftInput{TemplateID: req.TemplateID, ProductID: req.ProductID, ReleaseID: req.ReleaseID})
	return in, mapCustomerPackageAccessError(err)
}

func (s *Server) createDurableQuestionnaireDraft(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateQuestionnaireDraftInput
	s.createDurableWithFingerprint(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeQuestionnaireDraftRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.questionnaireDraftCommands.AuthorizeCreateQuestionnaireDraft(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.questionnaireDraftCommands.CreateQuestionnaireDraft(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		encoded, err := packageapp.EncodeQuestionnaireDraft(v)
		return http.StatusCreated, json.RawMessage(encoded), err
	}, nil, questionnaireDraftReplayFingerprint)
}

// A draft may contain text that needs broader authority than its root. Bind
// replay to the original permission set, not just current access to that root.
// Only the resulting request hash is persisted; grants are not response data.
func questionnaireDraftReplayFingerprint(a domain.Actor, body []byte) ([]byte, error) {
	grants := []string{}
	if a.UserID != "" && a.KeyID == "" && a.CollectorID == "" {
		for _, g := range a.ResourceGrants {
			encoded, err := json.Marshal(map[string]any{"resource_type": g.ResourceType, "resource_id": g.ResourceID, "scopes": draftPermissionSet(g.Scopes)})
			if err != nil {
				return nil, err
			}
			grants = append(grants, string(encoded))
		}
	}
	return json.Marshal(struct {
		Version        string `json:"version"`
		Scopes, Grants []string
		Body           []byte
	}{Version: "questionnaire-draft-permissions-v1", Scopes: draftPermissionSet(a.Scopes), Grants: draftPermissionSet(grants), Body: body})
}

func draftPermissionSet(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return slices.Compact(out)
}

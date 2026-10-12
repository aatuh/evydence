package query

import (
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
)

func NewQuestionnaireDraftAuthorizer() application.Authorizer {
	return packageCommandAuthorizer{action: authz.ActionQuestionnaireDraftsCreate}
}

func NewAnswerLibraryAuthorizer() application.Authorizer {
	return packageCommandAuthorizer{action: authz.ActionAnswerLibraryEntriesCreate}
}

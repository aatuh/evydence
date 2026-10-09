package app

import (
	"encoding/json"
	"reflect"
	"sort"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// CompareSSOExchangeSnapshot compares persisted records with the preflight
// snapshot used by the identity application service. Repositories call this
// after acquiring transaction-scoped locks for the supplied records/ranges.
func CompareSSOExchangeSnapshot(
	snapshot SSOExchangeSnapshot,
	provider domain.SSOProvider,
	link domain.UserIdentityLink,
	linkFound bool,
	user domain.HumanUser,
	userFound bool,
	bindings []domain.RoleBinding,
) error {
	if err := ValidateSSOExchangeSnapshot(snapshot); err != nil {
		return err
	}
	if !sameSSOProvider(snapshot.Provider, provider) || snapshot.IdentityLinkFound != linkFound {
		return ErrConflict
	}
	if linkFound && !sameUserIdentityLink(snapshot.IdentityLink, link) {
		return ErrConflict
	}
	if snapshot.UserLoaded {
		if snapshot.UserFound != userFound {
			return ErrConflict
		}
		if userFound && !sameHumanUser(snapshot.User, user) {
			return ErrConflict
		}
	}
	if snapshot.UserGrantsLoaded && !sameResourceGrantSet(snapshot.UserGrants, grantsFromRoleBindings(snapshot.Provider.TenantID, snapshot.User.ID, bindings)) {
		return ErrConflict
	}
	return nil
}

// ValidateSSOExchangeSnapshot rejects malformed presence combinations before a
// repository acquires locks or issues tenant-scoped reads.
func ValidateSSOExchangeSnapshot(snapshot SSOExchangeSnapshot) error {
	if snapshot.Provider.ID == "" || snapshot.Provider.TenantID == "" || snapshot.Subject == "" {
		return ErrValidation
	}
	if snapshot.IdentityLinkFound {
		if snapshot.IdentityLink.ID == "" || snapshot.IdentityLink.TenantID != snapshot.Provider.TenantID || snapshot.IdentityLink.ProviderID != snapshot.Provider.ID || snapshot.IdentityLink.Subject != snapshot.Subject || snapshot.IdentityLink.UserID == "" {
			return ErrValidation
		}
	} else if snapshot.UserLoaded || snapshot.UserFound || snapshot.UserGrantsLoaded {
		return ErrValidation
	}
	if snapshot.UserFound && !snapshot.UserLoaded {
		return ErrValidation
	}
	if snapshot.UserLoaded && snapshot.UserFound {
		if snapshot.User.ID == "" || snapshot.User.ID != snapshot.IdentityLink.UserID || snapshot.User.TenantID != snapshot.Provider.TenantID {
			return ErrValidation
		}
	}
	if snapshot.UserGrantsLoaded && (!snapshot.UserLoaded || !snapshot.UserFound) {
		return ErrValidation
	}
	return nil
}

func sameSSOProvider(left, right domain.SSOProvider) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.Name == right.Name &&
		left.Type == right.Type &&
		left.Issuer == right.Issuer &&
		left.ClientID == right.ClientID &&
		left.GroupsClaim == right.GroupsClaim &&
		reflect.DeepEqual(left.RoleMapping, right.RoleMapping) &&
		reflect.DeepEqual(left.JWKS, right.JWKS) &&
		reflect.DeepEqual(left.SAMLSigningCertificates, right.SAMLSigningCertificates) &&
		sameOptionalTime(left.TrustMaterialUpdatedAt, right.TrustMaterialUpdatedAt) &&
		left.Status == right.Status &&
		left.SchemaVersion == right.SchemaVersion &&
		samePersistedTime(left.CreatedAt, right.CreatedAt)
}

func sameUserIdentityLink(left, right domain.UserIdentityLink) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.UserID == right.UserID &&
		left.ProviderID == right.ProviderID &&
		left.Subject == right.Subject &&
		left.Email == right.Email &&
		left.Verified == right.Verified &&
		left.SchemaVersion == right.SchemaVersion &&
		samePersistedTime(left.CreatedAt, right.CreatedAt)
}

func sameHumanUser(left, right domain.HumanUser) bool {
	return left.ID == right.ID &&
		left.TenantID == right.TenantID &&
		left.OrganizationID == right.OrganizationID &&
		left.Email == right.Email &&
		left.DisplayName == right.DisplayName &&
		left.Status == right.Status &&
		sameOptionalTime(left.DeactivatedAt, right.DeactivatedAt) &&
		left.SchemaVersion == right.SchemaVersion &&
		samePersistedTime(left.CreatedAt, right.CreatedAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return samePersistedTime(*left, *right)
}

func samePersistedTime(left, right time.Time) bool {
	// PostgreSQL timestamps have microsecond precision. In-memory commands can
	// retain finer Go clock precision until the process reloads persisted state.
	return left.Truncate(time.Microsecond).Equal(right.Truncate(time.Microsecond))
}

func grantsFromRoleBindings(tenantID, userID string, bindings []domain.RoleBinding) []domain.ResourceGrant {
	grants := make([]domain.ResourceGrant, 0, len(bindings))
	for _, binding := range bindings {
		if binding.TenantID != tenantID || binding.SubjectType != "user" || binding.SubjectID != userID {
			continue
		}
		scopes := scopesForRole(binding.Role)
		if len(scopes) == 0 {
			continue
		}
		grants = append(grants, domain.ResourceGrant{
			Role:         binding.Role,
			ResourceType: binding.ResourceType,
			ResourceID:   binding.ResourceID,
			Scopes:       scopes,
		})
	}
	return grants
}

func sameResourceGrantSet(left, right []domain.ResourceGrant) bool {
	return reflect.DeepEqual(resourceGrantSet(left), resourceGrantSet(right))
}

func resourceGrantSet(values []domain.ResourceGrant) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value.Scopes = append([]string(nil), value.Scopes...)
		sort.Strings(value.Scopes)
		encoded, _ := json.Marshal(value)
		set[string(encoded)] = struct{}{}
	}
	return set
}

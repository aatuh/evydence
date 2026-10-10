package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/platform/redaction"
)

// IdempotencyState is the durable lifecycle for one tenant-and-actor scoped
// request key. Pending records have an owner lease; only a matching owner can
// transition them to a terminal state.
type IdempotencyState string

const (
	IdempotencyPending   IdempotencyState = "pending"
	IdempotencyCompleted IdempotencyState = "completed"
	IdempotencyFailed    IdempotencyState = "failed"

	defaultIdempotencyLease     = 2 * time.Minute
	defaultIdempotencyRetention = 24 * time.Hour
)

type IdempotencyRecord struct {
	State          IdempotencyState `json:"state"`
	RequestHash    string           `json:"request_hash"`
	OwnerTokenHash string           `json:"owner_token_hash,omitempty"`
	Status         int              `json:"status"`
	Response       any              `json:"response,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	LeaseExpiresAt *time.Time       `json:"lease_expires_at,omitempty"`
	CompletedAt    *time.Time       `json:"completed_at,omitempty"`
	FailedAt       *time.Time       `json:"failed_at,omitempty"`
	ExpiresAt      time.Time        `json:"expires_at"`
}

type IdempotencyRecordKey struct {
	TenantID       string
	ActorID        string
	Method         string
	Path           string
	IdempotencyKey string
}

// IdempotencyReservation contains only digests and the hash of a random
// server-generated owner token. Raw request bytes and raw owner tokens are
// deliberately never persisted or logged.
type IdempotencyReservation struct {
	Key            IdempotencyRecordKey
	RequestHash    string
	OwnerTokenHash string
	Now            time.Time
	LeaseExpiresAt time.Time
	ExpiresAt      time.Time
}

type IdempotencyReservationOutcome string

const (
	IdempotencyReservationAcquired  IdempotencyReservationOutcome = "acquired"
	IdempotencyReservationRecovered IdempotencyReservationOutcome = "recovered"
	IdempotencyReservationReplay    IdempotencyReservationOutcome = "replay"
	IdempotencyReservationPending   IdempotencyReservationOutcome = "pending"
	IdempotencyReservationFailure   IdempotencyReservationOutcome = "failed"
)

type IdempotencyReservationResult struct {
	Outcome IdempotencyReservationOutcome
	Record  IdempotencyRecord
}

func newIdempotencyReservation(key IdempotencyRecordKey, requestHash string, now time.Time) (IdempotencyReservation, error) {
	now = now.UTC()
	if err := validateIdempotencyKey(key); err != nil || strings.TrimSpace(requestHash) == "" || now.IsZero() {
		return IdempotencyReservation{}, ErrValidation
	}
	ownerToken := randomToken(32)
	return IdempotencyReservation{
		Key:            key,
		RequestHash:    requestHash,
		OwnerTokenHash: hashBytes([]byte(ownerToken)),
		Now:            now,
		LeaseExpiresAt: now.Add(defaultIdempotencyLease),
		ExpiresAt:      now.Add(defaultIdempotencyRetention),
	}, nil
}

func validateIdempotencyKey(key IdempotencyRecordKey) error {
	if strings.TrimSpace(key.TenantID) == "" || strings.TrimSpace(key.ActorID) == "" || strings.TrimSpace(key.Method) == "" || strings.TrimSpace(key.Path) == "" || strings.TrimSpace(key.IdempotencyKey) == "" {
		return ErrValidation
	}
	return nil
}

// ValidateIdempotencyKey validates the tenant-and-actor scoped key before a
// persistence adapter uses it in a state transition.
func ValidateIdempotencyKey(key IdempotencyRecordKey) error {
	return validateIdempotencyKey(key)
}

func validateIdempotencyReservation(reservation IdempotencyReservation) error {
	if err := validateIdempotencyKey(reservation.Key); err != nil || strings.TrimSpace(reservation.RequestHash) == "" || strings.TrimSpace(reservation.OwnerTokenHash) == "" || reservation.Now.IsZero() || reservation.LeaseExpiresAt.IsZero() || reservation.ExpiresAt.IsZero() || !reservation.LeaseExpiresAt.After(reservation.Now) || !reservation.ExpiresAt.After(reservation.Now) {
		return ErrValidation
	}
	return nil
}

// ValidateIdempotencyReservation validates a reservation before acquisition.
func ValidateIdempotencyReservation(reservation IdempotencyReservation) error {
	return validateIdempotencyReservation(reservation)
}

func normalizeLegacyIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	if strings.TrimSpace(record.RequestHash) == "" || record.CreatedAt.IsZero() || record.Status < 100 || record.Status > 599 {
		return IdempotencyRecord{}, ErrValidation
	}
	if record.State == "" {
		record.State = IdempotencyCompleted
	}
	if record.State != IdempotencyCompleted {
		return IdempotencyRecord{}, ErrValidation
	}
	if record.UpdatedAt.IsZero() {
		record.UpdatedAt = record.CreatedAt
	}
	if record.CompletedAt == nil {
		completedAt := record.CreatedAt
		record.CompletedAt = &completedAt
	}
	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = record.CreatedAt.Add(defaultIdempotencyRetention)
	}
	safeResponse, err := safeIdempotencyReplayResponse(record.Response)
	if err != nil {
		return IdempotencyRecord{}, err
	}
	record.Response = safeResponse
	record.OwnerTokenHash = ""
	record.LeaseExpiresAt = nil
	record.FailedAt = nil
	return record, nil
}

// NormalizeLegacyIdempotencyRecord upgrades a pre-state-machine completed
// record in memory without changing its response or request digest.
func NormalizeLegacyIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	return normalizeLegacyIdempotencyRecord(record)
}

func replayableIdempotencyRecord(record IdempotencyRecord) (IdempotencyRecord, error) {
	if record.State == "" {
		return normalizeLegacyIdempotencyRecord(record)
	}
	if record.State != IdempotencyCompleted || strings.TrimSpace(record.RequestHash) == "" || record.Status < 100 || record.Status > 599 || record.ExpiresAt.IsZero() {
		return IdempotencyRecord{}, ErrValidation
	}
	safeResponse, err := safeIdempotencyReplayResponse(record.Response)
	if err != nil {
		return IdempotencyRecord{}, err
	}
	record.Response = safeResponse
	return record, nil
}

func safeIdempotencyReplayResponse(response any) (any, error) {
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, ErrValidation
	}
	var decoded any
	// Redaction must not round valid manifest sizes/counts or other public
	// numbers when it reconstructs the JSON tree for a safe replay.
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, ErrValidation
	}
	keyMetadata, binding, publicCollectorKey := publicCollectorReplayMetadata(decoded)
	safe, changed := redaction.RemoveSensitive(decoded)
	if publicCollectorKey {
		// This narrowly projected creation DTO is public metadata, not the
		// secret-bearing api_key fields handled by the generic denylist.
		root := safe.(map[string]any)
		root["api_key"] = keyMetadata
		root["collector"].(map[string]any)["api_key_id"] = binding
		return root, nil
	}
	if keyMetadata, ok := publicAPIKeyCreationReplayMetadata(decoded); ok {
		root := safe.(map[string]any)
		root["api_key"] = keyMetadata
		return root, nil
	}
	if user, ok := publicHumanUserReplay(decoded); ok {
		return user, nil
	}
	if provider, ok := publicSSOProviderReplay(decoded); ok {
		return provider, nil
	}
	if link, ok := publicSSOIdentityLinkReplay(decoded); ok {
		return link, nil
	}
	if policy, ok := publicObjectRetentionReplay(decoded); ok {
		return policy, nil
	}
	if bundle, ok := publicSignedReleaseBundleReplay(decoded); ok {
		return bundle, nil
	}
	if signature, ok := publicArtifactSignatureReplay(decoded); ok {
		return signature, nil
	}
	if vex, ok := publicVEXAuthorReplay(decoded); ok {
		return vex, nil
	}
	if !changed {
		return response, nil
	}
	return safe, nil
}

func pendingIdempotencyRecord(reservation IdempotencyReservation) IdempotencyRecord {
	leaseExpiresAt := reservation.LeaseExpiresAt
	return IdempotencyRecord{
		State:          IdempotencyPending,
		RequestHash:    reservation.RequestHash,
		OwnerTokenHash: reservation.OwnerTokenHash,
		CreatedAt:      reservation.Now,
		UpdatedAt:      reservation.Now,
		LeaseExpiresAt: &leaseExpiresAt,
		ExpiresAt:      reservation.ExpiresAt,
	}
}

// PendingIdempotencyRecord returns the first durable state for a reservation.
func PendingIdempotencyRecord(reservation IdempotencyReservation) IdempotencyRecord {
	return pendingIdempotencyRecord(reservation)
}

func recoveredPendingIdempotencyRecord(previous IdempotencyRecord, reservation IdempotencyReservation) IdempotencyRecord {
	recovered := pendingIdempotencyRecord(reservation)
	recovered.CreatedAt = previous.CreatedAt
	recovered.ExpiresAt = previous.ExpiresAt
	return recovered
}

// RecoveredPendingIdempotencyRecord preserves original retention while giving
// an expired lease a new owner.
func RecoveredPendingIdempotencyRecord(previous IdempotencyRecord, reservation IdempotencyReservation) IdempotencyRecord {
	return recoveredPendingIdempotencyRecord(previous, reservation)
}

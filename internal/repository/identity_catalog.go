package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"cpa-usage-keeper/internal/entities"
	"gorm.io/gorm"
)

// CatalogRepository persists source-scoped catalog snapshots and mappings from
// external identities to source users.
type CatalogRepository struct{ db *gorm.DB }

// SourceCatalogSnapshot is a complete view of one source system at SyncedAt.
type SourceCatalogSnapshot struct {
	SourceSystem string
	Users        []SourceUserInput
	Keys         []SourceAPIKeyInput
	SyncedAt     time.Time
}

type SourceUserInput struct {
	SourceUserRef string
	Email         string
	DisplayName   string
	Active        bool
}

type SourceAPIKeyInput struct {
	SourceKeyRef  string
	SourceUserRef string
	UsageGroupRef string
	DisplayName   string
	Active        bool
}

func NewCatalogRepository(db *gorm.DB) *CatalogRepository { return &CatalogRepository{db: db} }

// ApplySourceSnapshot atomically replaces the catalog view for one source.
// Validation occurs before a transaction mutates any source records.
func (r *CatalogRepository) ApplySourceSnapshot(ctx context.Context, snapshot SourceCatalogSnapshot) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("catalog database is nil")
	}
	validated, err := validateSourceCatalogSnapshot(snapshot)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return applyValidatedSourceSnapshot(tx, validated)
	})
}

func (r *CatalogRepository) UpsertExternalIdentity(ctx context.Context, issuer, subject, email, displayName string) (entities.ExternalIdentity, error) {
	if r == nil || r.db == nil {
		return entities.ExternalIdentity{}, fmt.Errorf("catalog database is nil")
	}
	issuer, subject = strings.TrimSpace(issuer), strings.TrimSpace(subject)
	if issuer == "" || subject == "" {
		return entities.ExternalIdentity{}, fmt.Errorf("issuer and subject are required")
	}
	email, displayName = strings.TrimSpace(email), strings.TrimSpace(displayName)
	var identity entities.ExternalIdentity
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Where("issuer = ? AND subject = ?", issuer, subject).First(&identity).Error
		if err == nil {
			return tx.Model(&identity).Updates(map[string]any{"email": email, "normalized_email": normalizeEmail(email), "display_name": displayName}).Error
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("find external identity: %w", err)
		}
		id, err := newOpaqueCatalogID()
		if err != nil {
			return err
		}
		identity = entities.ExternalIdentity{ID: id, Issuer: issuer, Subject: subject, Email: email, NormalizedEmail: normalizeEmail(email), DisplayName: displayName}
		if err := tx.Create(&identity).Error; err != nil {
			return fmt.Errorf("create external identity: %w", err)
		}
		return nil
	})
	return identity, err
}

func (r *CatalogRepository) FindIdentityLink(ctx context.Context, externalIdentityID, sourceSystem string) (entities.IdentitySourceLink, bool, error) {
	if r == nil || r.db == nil {
		return entities.IdentitySourceLink{}, false, fmt.Errorf("catalog database is nil")
	}
	var link entities.IdentitySourceLink
	err := r.db.WithContext(ctx).Where("external_identity_id = ? AND source_system = ?", strings.TrimSpace(externalIdentityID), strings.TrimSpace(sourceSystem)).First(&link).Error
	if err == gorm.ErrRecordNotFound {
		return entities.IdentitySourceLink{}, false, nil
	}
	if err != nil {
		return entities.IdentitySourceLink{}, false, fmt.Errorf("find identity source link: %w", err)
	}
	return link, true, nil
}

func (r *CatalogRepository) FindActiveSourceUsersByEmail(ctx context.Context, sourceSystem, email string) ([]entities.SourceUser, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("catalog database is nil")
	}
	var users []entities.SourceUser
	if err := r.db.WithContext(ctx).Where("source_system = ? AND normalized_email = ? AND active = ?", strings.TrimSpace(sourceSystem), normalizeEmail(email), true).Order("id ASC").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("find active source users by email: %w", err)
	}
	return users, nil
}

// ReplaceIdentityLink creates or replaces the sole link for an identity/source
// pair. The target user is verified to belong to that source system.
func (r *CatalogRepository) ReplaceIdentityLink(ctx context.Context, externalIdentityID, sourceSystem, sourceUserID, matchMethod string, confirmed bool) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("catalog database is nil")
	}
	externalIdentityID, sourceSystem = strings.TrimSpace(externalIdentityID), strings.TrimSpace(sourceSystem)
	sourceUserID, matchMethod = strings.TrimSpace(sourceUserID), strings.TrimSpace(matchMethod)
	if externalIdentityID == "" || sourceSystem == "" || sourceUserID == "" || matchMethod == "" {
		return fmt.Errorf("identity link fields are required")
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&entities.ExternalIdentity{}).Where("id = ?", externalIdentityID).Count(&count).Error; err != nil {
			return fmt.Errorf("find external identity for link: %w", err)
		}
		if count != 1 {
			return gorm.ErrRecordNotFound
		}
		if err := tx.Model(&entities.SourceUser{}).Where("id = ? AND source_system = ?", sourceUserID, sourceSystem).Count(&count).Error; err != nil {
			return fmt.Errorf("find source user for link: %w", err)
		}
		if count != 1 {
			return gorm.ErrRecordNotFound
		}
		var link entities.IdentitySourceLink
		err := tx.Where("external_identity_id = ? AND source_system = ?", externalIdentityID, sourceSystem).First(&link).Error
		if err == nil {
			return tx.Model(&link).Updates(map[string]any{"source_user_id": sourceUserID, "match_method": matchMethod, "confirmed": confirmed}).Error
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("find identity source link for replacement: %w", err)
		}
		id, err := newOpaqueCatalogID()
		if err != nil {
			return err
		}
		return tx.Create(&entities.IdentitySourceLink{ID: id, ExternalIdentityID: externalIdentityID, SourceSystem: sourceSystem, SourceUserID: sourceUserID, MatchMethod: matchMethod, Confirmed: confirmed}).Error
	})
}

func (r *CatalogRepository) ListActiveSourceUsers(ctx context.Context, sourceSystem string) ([]entities.SourceUser, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("catalog database is nil")
	}
	var users []entities.SourceUser
	if err := r.db.WithContext(ctx).Where("source_system = ? AND active = ?", strings.TrimSpace(sourceSystem), true).Order("source_user_ref ASC, id ASC").Find(&users).Error; err != nil {
		return nil, fmt.Errorf("list active source users: %w", err)
	}
	return users, nil
}

func (r *CatalogRepository) ListActiveSourceAPIKeys(ctx context.Context, sourceSystem string) ([]entities.SourceAPIKey, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("catalog database is nil")
	}
	var keys []entities.SourceAPIKey
	if err := r.db.WithContext(ctx).Where("source_system = ? AND active = ?", strings.TrimSpace(sourceSystem), true).Order("source_key_ref ASC, id ASC").Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("list active source API keys: %w", err)
	}
	return keys, nil
}

func (r *CatalogRepository) FindActiveSourceAPIKey(ctx context.Context, sourceSystem, sourceKeyRef string) (entities.SourceAPIKey, error) {
	if r == nil || r.db == nil {
		return entities.SourceAPIKey{}, fmt.Errorf("catalog database is nil")
	}
	var key entities.SourceAPIKey
	if err := r.db.WithContext(ctx).Where("source_system = ? AND source_key_ref = ? AND active = ?", strings.TrimSpace(sourceSystem), strings.TrimSpace(sourceKeyRef), true).First(&key).Error; err != nil {
		return entities.SourceAPIKey{}, err
	}
	return key, nil
}

func (r *CatalogRepository) ListIdentityMappings(ctx context.Context, sourceSystem string) ([]entities.IdentitySourceLink, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("catalog database is nil")
	}
	var links []entities.IdentitySourceLink
	if err := r.db.WithContext(ctx).Where("source_system = ?", strings.TrimSpace(sourceSystem)).Order("external_identity_id ASC, id ASC").Find(&links).Error; err != nil {
		return nil, fmt.Errorf("list identity mappings: %w", err)
	}
	return links, nil
}

func (r *CatalogRepository) CatalogSyncState(ctx context.Context, sourceSystem string) (entities.SourceCatalogSyncState, error) {
	if r == nil || r.db == nil {
		return entities.SourceCatalogSyncState{}, fmt.Errorf("catalog database is nil")
	}
	var state entities.SourceCatalogSyncState
	if err := r.db.WithContext(ctx).Where("source_system = ?", strings.TrimSpace(sourceSystem)).First(&state).Error; err != nil {
		return entities.SourceCatalogSyncState{}, err
	}
	return state, nil
}

type validatedSourceCatalogSnapshot struct {
	SourceSystem string
	Users        []SourceUserInput
	Keys         []SourceAPIKeyInput
	SyncedAt     time.Time
}

func validateSourceCatalogSnapshot(snapshot SourceCatalogSnapshot) (validatedSourceCatalogSnapshot, error) {
	validated := validatedSourceCatalogSnapshot{SourceSystem: strings.TrimSpace(snapshot.SourceSystem), SyncedAt: snapshot.SyncedAt}
	if validated.SourceSystem == "" {
		return validated, fmt.Errorf("source system is required")
	}
	if validated.SyncedAt.IsZero() {
		return validated, fmt.Errorf("snapshot sync time is required")
	}
	users := make(map[string]struct{}, len(snapshot.Users))
	for _, input := range snapshot.Users {
		input.SourceUserRef, input.Email, input.DisplayName = strings.TrimSpace(input.SourceUserRef), strings.TrimSpace(input.Email), strings.TrimSpace(input.DisplayName)
		if input.SourceUserRef == "" {
			return validated, fmt.Errorf("source user reference is required")
		}
		if _, duplicate := users[input.SourceUserRef]; duplicate {
			return validated, fmt.Errorf("duplicate source user reference")
		}
		users[input.SourceUserRef] = struct{}{}
		validated.Users = append(validated.Users, input)
	}
	keys := make(map[string]struct{}, len(snapshot.Keys))
	for _, input := range snapshot.Keys {
		input.SourceUserRef, input.DisplayName = strings.TrimSpace(input.SourceUserRef), strings.TrimSpace(input.DisplayName)
		var err error
		input.SourceKeyRef, err = safeSourceReference(input.SourceKeyRef)
		if err != nil {
			return validated, fmt.Errorf("source API key reference is unsafe")
		}
		input.UsageGroupRef, err = safeSourceReference(input.UsageGroupRef)
		if err != nil {
			return validated, fmt.Errorf("source API key usage group reference is unsafe")
		}
		if input.SourceUserRef == "" {
			return validated, fmt.Errorf("source API key fields are required")
		}
		if _, ownerExists := users[input.SourceUserRef]; !ownerExists {
			return validated, fmt.Errorf("source API key owner is missing from snapshot")
		}
		if _, duplicate := keys[input.SourceKeyRef]; duplicate {
			return validated, fmt.Errorf("duplicate source API key reference")
		}
		keys[input.SourceKeyRef] = struct{}{}
		validated.Keys = append(validated.Keys, input)
	}
	return validated, nil
}

func applyValidatedSourceSnapshot(tx *gorm.DB, snapshot validatedSourceCatalogSnapshot) error {
	userIDs := make(map[string]string, len(snapshot.Users))
	for _, input := range snapshot.Users {
		var user entities.SourceUser
		err := tx.Where("source_system = ? AND source_user_ref = ?", snapshot.SourceSystem, input.SourceUserRef).First(&user).Error
		if err == nil {
			if err := tx.Model(&user).Updates(map[string]any{"email": input.Email, "normalized_email": normalizeEmail(input.Email), "display_name": input.DisplayName, "active": input.Active}).Error; err != nil {
				return fmt.Errorf("update source user: %w", err)
			}
			userIDs[input.SourceUserRef] = user.ID
			continue
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("find source user: %w", err)
		}
		id, err := newOpaqueCatalogID()
		if err != nil {
			return err
		}
		user = entities.SourceUser{ID: id, SourceSystem: snapshot.SourceSystem, SourceUserRef: input.SourceUserRef, Email: input.Email, NormalizedEmail: normalizeEmail(input.Email), DisplayName: input.DisplayName, Active: input.Active}
		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("create source user: %w", err)
		}
		userIDs[input.SourceUserRef] = id
	}
	if err := markAbsentSourceUsersInactive(tx, snapshot.SourceSystem, snapshot.Users); err != nil {
		return err
	}
	for _, input := range snapshot.Keys {
		var key entities.SourceAPIKey
		err := tx.Where("source_system = ? AND source_key_ref = ?", snapshot.SourceSystem, input.SourceKeyRef).First(&key).Error
		if err == nil {
			if err := tx.Model(&key).Updates(map[string]any{"source_user_id": userIDs[input.SourceUserRef], "usage_group_ref": input.UsageGroupRef, "display_name": input.DisplayName, "active": input.Active}).Error; err != nil {
				return fmt.Errorf("update source API key: %w", err)
			}
			continue
		}
		if err != gorm.ErrRecordNotFound {
			return fmt.Errorf("find source API key: %w", err)
		}
		id, err := newOpaqueCatalogID()
		if err != nil {
			return err
		}
		key = entities.SourceAPIKey{ID: id, SourceSystem: snapshot.SourceSystem, SourceKeyRef: input.SourceKeyRef, SourceUserID: userIDs[input.SourceUserRef], UsageGroupRef: input.UsageGroupRef, DisplayName: input.DisplayName, Active: input.Active}
		if err := tx.Create(&key).Error; err != nil {
			return fmt.Errorf("create source API key: %w", err)
		}
	}
	if err := markAbsentSourceAPIKeysInactive(tx, snapshot.SourceSystem, snapshot.Keys); err != nil {
		return err
	}
	state := entities.SourceCatalogSyncState{SourceSystem: snapshot.SourceSystem, LastSuccessAt: snapshot.SyncedAt, UserCount: len(snapshot.Users), KeyCount: len(snapshot.Keys)}
	if err := tx.Save(&state).Error; err != nil {
		return fmt.Errorf("record source catalog sync state: %w", err)
	}
	return nil
}

func markAbsentSourceUsersInactive(tx *gorm.DB, sourceSystem string, inputs []SourceUserInput) error {
	refs := make([]string, 0, len(inputs))
	for _, input := range inputs {
		refs = append(refs, input.SourceUserRef)
	}
	query := tx.Model(&entities.SourceUser{}).Where("source_system = ?", sourceSystem)
	if len(refs) > 0 {
		query = query.Where("source_user_ref NOT IN ?", refs)
	}
	if err := query.Update("active", false).Error; err != nil {
		return fmt.Errorf("mark absent source users inactive: %w", err)
	}
	return nil
}

func markAbsentSourceAPIKeysInactive(tx *gorm.DB, sourceSystem string, inputs []SourceAPIKeyInput) error {
	refs := make([]string, 0, len(inputs))
	for _, input := range inputs {
		refs = append(refs, input.SourceKeyRef)
	}
	query := tx.Model(&entities.SourceAPIKey{}).Where("source_system = ?", sourceSystem)
	if len(refs) > 0 {
		query = query.Where("source_key_ref NOT IN ?", refs)
	}
	if err := query.Update("active", false).Error; err != nil {
		return fmt.Errorf("mark absent source API keys inactive: %w", err)
	}
	return nil
}

func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// safeSourceReference is the catalog's trust boundary for key-adjacent source
// values. Snapshot producers must supply a short, non-secret entity reference
// or group reference, never a credential, JWT, authorization value, or hash.
func safeSourceReference(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 31 {
		return "", fmt.Errorf("invalid source reference")
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char)) {
			return "", fmt.Errorf("invalid source reference")
		}
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"authorization", "bearer", "token", "secret", "master", "api_key", "apikey"} {
		if strings.Contains(lower, forbidden) {
			return "", fmt.Errorf("invalid source reference")
		}
	}
	if strings.HasPrefix(lower, "sk-") || looksLikeJWT(value) || looksLikeHash(value) {
		return "", fmt.Errorf("invalid source reference")
	}
	return value, nil
}

func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if len(part) < 8 {
			return false
		}
	}
	return true
}

func looksLikeHash(value string) bool {
	if len(value) != 32 && len(value) != 40 && len(value) != 64 && len(value) != 96 && len(value) != 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') || (char >= '0' && char <= '9')) {
			return false
		}
	}
	return true
}

func newOpaqueCatalogID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate opaque catalog ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

package repository

import (
	"context"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/entities"
)

func TestApplySourceSnapshotIsAtomicAndMarksMissingRowsInactive(t *testing.T) {
	db := openTestDatabase(t)
	catalog := NewCatalogRepository(db)
	ctx := context.Background()
	first := SourceCatalogSnapshot{
		SourceSystem: "litellm",
		SyncedAt:     time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
		Users: []SourceUserInput{{
			SourceUserRef: "user-a", Email: "USER@example.com", DisplayName: "User A", Active: true,
		}},
		Keys: []SourceAPIKeyInput{{
			SourceKeyRef: "key-source-a", SourceUserRef: "user-a", UsageGroupRef: "litellm:engineering", DisplayName: "Engineering", Active: true,
		}},
	}
	if err := catalog.ApplySourceSnapshot(ctx, first); err != nil {
		t.Fatalf("apply first source snapshot: %v", err)
	}

	users, err := catalog.ListActiveSourceUsers(ctx, "litellm")
	if err != nil || len(users) != 1 {
		t.Fatalf("expected one active user after first snapshot, got users=%#v err=%v", users, err)
	}
	if users[0].ID == "user-a" || users[0].ID == "" {
		t.Fatalf("source user ID must be opaque rather than its source ref, got %q", users[0].ID)
	}
	keys, err := catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected one active key after first snapshot, got keys=%#v err=%v", keys, err)
	}
	if keys[0].ID == first.Keys[0].SourceKeyRef || keys[0].ID == "" {
		t.Fatalf("source API key ID must be opaque rather than its source ref, got %q", keys[0].ID)
	}

	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{SourceSystem: "litellm", SyncedAt: first.SyncedAt.Add(time.Minute)}); err != nil {
		t.Fatalf("apply empty source snapshot: %v", err)
	}
	users, err = catalog.ListActiveSourceUsers(ctx, "litellm")
	if err != nil || len(users) != 0 {
		t.Fatalf("expected absent users to become inactive, got users=%#v err=%v", users, err)
	}
	keys, err = catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil || len(keys) != 0 {
		t.Fatalf("expected absent keys to become inactive, got keys=%#v err=%v", keys, err)
	}
	state, err := catalog.CatalogSyncState(ctx, "litellm")
	if err != nil || state.UserCount != 0 || state.KeyCount != 0 || !state.LastSuccessAt.Equal(first.SyncedAt.Add(time.Minute)) {
		t.Fatalf("expected final snapshot state, got state=%+v err=%v", state, err)
	}
}

func TestApplySourceSnapshotRejectsInvalidInputWithoutChangingPriorState(t *testing.T) {
	db := openTestDatabase(t)
	catalog := NewCatalogRepository(db)
	ctx := context.Background()
	initial := SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC),
		Users: []SourceUserInput{{SourceUserRef: "user-a", Email: "a@example.com", Active: true}},
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-a", SourceUserRef: "user-a", UsageGroupRef: "group-a", Active: true}},
	}
	if err := catalog.ApplySourceSnapshot(ctx, initial); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: initial.SyncedAt.Add(time.Minute),
		Users: []SourceUserInput{{SourceUserRef: "user-b", Email: "b@example.com", Active: true}},
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-b", SourceUserRef: "missing-user", UsageGroupRef: "group-b", Active: true}},
	}); err == nil {
		t.Fatal("expected snapshot with a missing key owner to fail")
	}
	users, err := catalog.ListActiveSourceUsers(ctx, "litellm")
	if err != nil || len(users) != 1 || users[0].SourceUserRef != "user-a" {
		t.Fatalf("failed snapshot must preserve active users, got users=%#v err=%v", users, err)
	}
	keys, err := catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil || len(keys) != 1 || keys[0].SourceKeyRef != "key-a" {
		t.Fatalf("failed snapshot must preserve active keys, got keys=%#v err=%v", keys, err)
	}
	state, err := catalog.CatalogSyncState(ctx, "litellm")
	if err != nil || !state.LastSuccessAt.Equal(initial.SyncedAt) || state.UserCount != 1 || state.KeyCount != 1 {
		t.Fatalf("failed snapshot must preserve sync state, got state=%+v err=%v", state, err)
	}
}

func TestApplySourceSnapshotRejectsUnsafeKeyReferencesWithoutPersistingThem(t *testing.T) {
	db := openTestDatabase(t)
	catalog := NewCatalogRepository(db)
	ctx := context.Background()
	initial := SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC),
		Users: []SourceUserInput{{SourceUserRef: "user-a", Email: "a@example.com", Active: true}},
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-a", SourceUserRef: "user-a", UsageGroupRef: "group-a", Active: true}},
	}
	if err := catalog.ApplySourceSnapshot(ctx, initial); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	unsafeReference := "sk-live-example-credential"
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: initial.SyncedAt.Add(time.Minute),
		Users: initial.Users,
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: unsafeReference, SourceUserRef: "user-a", UsageGroupRef: "group-a", Active: true}},
	}); err == nil {
		t.Fatal("expected raw credential-shaped source key reference to be rejected")
	} else if strings.Contains(err.Error(), unsafeReference) {
		t.Fatal("validation error must not display rejected key material")
	}
	unsafeGroupReference := "Bearer-example-credential"
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: initial.SyncedAt.Add(2 * time.Minute),
		Users: initial.Users,
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-b", SourceUserRef: "user-a", UsageGroupRef: unsafeGroupReference, Active: true}},
	}); err == nil {
		t.Fatal("expected credential-shaped usage group reference to be rejected")
	} else if strings.Contains(err.Error(), unsafeGroupReference) {
		t.Fatal("validation error must not display rejected usage-group material")
	}
	hashReference := strings.Repeat("a", 64)
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: initial.SyncedAt.Add(3 * time.Minute),
		Users: initial.Users,
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-b", SourceUserRef: "user-a", UsageGroupRef: hashReference, Active: true}},
	}); err == nil {
		t.Fatal("expected hash-shaped usage group reference to be rejected")
	} else if strings.Contains(err.Error(), hashReference) {
		t.Fatal("validation error must not display rejected hash material")
	}
	keys, err := catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil || len(keys) != 1 || keys[0].SourceKeyRef != "key-a" {
		t.Fatalf("unsafe input must not be persisted or returned, got keys=%#v err=%v", keys, err)
	}
}

func TestSourceAPIKeyDirectWritesRejectUnsafeReferencesAndActiveReadsStaySafe(t *testing.T) {
	db := openTestDatabase(t)
	catalog := NewCatalogRepository(db)
	user := entities.SourceUser{ID: "source-user", SourceSystem: "litellm", SourceUserRef: "user-a", Active: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create source user: %v", err)
	}
	unsafeReference := "sk-live-example-credential"
	if err := db.Create(&entities.SourceAPIKey{ID: "unsafe-orm", SourceSystem: "litellm", SourceKeyRef: unsafeReference, SourceUserID: user.ID, UsageGroupRef: "group-a", Active: true}).Error; err == nil {
		t.Fatal("expected direct ORM write with credential-shaped key reference to fail")
	}
	if err := db.Exec(`INSERT INTO source_api_keys (id, source_system, source_key_ref, source_user_id, usage_group_ref, active)
		VALUES (?, ?, ?, ?, ?, ?)`, "unsafe-sql", "litellm", "key-b", user.ID, unsafeReference, true).Error; err == nil {
		t.Fatal("expected direct SQL write with credential-shaped usage group reference to fail")
	}
	if err := db.Create(&entities.SourceAPIKey{ID: "safe-key", SourceSystem: "litellm", SourceKeyRef: "key-a", SourceUserID: user.ID, UsageGroupRef: "group-a", Active: true}).Error; err != nil {
		t.Fatalf("create safe source API key: %v", err)
	}
	if err := db.Model(&entities.SourceAPIKey{}).Where("id = ?", "safe-key").Update("source_key_ref", unsafeReference).Error; err == nil {
		t.Fatal("expected direct update with credential-shaped key reference to fail")
	}
	keys, err := catalog.ListActiveSourceAPIKeys(context.Background(), "litellm")
	if err != nil || len(keys) != 1 || keys[0].ID != "safe-key" || keys[0].SourceKeyRef != "key-a" || keys[0].UsageGroupRef != "group-a" {
		t.Fatalf("active reads must expose only safely stored references, got keys=%#v err=%v", keys, err)
	}
}

func TestCatalogRepositoryEnforcesIdentityAndSourceCatalogConstraints(t *testing.T) {
	db := openTestDatabase(t)
	catalog := NewCatalogRepository(db)
	ctx := context.Background()

	identity, err := catalog.UpsertExternalIdentity(ctx, "https://issuer.example", "subject-a", "USER@example.com", "User A")
	if err != nil {
		t.Fatalf("upsert external identity: %v", err)
	}
	if identity.ID == "subject-a" || identity.ID == "" || identity.NormalizedEmail != "user@example.com" {
		t.Fatalf("expected opaque identity ID and normalized email, got %+v", identity)
	}
	if _, err := catalog.UpsertExternalIdentity(ctx, "https://issuer.example", "subject-a", "other@example.com", "User A"); err != nil {
		t.Fatalf("expected issuer/subject upsert: %v", err)
	}
	var identityCount int64
	if err := db.Model(&entities.ExternalIdentity{}).Where("issuer = ? AND subject = ?", "https://issuer.example", "subject-a").Count(&identityCount).Error; err != nil || identityCount != 1 {
		t.Fatalf("expected one identity per issuer/subject, got count=%d err=%v", identityCount, err)
	}
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		Users: []SourceUserInput{{SourceUserRef: "user-a", Email: "user@example.com", Active: true}},
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-a", SourceUserRef: "user-a", UsageGroupRef: "group-a", Active: true}},
	}); err != nil {
		t.Fatalf("apply source snapshot: %v", err)
	}
	if err := catalog.ApplySourceSnapshot(ctx, SourceCatalogSnapshot{
		SourceSystem: "other", SyncedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		Users: []SourceUserInput{{SourceUserRef: "user-a", Email: "user@example.com", Active: true}},
		Keys:  []SourceAPIKeyInput{{SourceKeyRef: "key-a", SourceUserRef: "user-a", UsageGroupRef: "group-a", Active: true}},
	}); err != nil {
		t.Fatalf("apply source-scoped snapshot: %v", err)
	}
	users, err := catalog.FindActiveSourceUsersByEmail(ctx, "litellm", "USER@example.com")
	if err != nil || len(users) != 1 || users[0].SourceSystem != "litellm" {
		t.Fatalf("expected source-scoped normalized email lookup, got users=%#v err=%v", users, err)
	}
	key, err := catalog.FindActiveSourceAPIKey(ctx, "litellm", "key-a")
	if err != nil || key.SourceSystem != "litellm" {
		t.Fatalf("expected source-scoped API key lookup, got key=%+v err=%v", key, err)
	}
	if err := catalog.ReplaceIdentityLink(ctx, identity.ID, "litellm", users[0].ID, "email", false); err != nil {
		t.Fatalf("replace identity link: %v", err)
	}
	link, found, err := catalog.FindIdentityLink(ctx, identity.ID, "litellm")
	if err != nil || !found || link.SourceUserID != users[0].ID {
		t.Fatalf("expected linked source user, got link=%+v found=%t err=%v", link, found, err)
	}
	if err := catalog.ReplaceIdentityLink(ctx, identity.ID, "litellm", users[0].ID, "manual", true); err != nil {
		t.Fatalf("replace existing identity link: %v", err)
	}
	mappings, err := catalog.ListIdentityMappings(ctx, "litellm")
	if err != nil || len(mappings) != 1 || mappings[0].MatchMethod != "manual" || !mappings[0].Confirmed {
		t.Fatalf("expected one replacement link, got mappings=%#v err=%v", mappings, err)
	}
	if err := db.Create(&entities.SourceUser{ID: "duplicate-user", SourceSystem: "litellm", SourceUserRef: "user-a"}).Error; err == nil {
		t.Fatal("expected source-system/source-user-ref uniqueness constraint")
	}
	if err := db.Create(&entities.SourceAPIKey{ID: "duplicate-key", SourceSystem: "litellm", SourceKeyRef: "key-a", SourceUserID: users[0].ID, UsageGroupRef: "group-a", Active: true}).Error; err == nil {
		t.Fatal("expected source-system/source-key-ref uniqueness constraint")
	}
	if err := db.Create(&entities.IdentitySourceLink{ID: "duplicate-link", ExternalIdentityID: identity.ID, SourceSystem: "litellm", SourceUserID: users[0].ID, MatchMethod: "manual"}).Error; err == nil {
		t.Fatal("expected one identity/source link constraint")
	}
	var otherUser entities.SourceUser
	if err := db.Where("source_system = ? AND source_user_ref = ?", "other", "user-a").First(&otherUser).Error; err != nil {
		t.Fatalf("find other-source user: %v", err)
	}
	if err := db.Create(&entities.SourceAPIKey{ID: "mismatched-key", SourceSystem: "litellm", SourceKeyRef: "key-b", SourceUserID: otherUser.ID, UsageGroupRef: "group-b", Active: true}).Error; err == nil {
		t.Fatal("expected source API key source-system ownership constraint")
	}
	if err := db.Create(&entities.IdentitySourceLink{ID: "mismatched-link", ExternalIdentityID: identity.ID, SourceSystem: "other", SourceUserID: users[0].ID, MatchMethod: "manual"}).Error; err == nil {
		t.Fatal("expected identity link source-system ownership constraint")
	}
}

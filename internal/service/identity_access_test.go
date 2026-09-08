package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	servicedto "cpa-usage-keeper/internal/service/dto"
)

func TestResolveScopeRejectsForeignKeyAndEmptySetFailsClosed(t *testing.T) {
	access, alice, bobKey := seededIdentityAccessService(t)
	_, err := access.ResolveScope(context.Background(), alice, ScopeSelection{KeyCatalogID: bobKey})
	if err != ErrUsageScopeForbidden {
		t.Fatalf("ResolveScope() error = %v, want ErrUsageScopeForbidden", err)
	}

	if err := access.catalog.ApplySourceSnapshot(context.Background(), repository.SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 12, 1, 0, 0, time.UTC),
		Users: []repository.SourceUserInput{
			{SourceUserRef: "alice", Email: "alice@example.com", Active: true},
			{SourceUserRef: "bob", Email: "bob@example.com", Active: true},
		},
		Keys: []repository.SourceAPIKeyInput{{SourceKeyRef: "bob-key", SourceUserRef: "bob", UsageGroupRef: "bob", Active: true}},
	}); err != nil {
		t.Fatalf("remove Alice keys: %v", err)
	}
	scope, err := access.ResolveScope(context.Background(), alice, ScopeSelection{})
	if err != nil {
		t.Fatalf("ResolveScope() error = %v", err)
	}
	if scope.Mode != servicedto.UsageScopeKeySet || len(scope.APIGroupKeys) != 0 {
		t.Fatalf("ResolveScope() = %#v, want fail-closed empty key set", scope)
	}
}

func TestResolveScopeAppliesAdministratorAndUserPolicy(t *testing.T) {
	access, alice, bobKey := seededIdentityAccessService(t)
	ctx := context.Background()

	admin, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "admin", IsAdministrator: true}, "litellm")
	if err != nil {
		t.Fatalf("ResolveIdentity(admin): %v", err)
	}
	all, err := access.ResolveScope(ctx, admin, ScopeSelection{})
	if err != nil || all.Mode != servicedto.UsageScopeAllSource || all.SourceSystem != "litellm" {
		t.Fatalf("admin all-source scope = %#v, %v", all, err)
	}

	users, err := access.ListScopeUsers(ctx, admin)
	if err != nil || len(users) != 2 {
		t.Fatalf("ListScopeUsers(admin) = %#v, %v", users, err)
	}
	selectedUser, err := access.ResolveScope(ctx, admin, ScopeSelection{UserCatalogID: users[0].ID})
	if err != nil || selectedUser.Mode != servicedto.UsageScopeKeySet || !sameStrings(selectedUser.APIGroupKeys, []string{"internal-alice-a", "internal-alice-b"}) {
		t.Fatalf("admin selected-user scope = %#v, %v", selectedUser, err)
	}
	selectedKey, err := access.ResolveScope(ctx, admin, ScopeSelection{KeyCatalogID: bobKey})
	if err != nil || !sameStrings(selectedKey.APIGroupKeys, []string{"internal-bob"}) {
		t.Fatalf("admin selected-key scope = %#v, %v", selectedKey, err)
	}

	owned, err := access.ResolveScope(ctx, alice, ScopeSelection{KeyCatalogID: users[0].ID})
	if err != ErrUsageScopeForbidden || owned.Mode != "" {
		t.Fatalf("user-supplied user ID must be forbidden, got scope=%#v err=%v", owned, err)
	}
}

func TestResolveScopeLimitsUserToOwnedKeysAndNormalizesResolverOutput(t *testing.T) {
	access, alice, _ := seededIdentityAccessService(t)
	ctx := context.Background()

	allOwned, err := access.ResolveScope(ctx, alice, ScopeSelection{})
	if err != nil || !sameStrings(allOwned.APIGroupKeys, []string{"internal-alice-a", "internal-alice-b"}) {
		t.Fatalf("user all-owned scope = %#v, %v", allOwned, err)
	}
	keys, err := access.ListScopeKeys(ctx, alice, "")
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListScopeKeys(user) = %#v, %v", keys, err)
	}
	oneOwned, err := access.ResolveScope(ctx, alice, ScopeSelection{KeyCatalogID: keys[0].ID})
	if err != nil || !sameStrings(oneOwned.APIGroupKeys, []string{"internal-alice-a"}) {
		t.Fatalf("user one-owned-key scope = %#v, %v", oneOwned, err)
	}

	access.resolvers["litellm"] = fixedUsageKeyResolver{values: []string{"z", "a", "z", ""}}
	normalized, err := access.ResolveScope(ctx, alice, ScopeSelection{})
	if err != nil || !sameStrings(normalized.APIGroupKeys, []string{"a", "z"}) {
		t.Fatalf("resolved key set must be sorted and deduplicated, got %#v err=%v", normalized, err)
	}
}

func TestResolveScopeRejectsForgedAdministratorPrincipal(t *testing.T) {
	access, _, _ := seededIdentityAccessService(t)
	scope, err := access.ResolveScope(context.Background(), AccessPrincipal{SourceSystem: "litellm", IsAdministrator: true}, ScopeSelection{})
	if err != ErrUsageScopeForbidden || scope.Mode != "" {
		t.Fatalf("forged administrator scope = %#v, %v; want forbidden", scope, err)
	}
}

func TestResolveScopeIgnoresMutationsToReturnedUserPrincipal(t *testing.T) {
	access, alice, bobKeyID := seededIdentityAccessService(t)
	ctx := context.Background()

	escalated := alice
	escalated.IsAdministrator = true
	scope, err := access.ResolveScope(ctx, escalated, ScopeSelection{})
	if err != nil || scope.Mode != servicedto.UsageScopeKeySet || !sameStrings(scope.APIGroupKeys, []string{"internal-alice-a", "internal-alice-b"}) {
		t.Fatalf("mutated user administrator scope = %#v, %v; want original user scope", scope, err)
	}

	bobKey, err := access.catalog.FindActiveSourceAPIKeyByID(ctx, "litellm", bobKeyID)
	if err != nil {
		t.Fatalf("FindActiveSourceAPIKeyByID(): %v", err)
	}
	otherUser := alice
	otherUser.SourceUserID = bobKey.SourceUserID
	scope, err = access.ResolveScope(ctx, otherUser, ScopeSelection{KeyCatalogID: bobKeyID})
	if err != ErrUsageScopeForbidden || scope.Mode != "" {
		t.Fatalf("mutated user ownership scope = %#v, %v; want forbidden", scope, err)
	}
}

func TestResolveScopeRejectsInactiveAndUnownedKeys(t *testing.T) {
	access, alice, bobKey := seededIdentityAccessService(t)
	ctx := context.Background()
	keys, err := access.ListScopeKeys(ctx, alice, "")
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListScopeKeys(alice) = %#v, %v", keys, err)
	}

	if err := access.catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 12, 1, 0, 0, time.UTC),
		Users: []repository.SourceUserInput{
			{SourceUserRef: "alice", Email: "alice@example.com", Active: true},
			{SourceUserRef: "bob", Email: "bob@example.com", Active: true},
		},
		Keys: []repository.SourceAPIKeyInput{
			{SourceKeyRef: "alice-key-a", SourceUserRef: "alice", UsageGroupRef: "alice-a", Active: true},
			{SourceKeyRef: "alice-key-b", SourceUserRef: "alice", UsageGroupRef: "alice-b", Active: true},
		},
	}); err != nil {
		t.Fatalf("make Bob key inactive: %v", err)
	}
	_, err = access.ResolveScope(ctx, alice, ScopeSelection{KeyCatalogID: bobKey})
	if err != ErrUsageScopeForbidden {
		t.Fatalf("inactive key error = %v, want ErrUsageScopeForbidden", err)
	}
	if _, err := access.ResolveScope(ctx, alice, ScopeSelection{KeyCatalogID: "foreign-key"}); err != ErrUsageScopeForbidden {
		t.Fatalf("unowned key error = %v, want ErrUsageScopeForbidden", err)
	}
}

func TestResolveIdentityAutoLinksOnlyOneExactNormalizedEmailMatch(t *testing.T) {
	access, _, _ := seededIdentityAccessService(t)
	ctx := context.Background()

	principal, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "case-match", Email: " ALICE@EXAMPLE.COM "}, "litellm")
	if err != nil || principal.SourceUserID == "" {
		t.Fatalf("unique normalized email must auto-link, principal=%#v err=%v", principal, err)
	}
	if _, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "missing-email"}, "litellm"); err != ErrUsageScopeForbidden {
		t.Fatalf("missing email error = %v, want ErrUsageScopeForbidden", err)
	}

	if err := access.catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC),
		Users: []repository.SourceUserInput{
			{SourceUserRef: "alice", Email: "alice@example.com", Active: true},
			{SourceUserRef: "bob", Email: "bob@example.com", Active: true},
			{SourceUserRef: "duplicate", Email: "bob@example.com", Active: true},
		},
		Keys: []repository.SourceAPIKeyInput{
			{SourceKeyRef: "alice-key-a", SourceUserRef: "alice", UsageGroupRef: "alice-a", Active: true},
			{SourceKeyRef: "alice-key-b", SourceUserRef: "alice", UsageGroupRef: "alice-b", Active: true},
			{SourceKeyRef: "bob-key", SourceUserRef: "bob", UsageGroupRef: "bob", Active: true},
		},
	}); err != nil {
		t.Fatalf("make email ambiguous: %v", err)
	}
	if _, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "ambiguous", Email: "bob@example.com"}, "litellm"); err != ErrUsageScopeForbidden {
		t.Fatalf("ambiguous email error = %v, want ErrUsageScopeForbidden", err)
	}
}

func TestResolveIdentityStoredLinkOutranksChangedJWTEmailAndManualReplacement(t *testing.T) {
	access, alice, _ := seededIdentityAccessService(t)
	ctx := context.Background()
	users, err := access.ListScopeUsers(ctx, mustAdmin(t, access, ctx))
	if err != nil || len(users) != 2 {
		t.Fatalf("ListScopeUsers(admin) = %#v, %v", users, err)
	}
	bob := users[1]
	if err := access.ReplaceIdentityMapping(ctx, mustAdmin(t, access, ctx), alice.ExternalIdentityID, bob.ID); err != nil {
		t.Fatalf("ReplaceIdentityMapping(): %v", err)
	}

	resolved, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "alice", Email: "alice@example.com"}, "litellm")
	if err != nil || resolved.SourceUserID != bob.ID {
		t.Fatalf("stored link must outrank JWT email, principal=%#v err=%v", resolved, err)
	}
	scope, err := access.ResolveScope(ctx, resolved, ScopeSelection{})
	if err != nil || !sameStrings(scope.APIGroupKeys, []string{"internal-bob"}) {
		t.Fatalf("replaced identity scope = %#v, %v", scope, err)
	}
}

func TestIdentityMappingAdministrationIsSourceScoped(t *testing.T) {
	access, alice, _ := seededIdentityAccessService(t)
	ctx := context.Background()
	if _, err := access.ListIdentityMappings(ctx, alice); err != ErrUsageScopeForbidden {
		t.Fatalf("ListIdentityMappings(user) error = %v, want ErrUsageScopeForbidden", err)
	}
	if err := access.ReplaceIdentityMapping(ctx, alice, alice.ExternalIdentityID, alice.SourceUserID); err != ErrUsageScopeForbidden {
		t.Fatalf("ReplaceIdentityMapping(user) error = %v, want ErrUsageScopeForbidden", err)
	}
}

func seededIdentityAccessService(t *testing.T) (*IdentityAccessService, AccessPrincipal, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "identity-access.db")
	db, err := repository.OpenDatabase(config.Config{SQLitePath: dbPath})
	if err != nil {
		t.Fatalf("OpenDatabase(): %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("DB(): %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	catalog := repository.NewCatalogRepository(db)
	ctx := context.Background()
	if err := catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{
		SourceSystem: "litellm", SyncedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		Users: []repository.SourceUserInput{
			{SourceUserRef: "alice", Email: "alice@example.com", Active: true},
			{SourceUserRef: "bob", Email: "bob@example.com", Active: true},
		},
		Keys: []repository.SourceAPIKeyInput{
			{SourceKeyRef: "alice-key-a", SourceUserRef: "alice", UsageGroupRef: "alice-a", Active: true},
			{SourceKeyRef: "alice-key-b", SourceUserRef: "alice", UsageGroupRef: "alice-b", Active: true},
			{SourceKeyRef: "bob-key", SourceUserRef: "bob", UsageGroupRef: "bob", Active: true},
		},
	}); err != nil {
		t.Fatalf("ApplySourceSnapshot(): %v", err)
	}
	service := NewIdentityAccessService(catalog, map[string]SourceUsageKeyResolver{"litellm": testUsageKeyResolver{}})
	alice, err := service.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "alice", Email: "alice@example.com"}, "litellm")
	if err != nil {
		t.Fatalf("ResolveIdentity(alice): %v", err)
	}
	keys, err := catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil {
		t.Fatalf("ListActiveSourceAPIKeys(): %v", err)
	}
	for _, key := range keys {
		if key.SourceUserID != alice.SourceUserID {
			return service, alice, key.ID
		}
	}
	t.Fatal("seed must contain a foreign key")
	return nil, AccessPrincipal{}, ""
}

func mustAdmin(t *testing.T, access *IdentityAccessService, ctx context.Context) AccessPrincipal {
	t.Helper()
	admin, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "admin", IsAdministrator: true}, "litellm")
	if err != nil {
		t.Fatalf("ResolveIdentity(admin): %v", err)
	}
	return admin
}

type testUsageKeyResolver struct{}

func (testUsageKeyResolver) ResolveAPIGroupKeys(_ context.Context, _ string, keys []entities.SourceAPIKey) ([]string, error) {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, "internal-"+key.UsageGroupRef)
	}
	return values, nil
}

type fixedUsageKeyResolver struct{ values []string }

func (r fixedUsageKeyResolver) ResolveAPIGroupKeys(_ context.Context, _ string, _ []entities.SourceAPIKey) ([]string, error) {
	return r.values, nil
}

func sameStrings(got, want []string) bool {
	got, want = append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	return fmt.Sprint(got) == fmt.Sprint(want)
}

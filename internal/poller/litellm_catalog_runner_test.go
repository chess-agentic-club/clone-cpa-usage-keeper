package poller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"gorm.io/gorm"
)

func TestLiteLLMCatalogRunnerPaginatesUsersAndKeysBeforeCommit(t *testing.T) {
	fixture := newLiteLLMCatalogFixture(t, false)
	db := catalogTestDB(t)
	runner := NewLiteLLMCatalogRunner(NewLiteLLMClient(fixture.server.URL, "test-master", time.Second), repository.NewCatalogRepository(db), time.Minute, 100)

	if err := runner.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	if got, want := fixture.paths(), []string{"/user/list?page=1&page_size=100", "/user/list?page=2&page_size=100", "/key/list?page=1&return_full_object=true&size=100", "/key/list?page=2&return_full_object=true&size=100"}; !sameStrings(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}

	var keys []entities.SourceAPIKey
	if err := db.Order("source_key_ref").Find(&keys).Error; err != nil {
		t.Fatalf("load catalog keys: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("catalog key count = %d, want 4", len(keys))
	}
	identityAliasFallback := false
	for _, key := range keys {
		if strings.HasPrefix(key.SourceKeyRef, "sk-") || len(key.SourceKeyRef) > 31 || len(key.UsageGroupRef) > 31 {
			t.Fatal("catalog persisted a non-opaque LiteLLM key reference")
		}
		identityAliasFallback = identityAliasFallback || key.DisplayName == "LiteLLM key"
	}
	if !identityAliasFallback {
		t.Fatal("key alias equal to its identity did not fall back to a safe display name")
	}
	var unowned entities.SourceUser
	if err := db.Where("source_system = ? AND source_user_ref = ?", liteLLMSourceSystem, liteLLMUnownedUserRef).First(&unowned).Error; err != nil {
		t.Fatalf("load unowned user: %v", err)
	}
	if unowned.Active || unowned.Email != "" {
		t.Fatalf("unowned user = %+v", unowned)
	}
	var inactiveCount int64
	if err := db.Model(&entities.SourceAPIKey{}).Where("source_system = ? AND active = ?", liteLLMSourceSystem, false).Count(&inactiveCount).Error; err != nil {
		t.Fatalf("count inactive keys: %v", err)
	}
	if inactiveCount != 2 {
		t.Fatalf("inactive key count = %d, want 2", inactiveCount)
	}
}

func TestLiteLLMCatalogRunnerFinalPageFailureRetainsLastSnapshot(t *testing.T) {
	db := catalogTestDB(t)
	catalog := repository.NewCatalogRepository(db)
	if err := catalog.ApplySourceSnapshot(context.Background(), repository.SourceCatalogSnapshot{
		SourceSystem: liteLLMSourceSystem,
		Users:        []repository.SourceUserInput{{SourceUserRef: "existing", DisplayName: "Existing", Active: true}},
		Keys:         []repository.SourceAPIKeyInput{{SourceKeyRef: "existing-key", SourceUserRef: "existing", UsageGroupRef: "existing-group", DisplayName: "Existing", Active: true}},
		SyncedAt:     time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	fixture := newLiteLLMCatalogFixture(t, true)
	runner := NewLiteLLMCatalogRunner(NewLiteLLMClient(fixture.server.URL, "test-master", time.Second), catalog, time.Minute, 100)
	if err := runner.SyncOnce(context.Background()); err == nil {
		t.Fatal("SyncOnce() succeeded after final key page failure")
	}
	keys, err := catalog.ListActiveSourceAPIKeys(context.Background(), liteLLMSourceSystem)
	if err != nil {
		t.Fatalf("ListActiveSourceAPIKeys() error = %v", err)
	}
	if len(keys) != 1 || keys[0].SourceKeyRef != "existing-key" {
		t.Fatalf("catalog changed after failed fetch: %+v", keys)
	}
}

func TestLiteLLMKeyReferenceIsCanonicalizedToOpaqueGroup(t *testing.T) {
	raw := "sk-" + strings.Repeat("z", 48)
	ref, err := opaqueLiteLLMKeyRef(raw)
	if err != nil {
		t.Fatalf("opaqueLiteLLMKeyRef() error = %v", err)
	}
	if !strings.HasPrefix(ref, "lkey-") || len(ref) > 31 || strings.Contains(ref, raw) {
		t.Fatal("raw LiteLLM key was not canonicalized to a safe opaque reference")
	}
	event, err := MapLiteLLMSpendLog(LiteLLMSpendLog{RequestID: "request", APIKey: raw})
	if err != nil {
		t.Fatalf("MapLiteLLMSpendLog() error = %v", err)
	}
	if event.APIGroupKey != liteLLMAPIGroupKeyFromRef(ref) || strings.Contains(event.APIGroupKey, raw) {
		t.Fatal("usage event did not use the opaque catalog group")
	}
	blank, err := MapLiteLLMSpendLog(LiteLLMSpendLog{RequestID: "unattributed"})
	if err != nil || blank.APIGroupKey != "litellm:unattributed" {
		t.Fatalf("blank key mapping = %+v, %v", blank, err)
	}
}

func TestLiteLLMUsageKeyResolverUsesOnlyOpaqueCatalogReferences(t *testing.T) {
	groups, err := (LiteLLMUsageKeyResolver{}).ResolveAPIGroupKeys(context.Background(), liteLLMSourceSystem, []entities.SourceAPIKey{{SourceSystem: liteLLMSourceSystem, UsageGroupRef: "lkey-abcdefghijklmnopqrstuv"}})
	if err != nil || len(groups) != 1 || groups[0] != "litellm:lkey-abcdefghijklmnopqrstuv" {
		t.Fatalf("ResolveAPIGroupKeys() = %v, %v", groups, err)
	}
	if _, err := (LiteLLMUsageKeyResolver{}).ResolveAPIGroupKeys(context.Background(), liteLLMSourceSystem, []entities.SourceAPIKey{{UsageGroupRef: strings.Repeat("a", 64)}}); err == nil {
		t.Fatal("resolver accepted a full hash reference")
	}
}

func TestLiteLLMKeyDisplayNameNeverUsesCredentialOrHashAlias(t *testing.T) {
	credentialAlias := "sk-" + strings.Repeat("q", 48)
	if got := liteLLMKeyDisplayName(LiteLLMKey{Token: strings.Repeat("a", 64), Alias: credentialAlias}); got != "LiteLLM key" {
		t.Fatal("credential-shaped alias was selected for display")
	}
	if got := liteLLMKeyDisplayName(LiteLLMKey{Token: strings.Repeat("a", 64), Alias: strings.Repeat("b", 64)}); got != "LiteLLM key" {
		t.Fatal("hash-shaped alias was selected for display")
	}
}

func TestLiteLLMCatalogRunnerReservesOwnerlessReferenceAgainstUserIDCollision(t *testing.T) {
	fixture := newLiteLLMCatalogFixture(t, false)
	fixture.server.Close()
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/list":
			writeCatalogJSON(t, w, map[string]any{"users": []map[string]string{{"user_id": liteLLMUnownedUserRef, "user_email": "member@example.com"}}, "total_pages": 1})
		case "/key/list":
			writeCatalogJSON(t, w, map[string]any{"keys": []map[string]any{{"token": strings.Repeat("e", 64), "user_id": "", "blocked": false}}, "total_pages": 1})
		default:
			t.Fatal("unexpected catalog request")
		}
	}))
	t.Cleanup(fixture.server.Close)
	db := catalogTestDB(t)
	if err := NewLiteLLMCatalogRunner(NewLiteLLMClient(fixture.server.URL, "test-master", time.Second), repository.NewCatalogRepository(db), time.Minute, 100).SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce() error = %v", err)
	}
	var users []entities.SourceUser
	if err := db.Where("source_system = ?", liteLLMSourceSystem).Order("source_user_ref").Find(&users).Error; err != nil {
		t.Fatalf("load source users: %v", err)
	}
	if len(users) != 2 || users[0].SourceUserRef == users[1].SourceUserRef {
		t.Fatal("ownerless synthetic user collided with a real LiteLLM user")
	}
}

func catalogTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "catalog.db")})
	if err != nil {
		t.Fatalf("OpenDatabase() error = %v", err)
	}
	t.Cleanup(func() { closeCatalogDB(t, db) })
	return db
}

func closeCatalogDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("DB() error = %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type liteLLMCatalogFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []string
	fail   bool
}

func newLiteLLMCatalogFixture(t *testing.T, failFinalKeyPage bool) *liteLLMCatalogFixture {
	t.Helper()
	fixture := &liteLLMCatalogFixture{fail: failFinalKeyPage}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.seen = append(fixture.seen, r.URL.RequestURI())
		fixture.mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Fatal("catalog request did not authenticate")
		}
		if r.URL.Query().Get("user_id") != "" {
			t.Fatal("full user catalog sync requested a user filter")
		}
		switch r.URL.Path {
		case "/user/list":
			if r.URL.Query().Get("page") == "1" {
				writeCatalogJSON(t, w, map[string]any{"users": []map[string]string{{"user_id": "alice", "user_email": "alice@example.com", "user_alias": "Alice"}}, "total_pages": 2})
				return
			}
			writeCatalogJSON(t, w, map[string]any{"users": []map[string]string{{"user_id": "bob", "user_email": "bob@example.com", "user_alias": "Bob"}}, "total_pages": 2})
		case "/key/list":
			if r.URL.Query().Get("page") == "2" && fixture.fail {
				http.Error(w, "upstream failure", http.StatusBadGateway)
				return
			}
			if r.URL.Query().Get("page") == "1" {
				raw := "sk-" + strings.Repeat("a", 48)
				writeCatalogJSON(t, w, map[string]any{"keys": []map[string]any{
					{"token": raw, "user_id": "alice", "key_alias": raw, "blocked": false},
					{"token": strings.Repeat("b", 64), "user_id": "alice", "key_alias": "Blocked", "blocked": true},
				}, "total_pages": 2})
				return
			}
			writeCatalogJSON(t, w, map[string]any{"keys": []map[string]any{
				{"token": strings.Repeat("c", 64), "user_id": "", "key_alias": "Ownerless", "blocked": false},
				{"token": strings.Repeat("d", 64), "user_id": "bob", "key_alias": "Expired", "blocked": false, "expires": "2000-01-01T00:00:00Z"},
			}, "total_pages": 2})
		default:
			t.Fatalf("unexpected catalog path %q", r.URL.Path)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *liteLLMCatalogFixture) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func writeCatalogJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode fixture response: %v", err)
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

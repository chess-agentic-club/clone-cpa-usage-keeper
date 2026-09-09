package test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "cpa-usage-keeper/internal/api"
	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/pricing"
	"cpa-usage-keeper/internal/repository"
	"cpa-usage-keeper/internal/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	embeddedSessionHeader = "X-CPA-Usage-Keeper-Embed-Session"
	requestIntentHeader   = "X-CPA-Usage-Keeper-Request"
	sensitiveGroupA       = "internal-sensitive-group-a"
	sensitiveGroupB       = "internal-sensitive-group-b"
	sensitiveGroupBob     = "internal-sensitive-group-bob"
)

var (
	embeddedLegacyRawKey = "sk-" + strings.Repeat("r", 48)
	embeddedLegacyHash   = strings.Repeat("e", 64)
)

type embeddedUsageIDs struct {
	AliceUser       string
	BobUser         string
	CarolUser       string
	AliceKeyA       string
	AliceKeyB       string
	BobKey          string
	UnownedUser     string
	UnownedKey      string
	PendingIdentity string
}

type embeddedUsageFixture struct {
	router     *gin.Engine
	db         *gorm.DB
	catalog    *repository.CatalogRepository
	access     *service.IdentityAccessService
	usage      service.UsageProvider
	config     AuthConfig
	adminToken string
	aliceToken string
	carolToken string
	ids        embeddedUsageIDs
}

func TestEmbeddedUsageUserAndAdministratorScopesCannotEscapePolicy(t *testing.T) {
	fixture := seededEmbeddedUsageRouter(t)

	assertEmbeddedTokens(t, fixture.router, fixture.aliceToken, "/api/v1/key-overview?range=24h", 30)
	assertEmbeddedTokens(t, fixture.router, fixture.aliceToken, "/api/v1/key-overview?range=24h&key_catalog_id="+url.QueryEscape(fixture.ids.AliceKeyA), 10)
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/key-overview?range=24h&key_catalog_id="+url.QueryEscape(fixture.ids.BobKey), http.StatusForbidden)
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/key-overview?range=24h&user_catalog_id="+url.QueryEscape(fixture.ids.BobUser), http.StatusForbidden)

	assertEmbeddedAnalysisTokens(t, fixture.router, fixture.adminToken, "/api/v1/usage/analysis?range=24h", 310)
	assertEmbeddedAnalysisTokens(t, fixture.router, fixture.adminToken, "/api/v1/usage/analysis?range=24h&user_catalog_id="+url.QueryEscape(fixture.ids.AliceUser), 30)
	assertEmbeddedAnalysisTokens(t, fixture.router, fixture.adminToken, "/api/v1/usage/analysis?range=24h&user_catalog_id="+url.QueryEscape(fixture.ids.AliceUser)+"&key_catalog_id="+url.QueryEscape(fixture.ids.AliceKeyB), 20)
	assertEmbeddedStatus(t, fixture.router, fixture.adminToken, "/api/v1/usage/analysis?range=24h&user_catalog_id="+url.QueryEscape(fixture.ids.AliceUser)+"&key_catalog_id="+url.QueryEscape(fixture.ids.BobKey), http.StatusForbidden)
	assertEmbeddedStatus(t, fixture.router, fixture.adminToken, "/api/v1/usage/analysis?range=24h&key_catalog_id="+url.QueryEscape(fixture.ids.UnownedKey), http.StatusForbidden)

	assertEmbeddedTokens(t, fixture.router, fixture.carolToken, "/api/v1/key-overview?range=24h", 0)
	assertEmbeddedAnalysisTokens(t, fixture.router, fixture.carolToken, "/api/v1/key-analysis?range=24h", 0)

	for _, path := range []string{
		"/api/v1/key-activity?range=24h",
		"/api/v1/key-overview/realtime?window=15m",
		"/api/v1/key-analysis/latency?range=24h",
	} {
		response := performEmbeddedUsageRequest(fixture.router, fixture.aliceToken, http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body=%s", path, response.Code, response.Body.String())
		}
		assertNoEmbeddedUsageSecrets(t, response.Body.String())
	}
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/key-events?range=24h", http.StatusForbidden)
	// No ranking provider is configured, so embedded RoleUser gets no ranking
	// route at all rather than a user-capable registration.
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/ranking", http.StatusNotFound)
}

func TestUsageScopeSelectorsAreRoleFilteredOpaqueAndStaleAware(t *testing.T) {
	fixture := seededEmbeddedUsageRouter(t)

	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/usage/scope/users", http.StatusForbidden)
	userKeys := performEmbeddedUsageRequest(fixture.router, fixture.aliceToken, http.MethodGet, "/api/v1/usage/scope/keys", "")
	if userKeys.Code != http.StatusOK {
		t.Fatalf("user keys status = %d, body=%s", userKeys.Code, userKeys.Body.String())
	}
	assertScopeEnvelope(t, userKeys.Body.Bytes(), "keys", 2, true)
	if strings.Contains(userKeys.Body.String(), fixture.ids.BobKey) {
		t.Fatalf("user key selector exposed Bob's key: %s", userKeys.Body.String())
	}

	adminUsers := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodGet, "/api/v1/usage/scope/users", "")
	if adminUsers.Code != http.StatusOK {
		t.Fatalf("admin users status = %d, body=%s", adminUsers.Code, adminUsers.Body.String())
	}
	assertScopeEnvelope(t, adminUsers.Body.Bytes(), "users", 3, true)

	adminKeys := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodGet, "/api/v1/usage/scope/keys?user_catalog_id="+url.QueryEscape(fixture.ids.AliceUser), "")
	if adminKeys.Code != http.StatusOK {
		t.Fatalf("admin Alice keys status = %d, body=%s", adminKeys.Code, adminKeys.Body.String())
	}
	assertScopeEnvelope(t, adminKeys.Body.Bytes(), "keys", 2, true)
	assertNoEmbeddedUsageSecrets(t, adminKeys.Body.String())
	allAdminKeys := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodGet, "/api/v1/usage/scope/keys", "")
	if allAdminKeys.Code != http.StatusOK {
		t.Fatalf("admin all keys status = %d, body=%s", allAdminKeys.Code, allAdminKeys.Body.String())
	}
	assertScopeEnvelope(t, allAdminKeys.Body.Bytes(), "keys", 3, true)
	if strings.Contains(allAdminKeys.Body.String(), fixture.ids.UnownedKey) {
		t.Fatalf("administrator selector exposed active key with inactive owner: %s", allAdminKeys.Body.String())
	}
	assertEmbeddedStatus(t, fixture.router, fixture.adminToken, "/api/v1/usage/scope/keys?user_catalog_id="+url.QueryEscape(fixture.ids.UnownedUser), http.StatusForbidden)
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, "/api/v1/usage/scope/keys?user_catalog_id="+url.QueryEscape(fixture.ids.BobUser), http.StatusForbidden)
}

func TestIdentityMappingRoutesRequireAdministratorAndAcceptOnlyOpaqueTarget(t *testing.T) {
	fixture := seededEmbeddedUsageRouter(t)
	path := "/api/v1/admin/identity-mappings"
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, path, http.StatusForbidden)
	assertEmbeddedStatus(t, fixture.router, fixture.aliceToken, path+"/"+url.PathEscape(fixture.ids.PendingIdentity), http.StatusForbidden, http.MethodPut, `{"source_user_catalog_id":"`+fixture.ids.CarolUser+`"}`)

	list := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodGet, path, "")
	if list.Code != http.StatusOK {
		t.Fatalf("mapping list status = %d, body=%s", list.Code, list.Body.String())
	}
	assertNoEmbeddedUsageSecrets(t, list.Body.String())
	if !strings.Contains(list.Body.String(), fixture.ids.PendingIdentity) {
		t.Fatalf("mapping list omitted an unmapped persisted identity: %s", list.Body.String())
	}

	updatePath := path + "/" + url.PathEscape(fixture.ids.PendingIdentity)
	bad := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodPut, updatePath, `{"source_user_catalog_id":"`+fixture.ids.CarolUser+`","source_user_ref":"forged"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("mapping update with extra field status = %d, body=%s", bad.Code, bad.Body.String())
	}
	good := performEmbeddedUsageRequest(fixture.router, fixture.adminToken, http.MethodPut, updatePath, `{"source_user_catalog_id":"`+fixture.ids.CarolUser+`"}`)
	if good.Code != http.StatusNoContent {
		t.Fatalf("mapping update status = %d, body=%s", good.Code, good.Body.String())
	}
	link, found, err := fixture.catalog.FindIdentityLink(context.Background(), fixture.ids.PendingIdentity, "litellm")
	if err != nil || !found || link.SourceUserID != fixture.ids.CarolUser {
		t.Fatalf("updated identity link = %#v, found=%v, err=%v", link, found, err)
	}
}

func seededEmbeddedUsageRouter(t *testing.T) embeddedUsageFixture {
	t.Helper()
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "embedded-usage.db")})
	if err != nil {
		t.Fatalf("open embedded usage database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("load embedded usage sql database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })

	ctx := context.Background()
	catalog := repository.NewCatalogRepository(db)
	if err := catalog.ApplySourceSnapshot(ctx, repository.SourceCatalogSnapshot{
		SourceSystem: "litellm",
		SyncedAt:     time.Now().Add(-10 * time.Minute),
		Users: []repository.SourceUserInput{
			{SourceUserRef: "alice", Email: "alice@example.com", DisplayName: "Alice", Active: true},
			{SourceUserRef: "bob", Email: "bob@example.com", DisplayName: "Bob", Active: true},
			{SourceUserRef: "carol", Email: "carol@example.com", DisplayName: "Carol", Active: true},
			{SourceUserRef: "internal-unowned", DisplayName: "Unowned LiteLLM keys", Active: false},
		},
		Keys: []repository.SourceAPIKeyInput{
			{SourceKeyRef: "alice-a", SourceUserRef: "alice", UsageGroupRef: sensitiveGroupA, DisplayName: "Team " + embeddedLegacyRawKey + " legacy", Active: true},
			{SourceKeyRef: "alice-b", SourceUserRef: "alice", UsageGroupRef: sensitiveGroupB, DisplayName: "Team " + embeddedLegacyHash + " legacy", Active: true},
			{SourceKeyRef: "bob-a", SourceUserRef: "bob", UsageGroupRef: sensitiveGroupBob, DisplayName: "Team bob-a legacy", Active: true},
			{SourceKeyRef: "unowned-a", SourceUserRef: "internal-unowned", UsageGroupRef: "internal-unowned-group", DisplayName: "Ownerless", Active: true},
		},
	}); err != nil {
		t.Fatalf("seed source catalog: %v", err)
	}
	access := service.NewIdentityAccessService(catalog, map[string]service.SourceUsageKeyResolver{"litellm": embeddedUsageKeyResolver{}})
	alice, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "alice", Email: "alice@example.com"}, "litellm")
	if err != nil {
		t.Fatalf("resolve Alice: %v", err)
	}
	carol, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "carol", Email: "carol@example.com"}, "litellm")
	if err != nil {
		t.Fatalf("resolve Carol: %v", err)
	}
	admin, err := access.ResolveIdentity(ctx, auth.ExternalPrincipal{Issuer: "issuer", Subject: "admin", IsAdministrator: true}, "litellm")
	if err != nil {
		t.Fatalf("resolve admin: %v", err)
	}
	pending, err := catalog.UpsertExternalIdentity(ctx, "issuer", "pending", "pending@example.com", "Pending Person")
	if err != nil {
		t.Fatalf("seed pending identity: %v", err)
	}

	users, err := catalog.ListActiveSourceUsers(ctx, "litellm")
	if err != nil {
		t.Fatalf("list source users: %v", err)
	}
	keys, err := catalog.ListActiveSourceAPIKeys(ctx, "litellm")
	if err != nil {
		t.Fatalf("list source keys: %v", err)
	}
	ids := embeddedUsageIDs{PendingIdentity: pending.ID}
	for _, user := range users {
		switch user.DisplayName {
		case "Alice":
			ids.AliceUser = user.ID
		case "Bob":
			ids.BobUser = user.ID
		case "Carol":
			ids.CarolUser = user.ID
		}
	}
	for _, key := range keys {
		switch key.UsageGroupRef {
		case sensitiveGroupA:
			ids.AliceKeyA = key.ID
		case sensitiveGroupB:
			ids.AliceKeyB = key.ID
		case sensitiveGroupBob:
			ids.BobKey = key.ID
		case "internal-unowned-group":
			ids.UnownedKey = key.ID
			ids.UnownedUser = key.SourceUserID
		}
	}

	now := time.Now().UTC().Truncate(time.Second)
	seedEmbeddedUsageEvents(t, db, now)
	if err := repository.AggregateUsageOverviewStats(ctx, db, now); err != nil {
		t.Fatalf("aggregate overview: %v", err)
	}
	if err := repository.AggregateUsageActivityStats(ctx, db, now); err != nil {
		t.Fatalf("aggregate activity: %v", err)
	}
	if err := repository.AggregateUsageLatencyStats(ctx, db, now); err != nil {
		t.Fatalf("aggregate latency: %v", err)
	}

	sessions := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	aliceToken := createEmbeddedUsageSession(t, sessions, alice.ExternalIdentityID, auth.RoleUser)
	carolToken := createEmbeddedUsageSession(t, sessions, carol.ExternalIdentityID, auth.RoleUser)
	adminToken := createEmbeddedUsageSession(t, sessions, admin.ExternalIdentityID, auth.RoleAdmin)

	configValue := AuthConfig{Enabled: true, AuthMode: AuthModeEmbeddedJWT, UsageSource: "litellm", SessionTTL: time.Hour}
	usage := service.NewUsageService(db, pricing.NewCatalog(pricing.EmptySnapshot()))
	// Construct a fresh manager/handler after session creation. Route success
	// therefore proves persisted sessions rehydrate policy grants after restart.
	restartedSessions := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	handler := NewAuthHandler(configValue, restartedSessions)
	handler.SetEmbeddedAuth(nil, access, catalog)
	router := NewRouter(nil, nil, usage, nil, configValue, handler, "", OptionalProviders{Status: StatusRouteConfig{UsageSource: "litellm"}})
	return embeddedUsageFixture{router: router, db: db, catalog: catalog, access: access, usage: usage, config: configValue, adminToken: adminToken, aliceToken: aliceToken, carolToken: carolToken, ids: ids}
}

func seedEmbeddedUsageEvents(t *testing.T, db *gorm.DB, now time.Time) {
	t.Helper()
	groups := []struct {
		key    string
		tokens int64
	}{
		{key: sensitiveGroupA, tokens: 10},
		{key: sensitiveGroupB, tokens: 20},
		{key: sensitiveGroupBob, tokens: 40},
		{key: "internal-unowned-group", tokens: 80},
		{key: "litellm:unattributed", tokens: 160},
	}
	events := make([]entities.UsageEvent, 0, len(groups))
	for index, group := range groups {
		ttft := int64(10 + index)
		requestID := fmt.Sprintf("embedded-usage-%d", index)
		events = append(events, entities.UsageEvent{
			EventKey: requestID, RequestID: requestID, SourceSystem: "litellm", APIGroupKey: group.key,
			Model: "model-a", Timestamp: now.Add(-time.Duration(index+1) * time.Minute),
			InputTokens: group.tokens, TotalTokens: group.tokens, TTFTMS: &ttft, LatencyMS: int64(20 + index),
		})
	}
	if _, err := repository.InsertExternalUsageEvents(db, "litellm", events); err != nil {
		t.Fatalf("seed usage events: %v", err)
	}
}

func createEmbeddedUsageSession(t *testing.T, sessions *auth.SessionManager, externalIdentityID string, role auth.Role) string {
	t.Helper()
	token, _, err := sessions.CreateEmbedded(externalIdentityID, role, time.Now().Add(time.Hour), auth.SessionSourceEmbed, auth.SessionClientMetadata{})
	if err != nil {
		t.Fatalf("create embedded %s session: %v", role, err)
	}
	return token
}

type embeddedUsageKeyResolver struct{}

func (embeddedUsageKeyResolver) ResolveAPIGroupKeys(_ context.Context, _ string, keys []entities.SourceAPIKey) ([]string, error) {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key.UsageGroupRef)
	}
	return values, nil
}

func performEmbeddedUsageRequest(handler http.Handler, token, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set(embeddedSessionHeader, token)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set(requestIntentHeader, "fetch")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertEmbeddedStatus(t *testing.T, handler http.Handler, token, path string, want int, optional ...any) {
	t.Helper()
	method, body := http.MethodGet, ""
	if len(optional) > 0 {
		method = optional[0].(string)
	}
	if len(optional) > 1 {
		body = optional[1].(string)
	}
	response := performEmbeddedUsageRequest(handler, token, method, path, body)
	if response.Code != want {
		t.Fatalf("%s %s status = %d, want %d, body=%s", method, path, response.Code, want, response.Body.String())
	}
}

func assertEmbeddedTokens(t *testing.T, handler http.Handler, token, path string, want int64) {
	t.Helper()
	response := performEmbeddedUsageRequest(handler, token, http.MethodGet, path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, body=%s", path, response.Code, response.Body.String())
	}
	var payload struct {
		Usage struct {
			TotalTokens int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode overview response: %v", err)
	}
	if payload.Usage.TotalTokens != want {
		t.Fatalf("GET %s total tokens = %d, want %d, body=%s", path, payload.Usage.TotalTokens, want, response.Body.String())
	}
	assertNoEmbeddedUsageSecrets(t, response.Body.String())
}

func assertEmbeddedAnalysisTokens(t *testing.T, handler http.Handler, token, path string, want int64) {
	t.Helper()
	response := performEmbeddedUsageRequest(handler, token, http.MethodGet, path, "")
	if response.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, body=%s", path, response.Code, response.Body.String())
	}
	var payload struct {
		TokenUsage []struct {
			TotalTokens int64 `json:"total_tokens"`
		} `json:"token_usage"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode analysis response: %v", err)
	}
	var total int64
	for _, bucket := range payload.TokenUsage {
		total += bucket.TotalTokens
	}
	if total != want {
		t.Fatalf("GET %s total tokens = %d, want %d, body=%s", path, total, want, response.Body.String())
	}
	assertNoEmbeddedUsageSecrets(t, response.Body.String())
}

func assertScopeEnvelope(t *testing.T, body []byte, field string, wantItems int, wantStale bool) {
	t.Helper()
	var payload struct {
		SourceSystem string `json:"source_system"`
		SyncedAt     string `json:"synced_at"`
		Stale        bool   `json:"stale"`
		Users        []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"users"`
		Keys []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode scope response: %v", err)
	}
	items := payload.Users
	if field == "keys" {
		items = payload.Keys
	}
	if payload.SourceSystem != "litellm" || payload.SyncedAt == "" || payload.Stale != wantStale || len(items) != wantItems {
		t.Fatalf("unexpected %s scope envelope: %s", field, body)
	}
	for _, item := range items {
		if item.ID == "" || item.Label == "" {
			t.Fatalf("scope item must contain only usable opaque id/label values: %s", body)
		}
	}
	assertNoEmbeddedUsageSecrets(t, string(body))
}

func assertNoEmbeddedUsageSecrets(t *testing.T, body string) {
	t.Helper()
	for _, forbidden := range []string{
		sensitiveGroupA, sensitiveGroupB, sensitiveGroupBob,
		"internal-unowned-group", "litellm:unattributed",
		"alice-a", "alice-b", "bob-a",
		embeddedLegacyRawKey, embeddedLegacyHash,
		strings.Repeat("a", 64), strings.Repeat("b", 64),
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response exposed canonical/source key material %q: %s", forbidden, body)
		}
	}
}

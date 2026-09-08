package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/repository"
	"cpa-usage-keeper/internal/service"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const embeddedTestAssertion = "eyJ.secret.assertion"

type embeddedVerifierStub struct {
	want      string
	principal auth.ExternalPrincipal
	err       error
	calls     int
}

func (v *embeddedVerifierStub) Verify(_ context.Context, assertion string) (auth.ExternalPrincipal, error) {
	v.calls++
	if v.err != nil || assertion != v.want {
		return auth.ExternalPrincipal{}, auth.ErrInvalidIdentityAssertion
	}
	return v.principal, nil
}

type embeddedKeyResolverStub struct{}

func (embeddedKeyResolverStub) ResolveAPIGroupKeys(context.Context, string, []entities.SourceAPIKey) ([]string, error) {
	return nil, nil
}

func TestSSOExchangeCreatesBoundedUserSessionWithoutPersistingJWT(t *testing.T) {
	now := time.Now().UTC()
	router, sessions, db := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "user-1", Email: "alice@example.com", DisplayName: "Alice", AssertionExpiresAt: now.Add(30 * time.Minute),
	}, true, true)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sso/exchange", strings.NewReader("assertion="+url.QueryEscape(embeddedTestAssertion)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/overview" {
		t.Fatalf("exchange response = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one embedded session cookie, got %+v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != embedSessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteNoneMode || !cookie.Partitioned {
		t.Fatalf("embedded session cookie is not cross-site secure: %+v", cookie)
	}
	session, ok := sessions.Get(cookie.Value)
	if !ok || session.Role != auth.RoleUser || session.ExternalIdentityID == "" || !session.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("unexpected bounded user session: %+v, found=%v", session, ok)
	}
	dump, err := json.Marshal(struct {
		Sessions   []entities.AuthSession
		Identities []entities.ExternalIdentity
	}{Sessions: loadEmbeddedSessionRows(t, db), Identities: loadExternalIdentityRows(t, db)})
	if err != nil {
		t.Fatalf("marshal persisted auth state: %v", err)
	}
	if strings.Contains(string(dump), embeddedTestAssertion) || strings.Contains(response.Body.String(), embeddedTestAssertion) {
		t.Fatal("raw JWT escaped into persistence or response")
	}
	redactedBody, err := io.ReadAll(request.Body)
	if err != nil || len(redactedBody) != 0 || request.Form.Get("assertion") != "" || request.PostForm.Get("assertion") != "" {
		t.Fatalf("exchange request body was retained: body=%q form=%q postForm=%q err=%v", redactedBody, request.Form.Get("assertion"), request.PostForm.Get("assertion"), err)
	}

	bootstrap := httptest.NewRecorder()
	bootstrapRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	bootstrapRequest.AddCookie(cookie)
	router.ServeHTTP(bootstrap, bootstrapRequest)
	if bootstrap.Code != http.StatusOK || !strings.Contains(bootstrap.Body.String(), `"authenticated":true`) || !strings.Contains(bootstrap.Body.String(), `"role":"user"`) || !strings.Contains(bootstrap.Body.String(), `"auth_mode":"embedded_jwt"`) {
		t.Fatalf("unexpected embedded session bootstrap: %d %s", bootstrap.Code, bootstrap.Body.String())
	}

	logout := httptest.NewRecorder()
	logoutRequest := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutRequest.Header.Set(requestIntentHeaderName, requestIntentHeaderValueFetch)
	logoutRequest.AddCookie(cookie)
	router.ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent || sessions.Validate(cookie.Value) {
		t.Fatalf("embedded logout failed: status=%d session_valid=%v", logout.Code, sessions.Validate(cookie.Value))
	}
	cleared := logout.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != embedSessionCookieName || cleared[0].MaxAge >= 0 || !cleared[0].Secure || !cleared[0].Partitioned {
		t.Fatalf("embedded logout did not clear the secure cookie: %+v", cleared)
	}
}

func TestSSOExchangeAcceptsJSONAndReturnsSessionResponse(t *testing.T) {
	router, _, _ := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "admin-1", IsAdministrator: true, AssertionExpiresAt: time.Now().Add(time.Hour),
	}, true, false)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sso/exchange", strings.NewReader(`{"assertion":"`+embeddedTestAssertion+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authenticated":true`) || !strings.Contains(response.Body.String(), `"role":"admin"`) || !strings.Contains(response.Body.String(), `"auth_mode":"embedded_jwt"`) {
		t.Fatalf("unexpected JSON exchange response: %d %s", response.Code, response.Body.String())
	}
	if len(response.Result().Cookies()) != 1 {
		t.Fatalf("JSON exchange did not set a session cookie: %+v", response.Result().Cookies())
	}
}

func TestSSOExchangeRedactsOversizedRequestBeforeHandler(t *testing.T) {
	router, _, _ := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "admin-1", IsAdministrator: true, AssertionExpiresAt: time.Now().Add(time.Hour),
	}, true, false)
	raw := embeddedTestAssertion + strings.Repeat("x", int(unauthenticatedLoginBodyLimit))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sso/exchange", strings.NewReader("assertion="+url.QueryEscape(raw)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized exchange response = %d %s", response.Code, response.Body.String())
	}
	retained, err := io.ReadAll(request.Body)
	if err != nil || len(retained) != 0 || request.Form.Get("assertion") != "" || request.PostForm.Get("assertion") != "" {
		t.Fatalf("oversized exchange retained request material: body_bytes=%d form_present=%v post_form_present=%v err=%v", len(retained), request.Form.Get("assertion") != "", request.PostForm.Get("assertion") != "", err)
	}
}

func TestSSOExchangeRejectsUnavailableCatalogBeforePersistingIdentity(t *testing.T) {
	router, _, db := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "user-1", Email: "alice@example.com", AssertionExpiresAt: time.Now().Add(time.Hour),
	}, false, false)
	response := performEmbeddedExchange(router, embeddedTestAssertion)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"error":"catalog_unavailable"`) {
		t.Fatalf("catalog-not-ready response = %d %s", response.Code, response.Body.String())
	}
	if identities := loadExternalIdentityRows(t, db); len(identities) != 0 {
		t.Fatalf("catalog-not-ready exchange persisted identities: %+v", identities)
	}
}

func TestSSOExchangePersistsIdentityBeforeReturningMappingRequired(t *testing.T) {
	router, sessions, db := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "user-unmapped", Email: "nobody@example.com", DisplayName: "Unmapped", AssertionExpiresAt: time.Now().Add(time.Hour),
	}, true, false)
	response := performEmbeddedExchange(router, embeddedTestAssertion)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"error":"mapping_required"`) {
		t.Fatalf("mapping-required response = %d %s", response.Code, response.Body.String())
	}
	identities := loadExternalIdentityRows(t, db)
	if len(identities) != 1 || identities[0].Subject != "user-unmapped" {
		t.Fatalf("verified identity was not retained for administrator repair: %+v", identities)
	}
	if len(sessions.List()) != 0 {
		t.Fatalf("mapping failure created a session: %+v", sessions.List())
	}
}

func TestSSOExchangeAllowsAdministratorWithoutSourceLink(t *testing.T) {
	router, sessions, _ := embeddedAuthRouter(t, auth.ExternalPrincipal{
		Issuer: "https://webui.example.com", Subject: "admin-no-link", IsAdministrator: true, AssertionExpiresAt: time.Now().Add(time.Hour),
	}, true, false)
	response := performEmbeddedExchange(router, embeddedTestAssertion)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/analysis" {
		t.Fatalf("admin exchange response = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if records := sessions.List(); len(records) != 1 || records[0].Role != auth.RoleAdmin {
		t.Fatalf("admin exchange did not create an admin session: %+v", records)
	}
}

func TestEmbeddedAndStandaloneAuthRoutesAreModeGated(t *testing.T) {
	embeddedRouter, _, _ := embeddedAuthRouter(t, auth.ExternalPrincipal{Issuer: "issuer", Subject: "admin", IsAdministrator: true, AssertionExpiresAt: time.Now().Add(time.Hour)}, true, false)
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/api/v1/auth/login"}, {http.MethodPost, "/api/v1/auth/api-key-login"}} {
		if hasEmbeddedAuthRoute(embeddedRouter.Routes(), route.method, route.path) {
			t.Fatalf("embedded mode registered standalone route %s %s", route.method, route.path)
		}
	}
	if !hasEmbeddedAuthRoute(embeddedRouter.Routes(), http.MethodPost, "/api/v1/auth/sso/exchange") {
		t.Fatal("embedded mode did not register SSO exchange")
	}

	config := AuthConfig{Enabled: true, AuthMode: AuthModeStandalone, LoginPassword: "secret", SessionTTL: time.Hour}
	standalone := NewRouter(nil, nil, nil, nil, config, NewAuthHandler(config, auth.NewSessionManager(time.Hour)), "", OptionalProviders{Status: StatusRouteConfig{UsageSource: "litellm", Capabilities: SourceCapabilitiesForUsageSource("litellm")}})
	if hasEmbeddedAuthRoute(standalone.Routes(), http.MethodPost, "/api/v1/auth/sso/exchange") {
		t.Fatal("standalone mode registered SSO exchange")
	}
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/api/v1/auth/login"}, {http.MethodPost, "/api/v1/auth/api-key-login"}} {
		if !hasEmbeddedAuthRoute(standalone.Routes(), route.method, route.path) {
			t.Fatalf("standalone mode omitted route %s %s", route.method, route.path)
		}
	}
	bootstrap := httptest.NewRecorder()
	standalone.ServeHTTP(bootstrap, httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil))
	if !strings.Contains(bootstrap.Body.String(), `"auth_mode":"standalone"`) {
		t.Fatalf("standalone bootstrap omitted auth mode: %s", bootstrap.Body.String())
	}
}

func TestEmbeddedTaskSanitizesLegacyLiteLLMDisplayNameWithoutInvalidatingSession(t *testing.T) {
	legacyHash := strings.Repeat("a", 64)
	principal := auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:lkey-safeopaqueprincipal", DisplayName: legacyHash}
	sessions := auth.NewSessionManager(time.Hour)
	token, _, err := sessions.CreateAPIKeyViewerForPrincipalWithSourceAndMetadata(principal, auth.SessionSourceStandard, auth.SessionClientMetadata{})
	if err != nil {
		t.Fatalf("create legacy viewer session: %v", err)
	}
	config := AuthConfig{Enabled: true, AuthMode: AuthModeStandalone, SessionTTL: time.Hour, ViewerKeyRevalidationTTL: time.Minute}
	validator := &authViewerKeyAdapterStub{principal: principal}
	handler := NewAuthHandler(config, sessions)
	handler.SetViewerKeyAuthenticator(validator, validator)
	router := NewRouter(nil, nil, nil, nil, config, handler, "", OptionalProviders{Status: StatusRouteConfig{UsageSource: "litellm", Capabilities: SourceCapabilitiesForUsageSource("litellm")}})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authenticated":true`) || !strings.Contains(response.Body.String(), `"display_key":"LiteLLM key"`) {
		t.Fatalf("legacy session was rejected instead of sanitized: status=%d", response.Code)
	}
	if strings.Contains(response.Body.String(), legacyHash) || !sessions.Validate(token) {
		t.Fatal("legacy display identity leaked or its valid session was deleted")
	}
}

func embeddedAuthRouter(t *testing.T, principal auth.ExternalPrincipal, catalogReady, matchingUser bool) (*gin.Engine, *auth.SessionManager, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+url.QueryEscape(t.Name())+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open embedded auth database: %v", err)
	}
	if err := db.AutoMigrate(entities.All()...); err != nil {
		t.Fatalf("migrate embedded auth database: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("load embedded auth sql database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	catalog := repository.NewCatalogRepository(db)
	if catalogReady {
		email := "different@example.com"
		if matchingUser {
			email = principal.Email
		}
		if err := catalog.ApplySourceSnapshot(context.Background(), repository.SourceCatalogSnapshot{
			SourceSystem: "litellm", SyncedAt: time.Now(), Users: []repository.SourceUserInput{{SourceUserRef: "source-user-1", Email: email, DisplayName: "Alice", Active: true}},
		}); err != nil {
			t.Fatalf("seed source catalog: %v", err)
		}
	}
	access := service.NewIdentityAccessService(catalog, map[string]service.SourceUsageKeyResolver{"litellm": embeddedKeyResolverStub{}})
	sessions := auth.NewPersistentSessionManager(2*time.Hour, auth.NewGormSessionStore(db))
	config := AuthConfig{Enabled: true, AuthMode: AuthModeEmbeddedJWT, UsageSource: "litellm", SessionTTL: 2 * time.Hour}
	handler := NewAuthHandler(config, sessions)
	handler.SetEmbeddedAuth(&embeddedVerifierStub{want: embeddedTestAssertion, principal: principal}, access, catalog)
	capabilities := SourceCapabilitiesForAuthMode(SourceCapabilitiesForUsageSource("litellm"), AuthModeEmbeddedJWT)
	router := NewRouter(nil, nil, nil, nil, config, handler, "", OptionalProviders{Status: StatusRouteConfig{UsageSource: "litellm", Capabilities: capabilities}})
	return router, sessions, db
}

func performEmbeddedExchange(router http.Handler, assertion string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sso/exchange", strings.NewReader("assertion="+url.QueryEscape(assertion)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func loadEmbeddedSessionRows(t *testing.T, db *gorm.DB) []entities.AuthSession {
	t.Helper()
	var rows []entities.AuthSession
	if err := db.Order("token_hash").Find(&rows).Error; err != nil {
		t.Fatalf("load embedded sessions: %v", err)
	}
	return rows
}

func loadExternalIdentityRows(t *testing.T, db *gorm.DB) []entities.ExternalIdentity {
	t.Helper()
	var rows []entities.ExternalIdentity
	if err := db.Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("load external identities: %v", err)
	}
	return rows
}

func hasEmbeddedAuthRoute(routes []gin.RouteInfo, method, path string) bool {
	for _, route := range routes {
		if route.Method == method && route.Path == path {
			return true
		}
	}
	return false
}

var _ auth.EmbeddedIdentityVerifier = (*embeddedVerifierStub)(nil)
var _ service.SourceUsageKeyResolver = embeddedKeyResolverStub{}

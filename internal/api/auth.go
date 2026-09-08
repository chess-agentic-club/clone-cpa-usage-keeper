package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/helper"
	"cpa-usage-keeper/internal/service"
	servicedto "cpa-usage-keeper/internal/service/dto"
	"github.com/gin-gonic/gin"
)

const (
	sessionCookieName         = "cpa_usage_keeper_session"
	embedSessionCookieName    = "cpa_usage_keeper_embed_session"
	authTokenContextKey       = "auth_token"
	authSessionContextKey     = "auth_session"
	authResolvedContextKey    = "auth_resolved_session"
	activeViewerKeyContextKey = "active_viewer_api_key"

	embedHeaderName               = "X-CPA-Usage-Keeper-Embed"
	embedHeaderValueCPAMC         = "cpamc"
	embedSessionHeaderName        = "X-CPA-Usage-Keeper-Embed-Session"
	requestIntentHeaderName       = "X-CPA-Usage-Keeper-Request"
	requestIntentHeaderValueFetch = "fetch"
)

const (
	maxFailedLoginAttempts = 5
	loginAttemptWindow     = time.Minute
	loginAttemptGlobalMax  = 60
	loginAttemptSourceMax  = 4096
)

type AuthConfig struct {
	Enabled                         bool
	AuthMode                        string
	UsageSource                     string
	LoginPassword                   string
	SessionTTL                      time.Duration
	BasePath                        string
	FrameAncestorOrigins            []string
	TrustedProxyCIDRs               []string
	APIKeyViewerLocalRankingEnabled bool
	ViewerKeyRevalidationTTL        time.Duration
}

type authHandler struct {
	config                   AuthConfig
	capabilities             SourceCapabilities
	sessions                 *auth.SessionManager
	legacyCPAAPIKeyProvider  service.CPAAPIKeyProvider
	viewerKeyAuthenticator   auth.ViewerKeyAuthenticator
	viewerPrincipalValidator auth.ViewerPrincipalValidator
	viewerPrincipalResolver  auth.ViewerPrincipalResolver
	viewerValidationCache    *auth.ViewerPrincipalValidationCache
	loginAttempts            *auth.LoginAttemptLimiter
	embeddedVerifier         auth.EmbeddedIdentityVerifier
	usageAccess              service.UsageAccessProvider
	catalogState             CatalogStateProvider
}

// CatalogStateProvider exposes only the last committed source-catalog state.
// A missing or unreadable state fails SSO exchange closed.
type CatalogStateProvider interface {
	CatalogSyncState(context.Context, string) (entities.SourceCatalogSyncState, error)
}

type loginRequest struct {
	Password string `json:"password"`
}

type apiKeyLoginRequest struct {
	APIKey string `json:"apiKey"`
}

type sessionResponse struct {
	Authenticated bool                   `json:"authenticated"`
	Role          auth.Role              `json:"role,omitempty"`
	APIKey        *sessionAPIKeyResponse `json:"api_key,omitempty"`
	Capabilities  SourceCapabilities     `json:"capabilities"`
	AuthMode      string                 `json:"auth_mode"`
}

type sessionAPIKeyResponse struct {
	DisplayKey          string `json:"display_key"`
	Alias               string `json:"alias,omitempty"`
	LocalRankingEnabled bool   `json:"local_ranking_enabled,omitempty"`
}

type loginResponse struct {
	SessionToken string `json:"session_token,omitempty"`
}

type sessionCookieKind string

const (
	sessionCookieKindStandard sessionCookieKind = "standard"
	sessionCookieKindEmbed    sessionCookieKind = "embed"
)

type sessionTokenTransport string

const (
	sessionTokenTransportCookie sessionTokenTransport = "cookie"
	sessionTokenTransportHeader sessionTokenTransport = "header"
)

type resolvedSessionToken struct {
	Token      string
	CookieKind sessionCookieKind
	Source     auth.SessionSource
	Transport  sessionTokenTransport
}

func NewAuthHandler(config AuthConfig, sessions *auth.SessionManager) *authHandler {
	config.AuthMode = normalizeAuthMode(config.AuthMode)
	return &authHandler{
		config:                config,
		sessions:              sessions,
		viewerValidationCache: auth.NewViewerPrincipalValidationCache(config.ViewerKeyRevalidationTTL),
		loginAttempts: auth.NewLoginAttemptLimiter(auth.LoginAttemptLimiterOptions{
			Window:         loginAttemptWindow,
			PerSourceLimit: maxFailedLoginAttempts,
			GlobalLimit:    loginAttemptGlobalMax,
			MaxSources:     loginAttemptSourceMax,
		}),
	}
}

// SetEmbeddedAuth configures the verified-identity exchange boundary. Raw
// assertions are consumed only by the verifier and are never retained here.
func (h *authHandler) SetEmbeddedAuth(verifier auth.EmbeddedIdentityVerifier, access service.UsageAccessProvider, catalogState CatalogStateProvider) {
	if h == nil {
		return
	}
	h.embeddedVerifier = verifier
	h.usageAccess = access
	h.catalogState = catalogState
}

func (h *authHandler) setCPAAPIKeyProvider(provider service.CPAAPIKeyProvider) {
	if h != nil {
		h.legacyCPAAPIKeyProvider = provider
	}
}

// SetViewerKeyAuthenticator configures the selected source's login and
// revalidation adapter. It deliberately accepts only non-secret principals.
func (h *authHandler) SetViewerKeyAuthenticator(authenticator auth.ViewerKeyAuthenticator, validator auth.ViewerPrincipalValidator) {
	h.setViewerKeyAuthenticator(authenticator, validator)
}

func (h *authHandler) setViewerKeyAuthenticator(authenticator auth.ViewerKeyAuthenticator, validator auth.ViewerPrincipalValidator) {
	if h == nil {
		return
	}
	h.viewerKeyAuthenticator = authenticator
	h.viewerPrincipalValidator = validator
	h.viewerPrincipalResolver, _ = authenticator.(auth.ViewerPrincipalResolver)
}

func (h *authHandler) registerRoutes(router gin.IRoutes, capabilities SourceCapabilities) {
	h.capabilities = SourceCapabilitiesForAuthMode(capabilities, h.config.AuthMode)
	router.GET("/session", h.getSession)
	if h.config.AuthMode == AuthModeEmbeddedJWT {
		router.POST("/sso/exchange", h.ssoExchange)
	} else {
		router.POST("/login", h.login)
		if h.capabilities.ViewerKeyLogin {
			router.POST("/api-key-login", h.apiKeyLogin)
		}
	}
	router.POST("/logout", h.logout)
}

func (h *authHandler) middleware() gin.HandlerFunc {
	return h.roleMiddleware()
}

func (h *authHandler) adminMiddleware() gin.HandlerFunc {
	return h.roleMiddleware(auth.RoleAdmin)
}

func (h *authHandler) apiKeyViewerMiddleware() gin.HandlerFunc {
	return h.roleMiddleware(auth.RoleAPIKeyViewer)
}

func (h *authHandler) roleMiddleware(allowedRoles ...auth.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || !h.config.Enabled {
			c.Next()
			return
		}
		if h.sessions == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}

		resolved, session, ok := h.resolveValidSession(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		if len(allowedRoles) > 0 && !sessionRoleAllowed(session.Role, allowedRoles) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.Set(authTokenContextKey, resolved.Token)
		c.Set(authSessionContextKey, session)
		c.Set(authResolvedContextKey, resolved)
		h.sessions.Touch(resolved.Token, sessionClientIP(c))
		c.Next()
	}
}

func (h *authHandler) activeAPIKeyViewerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if h == nil || !h.config.Enabled {
			c.Next()
			return
		}
		resolvedValue, hasResolved := c.Get(authResolvedContextKey)
		resolved, resolvedOK := resolvedValue.(resolvedSessionToken)
		sessionValue, hasSession := c.Get(authSessionContextKey)
		session, sessionOK := sessionValue.(auth.Session)
		if !hasResolved || !resolvedOK || !hasSession || !sessionOK || session.Role != auth.RoleAPIKeyViewer {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		// Principal-only sessions were already revalidated by roleMiddleware.
		// Their source-specific usage scope is applied in Task 5, so they must
		// not be forced through the legacy CPA API-key lookup here.
		if session.CPAAPIKeyID == 0 {
			principal, principalOK := ViewerScopeFromSession(session)
			if !principalOK {
				h.deleteSession(resolved.Token)
				clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
				return
			}
			if h.viewerPrincipalResolver != nil {
				principal, err := h.viewerPrincipalResolver.ResolveViewerPrincipal(c.Request.Context(), principal)
				if err != nil {
					h.deleteSession(resolved.Token)
					clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
					return
				}
				session.ViewerSourceSystem = principal.SourceSystem
				session.ViewerAPIGroupKey = principal.APIGroupKey
				session.ViewerDisplayName = principal.DisplayName
			}
			c.Set(authSessionContextKey, session)
			c.Next()
			return
		}
		row, ok := h.activeViewerAPIKey(c, resolved, session)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		// Normalize legacy CPA sessions into the same trusted principal shape as
		// source-scoped sessions. The canonical analytics key comes from the
		// active server-side CPA row, never from request query parameters.
		session.ViewerSourceSystem = "legacy"
		session.ViewerAPIGroupKey = row.APIKey
		if strings.TrimSpace(session.ViewerAPIGroupKey) == "" {
			session.ViewerAPIGroupKey = strconv.FormatInt(row.ID, 10)
		}
		session.ViewerDisplayName = helper.CPAAPIKeyDisplayName(row)
		c.Set(authSessionContextKey, session)
		c.Set(activeViewerKeyContextKey, row)
		c.Next()
	}
}

// ViewerScopeFromSession returns the trusted, non-secret principal persisted
// in a viewer session. Legacy CPA sessions are enriched by the viewer
// middleware before dashboard handlers consume this helper.
func ViewerScopeFromSession(session auth.Session) (auth.ViewerPrincipal, bool) {
	if session.Role != auth.RoleAPIKeyViewer {
		return auth.ViewerPrincipal{}, false
	}
	principal, err := auth.NormalizeViewerPrincipal(auth.ViewerPrincipal{
		SourceSystem: session.ViewerSourceSystem,
		APIGroupKey:  session.ViewerAPIGroupKey,
		DisplayName:  session.ViewerDisplayName,
	})
	if err != nil {
		return auth.ViewerPrincipal{}, false
	}
	return principal, true
}

func viewerScopeFromContext(c *gin.Context) (auth.ViewerPrincipal, auth.Session, bool) {
	if c == nil {
		return auth.ViewerPrincipal{}, auth.Session{}, false
	}
	sessionValue, ok := c.Get(authSessionContextKey)
	if !ok {
		return auth.ViewerPrincipal{}, auth.Session{}, false
	}
	session, ok := sessionValue.(auth.Session)
	if !ok {
		return auth.ViewerPrincipal{}, auth.Session{}, false
	}
	principal, ok := ViewerScopeFromSession(session)
	if !ok {
		return auth.ViewerPrincipal{}, auth.Session{}, false
	}
	return principal, session, true
}

func applyViewerScope(filter *servicedto.UsageFilter, principal auth.ViewerPrincipal, session auth.Session) {
	if filter == nil {
		return
	}
	filter.APIGroupKey = principal.APIGroupKey
	// Preserve the legacy internal identifier for compatibility with response
	// labels; the service always gives APIGroupKey precedence over this field.
	if session.CPAAPIKeyID > 0 {
		filter.APIKeyID = strconv.FormatInt(session.CPAAPIKeyID, 10)
	} else {
		filter.APIKeyID = ""
	}
}

func activeAPIKeyViewerContext(c *gin.Context) (auth.Session, entities.CPAAPIKey, bool) {
	if c == nil {
		return auth.Session{}, entities.CPAAPIKey{}, false
	}
	sessionValue, hasSession := c.Get(authSessionContextKey)
	session, sessionOK := sessionValue.(auth.Session)
	keyValue, hasKey := c.Get(activeViewerKeyContextKey)
	key, keyOK := keyValue.(entities.CPAAPIKey)
	if !hasSession || !sessionOK || !hasKey || !keyOK || session.CPAAPIKeyID <= 0 || session.CPAAPIKeyID != key.ID {
		return auth.Session{}, entities.CPAAPIKey{}, false
	}
	return session, key, true
}

func sessionRoleAllowed(role auth.Role, allowedRoles []auth.Role) bool {
	for _, allowed := range allowedRoles {
		if role == allowed {
			return true
		}
	}
	return false
}

func sessionMatchesResolvedSource(session auth.Session, resolved resolvedSessionToken) bool {
	return auth.NormalizeSessionSource(session.Source) == resolved.Source
}

func (h *authHandler) resolveValidSession(c *gin.Context) (resolvedSessionToken, auth.Session, bool) {
	for _, resolved := range h.resolveSessionTokenCandidates(c) {
		if resolved.Token == "" {
			continue
		}
		session, ok := h.sessions.Get(resolved.Token)
		if !ok {
			h.deleteSession(resolved.Token)
			if resolved.Transport == sessionTokenTransportCookie {
				clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
			}
			continue
		}
		if !sessionMatchesResolvedSource(session, resolved) {
			if resolved.Transport == sessionTokenTransportCookie {
				clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
			}
			continue
		}
		if !h.validateViewerSession(c, session) {
			h.deleteSession(resolved.Token)
			if resolved.Transport == sessionTokenTransportCookie {
				clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
			}
			continue
		}
		return resolved, session, true
	}
	return h.resolveSessionToken(c), auth.Session{}, false
}

func (h *authHandler) getSession(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusOK, sessionResponse{Authenticated: true, Role: auth.RoleAdmin, AuthMode: AuthModeStandalone})
		return
	}
	if !h.config.Enabled {
		c.JSON(http.StatusOK, sessionResponse{Authenticated: true, Role: auth.RoleAdmin, Capabilities: h.capabilities, AuthMode: h.config.AuthMode})
		return
	}
	if h.sessions == nil {
		c.JSON(http.StatusOK, sessionResponse{Authenticated: false, Capabilities: h.capabilities, AuthMode: h.config.AuthMode})
		return
	}

	resolved, session, ok := h.resolveValidSession(c)
	if !ok {
		c.JSON(http.StatusOK, sessionResponse{Authenticated: false, Capabilities: h.capabilities, AuthMode: h.config.AuthMode})
		return
	}
	response := sessionResponse{Authenticated: true, Role: session.Role, Capabilities: h.capabilities, AuthMode: h.config.AuthMode}
	if session.Role == auth.RoleAPIKeyViewer {
		if session.CPAAPIKeyID > 0 {
			row, ok := h.activeViewerAPIKey(c, resolved, session)
			if !ok {
				c.JSON(http.StatusOK, sessionResponse{Authenticated: false, Capabilities: h.capabilities, AuthMode: h.config.AuthMode})
				return
			}
			response.APIKey = &sessionAPIKeyResponse{
				DisplayKey:          helper.CPAAPIKeyMaskedDisplayKey(row),
				Alias:               row.KeyAlias,
				LocalRankingEnabled: h.config.APIKeyViewerLocalRankingEnabled,
			}
		} else {
			response.APIKey = &sessionAPIKeyResponse{
				DisplayKey:          sanitizedViewerDisplayName(session.ViewerSourceSystem, session.ViewerAPIGroupKey, session.ViewerDisplayName),
				LocalRankingEnabled: h.config.APIKeyViewerLocalRankingEnabled,
			}
		}
	}
	c.JSON(http.StatusOK, response)
}

func sanitizedViewerDisplayName(sourceSystem, apiGroupKey, displayName string) string {
	sourceSystem = strings.TrimSpace(sourceSystem)
	apiGroupKey = strings.TrimSpace(apiGroupKey)
	displayName = strings.TrimSpace(displayName)
	fallback := "API Key Viewer"
	if sourceSystem == "litellm" {
		fallback = "LiteLLM key"
	}
	if displayName == "" || displayName == apiGroupKey {
		return fallback
	}
	if sourceSystem == "litellm" && (strings.HasPrefix(strings.ToLower(displayName), "sk-") || strings.HasPrefix(strings.ToLower(displayName), "litellm:") || isHexCredential(displayName)) {
		return fallback
	}
	return displayName
}

func isHexCredential(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func (h *authHandler) login(c *gin.Context) {
	if h == nil || !h.config.Enabled {
		c.Status(http.StatusNoContent)
		return
	}
	if h.sessions == nil {
		writeInternalError(c, "session manager is not configured", nil)
		return
	}
	clientKey := loginClientKey(c)
	if !h.allowLoginAttempt(c, clientKey) {
		return
	}

	var request loginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		if isRequestEntityTooLarge(err) {
			writeRequestEntityTooLarge(c)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	passwordMatches := subtle.ConstantTimeCompare([]byte(request.Password), []byte(h.config.LoginPassword)) == 1
	if !passwordMatches {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}
	h.loginAttempts.Reset(clientKey)

	resolved := h.resolveSessionToken(c)
	token, expiresAt, err := h.sessions.CreateWithSourceAndMetadata(resolved.Source, sessionClientMetadata(c))
	if err != nil {
		writeInternalError(c, "create auth session failed", err)
		return
	}

	setSessionCookie(c, h.config.BasePath, resolved.CookieKind, token, expiresAt)
	writeLoginSuccess(c, resolved, token)
}

func (h *authHandler) apiKeyLogin(c *gin.Context) {
	if h == nil || !h.config.Enabled {
		c.Status(http.StatusNoContent)
		return
	}
	if h.sessions == nil || h.viewerKeyAuthenticator == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	clientKey := loginClientKey(c)
	if !h.allowLoginAttempt(c, clientKey) {
		return
	}
	var request apiKeyLoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		if isRequestEntityTooLarge(err) {
			writeRequestEntityTooLarge(c)
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	principal, err := h.viewerKeyAuthenticator.AuthenticateViewerKey(c.Request.Context(), request.APIKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	revalidationRef := ""
	if provider, ok := h.viewerKeyAuthenticator.(auth.ViewerPrincipalReferenceProvider); ok {
		revalidationRef, err = provider.CreateViewerPrincipalReference(principal)
		if err != nil {
			writeInternalError(c, "create viewer revalidation reference failed", err)
			return
		}
	}
	h.loginAttempts.Reset(clientKey)
	resolved := h.resolveSessionToken(c)
	token, expiresAt, err := h.sessions.CreateAPIKeyViewerForPrincipalWithRevalidationRefAndSourceAndMetadata(principal, revalidationRef, resolved.Source, sessionClientMetadata(c))
	if err != nil {
		writeInternalError(c, "create api key viewer session failed", err)
		return
	}
	setSessionCookie(c, h.config.BasePath, resolved.CookieKind, token, expiresAt)
	writeLoginSuccess(c, resolved, token)
}

func (h *authHandler) activeViewerAPIKey(c *gin.Context, resolved resolvedSessionToken, session auth.Session) (entities.CPAAPIKey, bool) {
	if h.legacyCPAAPIKeyProvider == nil || session.CPAAPIKeyID <= 0 {
		h.deleteSession(resolved.Token)
		clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
		return entities.CPAAPIKey{}, false
	}
	row, err := h.legacyCPAAPIKeyProvider.FindActiveCPAAPIKeyByID(c.Request.Context(), session.CPAAPIKeyID)
	if err != nil {
		h.deleteSession(resolved.Token)
		clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
		return entities.CPAAPIKey{}, false
	}
	return row, true
}

func (h *authHandler) validateViewerSession(c *gin.Context, session auth.Session) bool {
	if session.Role != auth.RoleAPIKeyViewer {
		return true
	}
	if session.CPAAPIKeyID > 0 {
		// Some compatibility-only routes (such as version) are constructed
		// without a CPA provider. Preserve established legacy session behavior
		// there; routes that require the active key still enforce it below.
		if h.legacyCPAAPIKeyProvider == nil {
			return true
		}
		_, err := h.legacyCPAAPIKeyProvider.FindActiveCPAAPIKeyByID(c.Request.Context(), session.CPAAPIKeyID)
		return err == nil
	}
	principal := auth.ViewerPrincipal{
		SourceSystem: session.ViewerSourceSystem,
		APIGroupKey:  session.ViewerAPIGroupKey,
		DisplayName:  session.ViewerDisplayName,
	}
	if h.viewerValidationCache == nil {
		h.viewerValidationCache = auth.NewViewerPrincipalValidationCache(h.config.ViewerKeyRevalidationTTL)
	}
	if referenceValidator, ok := h.viewerPrincipalValidator.(auth.ViewerPrincipalReferenceValidator); ok && strings.TrimSpace(session.ViewerRevalidationRef) != "" {
		return h.viewerValidationCache.ValidateWithReference(c.Request.Context(), referenceValidator, principal, session.ViewerRevalidationRef) == nil
	}
	return h.viewerValidationCache.Validate(c.Request.Context(), h.viewerPrincipalValidator, principal) == nil
}

func (h *authHandler) logout(c *gin.Context) {
	if h == nil || !h.config.Enabled {
		c.Status(http.StatusNoContent)
		return
	}
	resolved, _, ok := h.resolveValidSession(c)
	if !ok {
		resolved = h.resolveSessionToken(c)
	}
	if h.sessions != nil {
		h.deleteSession(resolved.Token)
	}
	clearSessionCookie(c, h.config.BasePath, resolved.CookieKind)
	c.Status(http.StatusNoContent)
}

func (h *authHandler) allowLoginAttempt(c *gin.Context, key string) bool {
	allowed, retryAfter := h.loginAttempts.Allow(key)
	if allowed {
		return true
	}
	seconds := int64((retryAfter + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.FormatInt(seconds, 10))
	c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many login attempts"})
	return false
}

func (h *authHandler) deleteSession(token string) {
	if h == nil || token == "" {
		return
	}
	if h.sessions != nil {
		h.sessions.Delete(token)
	}
}

func loginClientKey(c *gin.Context) string {
	return c.ClientIP()
}

func sessionClientMetadata(c *gin.Context) auth.SessionClientMetadata {
	return auth.SessionClientMetadata{
		IP:        sessionClientIP(c),
		UserAgent: c.Request.UserAgent(),
	}
}

// sessionClientIP 只用于会话信息展示；宿主机 Nginx 会把其观测到的客户端追加在 XFF 最右侧。
func sessionClientIP(c *gin.Context) string {
	forwarded := strings.Split(c.GetHeader("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		candidate := strings.TrimSpace(forwarded[index])
		address, err := netip.ParseAddr(candidate)
		if err == nil {
			return address.Unmap().String()
		}
	}
	return c.ClientIP()
}

func isCPAMCEmbedRequest(c *gin.Context) bool {
	return strings.EqualFold(strings.TrimSpace(c.GetHeader(embedHeaderName)), embedHeaderValueCPAMC)
}

func resolveSessionToken(c *gin.Context) resolvedSessionToken {
	return resolveSessionTokenForMode(c, false)
}

func (h *authHandler) resolveSessionToken(c *gin.Context) resolvedSessionToken {
	return resolveSessionTokenForMode(c, h != nil && h.config.AuthMode == AuthModeEmbeddedJWT)
}

func resolveSessionTokenForMode(c *gin.Context, forceEmbed bool) resolvedSessionToken {
	if candidates := resolveSessionTokenCandidatesForMode(c, forceEmbed); len(candidates) > 0 {
		return candidates[0]
	}
	if forceEmbed || isCPAMCEmbedRequest(c) {
		return resolvedSessionToken{CookieKind: sessionCookieKindEmbed, Source: auth.SessionSourceEmbed, Transport: sessionTokenTransportCookie}
	}
	return resolvedSessionToken{CookieKind: sessionCookieKindStandard, Source: auth.SessionSourceStandard, Transport: sessionTokenTransportCookie}
}

func resolveSessionTokenCandidates(c *gin.Context) []resolvedSessionToken {
	return resolveSessionTokenCandidatesForMode(c, false)
}

func (h *authHandler) resolveSessionTokenCandidates(c *gin.Context) []resolvedSessionToken {
	return resolveSessionTokenCandidatesForMode(c, h != nil && h.config.AuthMode == AuthModeEmbeddedJWT)
}

func resolveSessionTokenCandidatesForMode(c *gin.Context, forceEmbed bool) []resolvedSessionToken {
	if forceEmbed || isCPAMCEmbedRequest(c) {
		var candidates []resolvedSessionToken
		cookieToken, _ := c.Cookie(embedSessionCookieName)
		if cookieToken != "" {
			candidates = append(candidates, resolvedSessionToken{Token: cookieToken, CookieKind: sessionCookieKindEmbed, Source: auth.SessionSourceEmbed, Transport: sessionTokenTransportCookie})
		}
		headerToken := strings.TrimSpace(c.GetHeader(embedSessionHeaderName))
		if headerToken != "" && headerToken != cookieToken {
			candidates = append(candidates, resolvedSessionToken{Token: headerToken, CookieKind: sessionCookieKindEmbed, Source: auth.SessionSourceEmbed, Transport: sessionTokenTransportHeader})
		}
		return candidates
	}
	token, _ := c.Cookie(sessionCookieName)
	if token == "" {
		return nil
	}
	return []resolvedSessionToken{{Token: token, CookieKind: sessionCookieKindStandard, Source: auth.SessionSourceStandard, Transport: sessionTokenTransportCookie}}
}

func writeLoginSuccess(c *gin.Context, resolved resolvedSessionToken, token string) {
	if resolved.Source == auth.SessionSourceEmbed {
		c.JSON(http.StatusOK, loginResponse{SessionToken: token})
		return
	}
	c.Status(http.StatusNoContent)
}

func requiresRequestIntent(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func requestIntentMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isSSOExchange := c.Request.Method == http.MethodPost && strings.HasSuffix(c.Request.URL.Path, "/api/v1/auth/sso/exchange")
		if requiresRequestIntent(c.Request.Method) && !isSSOExchange && c.GetHeader(requestIntentHeaderName) != requestIntentHeaderValueFetch {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "fetch request required"})
			return
		}
		c.Next()
	}
}

func (h *authHandler) ssoExchange(c *gin.Context) {
	defer redactExchangeRequest(c.Request)
	if h == nil || !h.config.Enabled || h.config.AuthMode != AuthModeEmbeddedJWT || h.sessions == nil || h.embeddedVerifier == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "authentication_unavailable"})
		return
	}
	assertion, formRequest, err := readSSOAssertion(c.Request)
	if err != nil {
		if isRequestEntityTooLarge(err) {
			writeRequestEntityTooLarge(c)
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	principal, err := h.embeddedVerifier.Verify(c.Request.Context(), assertion)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_assertion"})
		return
	}
	if !h.catalogReady(c.Request.Context()) || h.usageAccess == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "catalog_unavailable"})
		return
	}
	accessPrincipal, err := h.usageAccess.ResolveIdentity(c.Request.Context(), principal, h.config.UsageSource)
	if err != nil {
		if errors.Is(err, service.ErrUsageScopeForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "mapping_required"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "catalog_unavailable"})
		return
	}
	role := auth.RoleUser
	if principal.IsAdministrator {
		role = auth.RoleAdmin
	}
	token, expiresAt, err := h.sessions.CreateEmbedded(accessPrincipal.ExternalIdentityID, role, principal.AssertionExpiresAt, auth.SessionSourceEmbed, sessionClientMetadata(c))
	if err != nil {
		if errors.Is(err, auth.ErrExpiredIdentityAssertion) || errors.Is(err, auth.ErrInvalidExternalIdentity) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_assertion"})
			return
		}
		writeInternalError(c, "create embedded auth session failed", err)
		return
	}
	setSessionCookie(c, h.config.BasePath, sessionCookieKindEmbed, token, expiresAt)
	if formRequest {
		c.Redirect(http.StatusSeeOther, embeddedLandingPath(h.config.BasePath, role))
		return
	}
	c.JSON(http.StatusOK, sessionResponse{Authenticated: true, Role: role, Capabilities: h.capabilities, AuthMode: h.config.AuthMode})
}

func (h *authHandler) catalogReady(ctx context.Context) bool {
	if h == nil || h.catalogState == nil || strings.TrimSpace(h.config.UsageSource) == "" {
		return false
	}
	state, err := h.catalogState.CatalogSyncState(ctx, h.config.UsageSource)
	return err == nil && !state.LastSuccessAt.IsZero()
}

func readSSOAssertion(request *http.Request) (string, bool, error) {
	if request == nil || request.Body == nil {
		return "", false, errors.New("missing request body")
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil {
		return "", false, err
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return "", false, err
	}
	defer func() {
		for index := range body {
			body[index] = 0
		}
	}()
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(body))
		if err != nil || len(values["assertion"]) != 1 || strings.TrimSpace(values.Get("assertion")) == "" {
			return "", true, errors.New("invalid assertion form")
		}
		return values.Get("assertion"), true, nil
	case "application/json":
		var payload struct {
			Assertion string `json:"assertion"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.Assertion) == "" {
			return "", false, errors.New("invalid assertion JSON")
		}
		return payload.Assertion, false, nil
	default:
		return "", false, errors.New("unsupported content type")
	}
}

func redactExchangeRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Body = http.NoBody
	request.Form = nil
	request.PostForm = nil
}

func embeddedLandingPath(basePath string, role auth.Role) string {
	landing := "/analysis"
	if role == auth.RoleUser {
		landing = "/overview"
	}
	basePath = strings.TrimRight(basePath, "/")
	return basePath + landing
}

func setSessionCookie(c *gin.Context, basePath string, kind sessionCookieKind, token string, expiresAt time.Time) {
	cookie := sessionCookie(basePath, kind)
	if kind == sessionCookieKindStandard {
		cookie.Secure = c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	}
	cookie.Value = token
	cookie.Expires = expiresAt
	cookie.MaxAge = int(time.Until(expiresAt).Seconds())
	http.SetCookie(c.Writer, cookie)
}

func sessionCookiePath(basePath string) string {
	if basePath == "" {
		return "/"
	}
	return basePath
}

func clearSessionCookie(c *gin.Context, basePath string, kind sessionCookieKind) {
	cookie := sessionCookie(basePath, kind)
	if kind == sessionCookieKindStandard {
		cookie.Secure = c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	}
	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	cookie.MaxAge = -1
	http.SetCookie(c.Writer, cookie)
}

func sessionCookie(basePath string, kind sessionCookieKind) *http.Cookie {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Path:     sessionCookiePath(basePath),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if kind == sessionCookieKindEmbed {
		cookie.Name = embedSessionCookieName
		cookie.Secure = true
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Partitioned = true
		return cookie
	}
	return cookie
}

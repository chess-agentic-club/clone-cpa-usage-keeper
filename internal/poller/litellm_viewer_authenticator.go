package poller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"cpa-usage-keeper/internal/auth"
)

// LiteLLMViewerKeyAuthenticator verifies LiteLLM virtual keys without
// retaining them after the request has completed.
type LiteLLMViewerKeyAuthenticator struct {
	baseURL   string
	masterKey string
	client    *http.Client

	mu                   sync.RWMutex
	canonicalByPrincipal map[string]string
}

type liteLLMKeyInfoResponse struct {
	Key  string                `json:"key"`
	Info liteLLMVirtualKeyInfo `json:"info"`
}

type liteLLMVirtualKeyInfo struct {
	Token    string     `json:"token"`
	KeyName  string     `json:"key_name"`
	KeyAlias string     `json:"key_alias"`
	Blocked  bool       `json:"blocked"`
	Expires  *time.Time `json:"expires"`
}

const maxLiteLLMKeyInfoBodyBytes = 1 << 20

func NewLiteLLMViewerKeyAuthenticator(baseURL, masterKey string, timeout time.Duration) *LiteLLMViewerKeyAuthenticator {
	return &LiteLLMViewerKeyAuthenticator{
		baseURL:   strings.TrimRight(baseURL, "/"),
		masterKey: masterKey,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		canonicalByPrincipal: make(map[string]string),
	}
}

// NewLiteLLMViewerKeyAuthenticatorWithMasterKey is retained as a descriptive
// alias for callers that want to make the server-only credential explicit.
func NewLiteLLMViewerKeyAuthenticatorWithMasterKey(baseURL, masterKey string, timeout time.Duration) *LiteLLMViewerKeyAuthenticator {
	return NewLiteLLMViewerKeyAuthenticator(baseURL, masterKey, timeout)
}

func (a *LiteLLMViewerKeyAuthenticator) AuthenticateViewerKey(ctx context.Context, rawKey string) (auth.ViewerPrincipal, error) {
	if a == nil || a.client == nil || !isCanonicalLiteLLMToken(rawKey) {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	payload, err := a.fetchKeyInfo(ctx, rawKey, "")
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	info := payload.Info
	if !activeLiteLLMKeyInfo(info) {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	canonical, err := canonicalLiteLLMKeyInfoIdentity(payload)
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	ref, err := opaqueLiteLLMKeyRef(canonical)
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	principal, err := auth.NormalizeViewerPrincipal(auth.ViewerPrincipal{
		SourceSystem: liteLLMSourceSystem,
		APIGroupKey:  liteLLMAPIGroupKeyFromRef(ref),
		DisplayName:  liteLLMViewerDisplayName(info, rawKey, payload.Key, canonical),
	})
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	a.mu.Lock()
	a.canonicalByPrincipal[principal.APIGroupKey] = canonical
	a.mu.Unlock()
	return principal, nil
}

// ValidateViewerPrincipal revalidates the in-memory canonical hash using the
// server-only master key. The persisted session contains only the irreversible
// opaque principal reference.
func (a *LiteLLMViewerKeyAuthenticator) ValidateViewerPrincipal(ctx context.Context, principal auth.ViewerPrincipal) error {
	if a == nil || a.client == nil || !isCanonicalLiteLLMToken(a.masterKey) || principal.SourceSystem != liteLLMSourceSystem {
		return auth.ErrViewerPrincipalUnavailable
	}
	ref, found := strings.CutPrefix(principal.APIGroupKey, liteLLMSourceSystem+":")
	if !found || !isLiteLLMOpaqueKeyRef(ref) {
		return auth.ErrViewerPrincipalUnavailable
	}
	principal, err := auth.NormalizeViewerPrincipal(principal)
	if err != nil {
		return auth.ErrViewerPrincipalUnavailable
	}
	a.mu.RLock()
	canonical := a.canonicalByPrincipal[principal.APIGroupKey]
	a.mu.RUnlock()
	if canonical == "" || !isLiteLLMHash(canonical) {
		return auth.ErrViewerPrincipalUnavailable
	}
	payload, err := a.fetchKeyInfo(ctx, a.masterKey, canonical)
	if err != nil || !activeLiteLLMKeyInfo(payload.Info) {
		return auth.ErrViewerPrincipalUnavailable
	}
	returnedCanonical, err := canonicalLiteLLMKeyInfoIdentity(payload)
	if err != nil || returnedCanonical != canonical {
		return auth.ErrViewerPrincipalUnavailable
	}
	return nil
}

func (a *LiteLLMViewerKeyAuthenticator) fetchKeyInfo(ctx context.Context, bearer, key string) (liteLLMKeyInfoResponse, error) {
	if a == nil || a.client == nil || !isCanonicalLiteLLMToken(bearer) {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	endpoint, err := url.Parse(a.baseURL + "/key/info")
	if err != nil {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	if key != "" {
		query := endpoint.Query()
		query.Set("key", key)
		endpoint.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := a.client.Do(request)
	if err != nil {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxLiteLLMKeyInfoBodyBytes+1))
	var payload liteLLMKeyInfoResponse
	if err := decoder.Decode(&payload); err != nil {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return liteLLMKeyInfoResponse{}, auth.ErrInvalidViewerCredentials
	}
	return payload, nil
}

func canonicalLiteLLMKeyInfoIdentity(payload liteLLMKeyInfoResponse) (string, error) {
	values := []string{strings.TrimSpace(payload.Info.Token), strings.TrimSpace(payload.Key)}
	canonical := ""
	for _, value := range values {
		if value == "" {
			continue
		}
		candidate, err := canonicalLiteLLMKeyRef(value)
		if err != nil || (canonical != "" && candidate != canonical) {
			return "", auth.ErrInvalidViewerCredentials
		}
		canonical = candidate
	}
	if canonical == "" {
		return "", auth.ErrInvalidViewerCredentials
	}
	return canonical, nil
}

func activeLiteLLMKeyInfo(info liteLLMVirtualKeyInfo) bool {
	return !info.Blocked && (info.Expires == nil || info.Expires.After(time.Now()))
}

func liteLLMViewerDisplayName(info liteLLMVirtualKeyInfo, rawKey, responseKey, canonical string) string {
	displayName := strings.TrimSpace(info.KeyAlias)
	if displayName == "" {
		displayName = strings.TrimSpace(info.KeyName)
	}
	if displayName == "" || strings.EqualFold(displayName, strings.TrimSpace(rawKey)) || strings.EqualFold(displayName, strings.TrimSpace(responseKey)) || strings.EqualFold(displayName, canonical) || strings.HasPrefix(strings.ToLower(displayName), "sk-") || isLiteLLMHash(displayName) {
		return "LiteLLM key"
	}
	displayCanonical, err := canonicalLiteLLMKeyRef(displayName)
	if err == nil && displayCanonical == canonical {
		return "LiteLLM key"
	}
	return displayName
}

func isCanonicalLiteLLMToken(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

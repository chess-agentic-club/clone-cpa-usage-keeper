package poller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"cpa-usage-keeper/internal/auth"
)

// LiteLLMViewerKeyAuthenticator verifies LiteLLM virtual keys without
// retaining them after the request has completed.
type LiteLLMViewerKeyAuthenticator struct {
	baseURL string
	client  *http.Client
}

type liteLLMKeyInfoResponse struct {
	Info liteLLMVirtualKeyInfo `json:"info"`
}

type liteLLMVirtualKeyInfo struct {
	Token    string     `json:"token"`
	KeyName  string     `json:"key_name"`
	KeyAlias string     `json:"key_alias"`
	Blocked  bool       `json:"blocked"`
	Expires  *time.Time `json:"expires"`
}

func NewLiteLLMViewerKeyAuthenticator(baseURL string, timeout time.Duration) *LiteLLMViewerKeyAuthenticator {
	return &LiteLLMViewerKeyAuthenticator{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *LiteLLMViewerKeyAuthenticator) AuthenticateViewerKey(ctx context.Context, rawKey string) (auth.ViewerPrincipal, error) {
	if a == nil || a.client == nil || strings.TrimSpace(rawKey) == "" {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/key/info", nil)
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	req.Header.Set("Authorization", "Bearer "+rawKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}

	decoder := json.NewDecoder(resp.Body)
	var payload liteLLMKeyInfoResponse
	if err := decoder.Decode(&payload); err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	info := payload.Info
	if info.Blocked || (info.Expires != nil && !info.Expires.After(time.Now())) {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	token := info.Token
	if !isCanonicalLiteLLMToken(token) {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	displayName := strings.TrimSpace(info.KeyAlias)
	if displayName == "" {
		displayName = strings.TrimSpace(info.KeyName)
	}
	if displayName == "" {
		displayName = "LiteLLM key"
	}
	principal, err := auth.NormalizeViewerPrincipal(auth.ViewerPrincipal{
		SourceSystem: liteLLMSourceSystem,
		APIGroupKey:  liteLLMAPIGroupKey(token),
		DisplayName:  displayName,
	})
	if err != nil {
		return auth.ViewerPrincipal{}, auth.ErrInvalidViewerCredentials
	}
	return principal, nil
}

// ValidateViewerPrincipal validates the non-secret identity retained in a
// session. Remote validation requires the original virtual key, which is
// deliberately never retained outside AuthenticateViewerKey.
func (a *LiteLLMViewerKeyAuthenticator) ValidateViewerPrincipal(_ context.Context, principal auth.ViewerPrincipal) error {
	principal, err := auth.NormalizeViewerPrincipal(principal)
	if err != nil || a == nil || principal.SourceSystem != liteLLMSourceSystem {
		return auth.ErrViewerPrincipalUnavailable
	}
	token := strings.TrimPrefix(principal.APIGroupKey, liteLLMSourceSystem+":")
	if !isCanonicalLiteLLMToken(token) || principal.APIGroupKey != liteLLMAPIGroupKey(token) {
		return auth.ErrViewerPrincipalUnavailable
	}
	return nil
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

package poller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
)

const liteLLMVirtualKey = "sk-virtual"

func TestLiteLLMViewerAuthenticatesVirtualKeyFromKeyInfo(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/key/info" {
			t.Fatalf("request = %s %s, want GET /key/info", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+liteLLMVirtualKey {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.URL.RawQuery != "" {
			t.Fatalf("request must not contain a query: %s", r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"info":{"token":"returned-token","key_name":"  Engineering key  ","key_alias":"  Engineering  ","blocked":false,"expires":%q}}`, expires))
	}))
	defer server.Close()

	principal, err := NewLiteLLMViewerKeyAuthenticator(server.URL, time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
	if err != nil {
		t.Fatalf("AuthenticateViewerKey returned error: %v", err)
	}
	if principal != (auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:returned-token", DisplayName: "Engineering"}) {
		t.Fatalf("principal = %+v", principal)
	}
	event, err := MapLiteLLMSpendLog(LiteLLMSpendLog{RequestID: "req-1", APIKey: "returned-token"})
	if err != nil || event.APIGroupKey != principal.APIGroupKey {
		t.Fatalf("mapper identity = %q, %v; principal identity = %q", event.APIGroupKey, err, principal.APIGroupKey)
	}
}

func TestLiteLLMViewerAuthenticationRejectsInvalidKeyInfoWithoutLeakingSecret(t *testing.T) {
	futureExpiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	pastExpiry := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name     string
		response string
		status   int
	}{
		{name: "missing token", response: fmt.Sprintf(`{"info":{"key_name":"Engineering","key_alias":"Engineering","blocked":false,"expires":%q}}`, futureExpiry), status: http.StatusOK},
		{name: "unauthorized", response: `{"error":"invalid key"}`, status: http.StatusUnauthorized},
		{name: "not found", response: `{"error":"missing key"}`, status: http.StatusNotFound},
		{name: "blocked", response: fmt.Sprintf(`{"info":{"token":"returned-token","key_name":"Engineering","key_alias":"Engineering","blocked":true,"expires":%q}}`, futureExpiry), status: http.StatusOK},
		{name: "expired", response: fmt.Sprintf(`{"info":{"token":"returned-token","key_name":"Engineering","key_alias":"Engineering","blocked":false,"expires":%q}}`, pastExpiry), status: http.StatusOK},
		{name: "noncanonical token", response: fmt.Sprintf(`{"info":{"token":"returned token","key_name":"Engineering","key_alias":"Engineering","blocked":false,"expires":%q}}`, futureExpiry), status: http.StatusOK},
		{name: "trailing JSON", response: fmt.Sprintf(`{"info":{"token":"returned-token","key_name":"Engineering","key_alias":"Engineering","blocked":false,"expires":%q}} {}`, futureExpiry), status: http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.response)
			}))
			defer server.Close()

			_, err := NewLiteLLMViewerKeyAuthenticator(server.URL, time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
			if !errors.Is(err, auth.ErrInvalidViewerCredentials) {
				t.Fatalf("error = %v, want invalid viewer credentials", err)
			}
			if strings.Contains(err.Error(), liteLLMVirtualKey) {
				t.Fatalf("error leaked virtual key: %q", err)
			}
		})
	}
}

func TestLiteLLMViewerAuthenticationRejectsRedirectWithoutFollowingIt(t *testing.T) {
	redirected := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/key/info":
			http.Redirect(w, r, "/redirected", http.StatusFound)
		case "/redirected":
			redirected <- struct{}{}
			_, _ = io.WriteString(w, `{"info":{"token":"returned-token","key_name":"Engineering","key_alias":"Engineering","blocked":false}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err := NewLiteLLMViewerKeyAuthenticator(server.URL, time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
	if !errors.Is(err, auth.ErrInvalidViewerCredentials) {
		t.Fatalf("error = %v, want invalid viewer credentials", err)
	}
	select {
	case <-redirected:
		t.Fatal("client followed redirect")
	default:
	}
}

func TestLiteLLMViewerAuthenticationTransportErrorDoesNotLeakSecret(t *testing.T) {
	_, err := NewLiteLLMViewerKeyAuthenticator("http://127.0.0.1:1", time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
	if !errors.Is(err, auth.ErrInvalidViewerCredentials) {
		t.Fatalf("error = %v, want invalid viewer credentials", err)
	}
	if strings.Contains(err.Error(), liteLLMVirtualKey) {
		t.Fatalf("error leaked virtual key: %q", err)
	}
}

func TestLiteLLMViewerValidatorAcceptsOnlyCanonicalLiteLLMPrincipal(t *testing.T) {
	authenticator := NewLiteLLMViewerKeyAuthenticator("http://litellm.invalid", time.Second)
	valid := auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:returned-token", DisplayName: "Engineering"}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), valid); err != nil {
		t.Fatalf("ValidateViewerPrincipal returned error: %v", err)
	}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "cliproxy", APIGroupKey: "litellm:returned-token", DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("wrong-source validation error = %v", err)
	}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:returned token", DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("noncanonical-token validation error = %v", err)
	}
	for _, apiGroupKey := range []string{"litellm:returned-token ", "litellm:returned-token\x00"} {
		if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: apiGroupKey, DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
			t.Fatalf("noncanonical API group key %q validation error = %v", apiGroupKey, err)
		}
	}
}

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

	principal, err := NewLiteLLMViewerKeyAuthenticator(server.URL, "master-key", time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
	if err != nil {
		t.Fatalf("AuthenticateViewerKey returned error: %v", err)
	}
	ref, err := opaqueLiteLLMKeyRef("returned-token")
	if err != nil {
		t.Fatalf("opaqueLiteLLMKeyRef() error = %v", err)
	}
	if principal != (auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: liteLLMAPIGroupKeyFromRef(ref), DisplayName: "Engineering"}) {
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

			_, err := NewLiteLLMViewerKeyAuthenticator(server.URL, "master-key", time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
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

	_, err := NewLiteLLMViewerKeyAuthenticator(server.URL, "master-key", time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
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
	_, err := NewLiteLLMViewerKeyAuthenticator("http://127.0.0.1:1", "master-key", time.Second).AuthenticateViewerKey(context.Background(), liteLLMVirtualKey)
	if !errors.Is(err, auth.ErrInvalidViewerCredentials) {
		t.Fatalf("error = %v, want invalid viewer credentials", err)
	}
	if strings.Contains(err.Error(), liteLLMVirtualKey) {
		t.Fatalf("error leaked virtual key: %q", err)
	}
}

func TestLiteLLMViewerValidatorRejectsUnknownOrMalformedPrincipal(t *testing.T) {
	authenticator := NewLiteLLMViewerKeyAuthenticator("http://litellm.invalid", "master-key", time.Second)
	ref, err := opaqueLiteLLMKeyRef("returned-token")
	if err != nil {
		t.Fatalf("opaqueLiteLLMKeyRef() error = %v", err)
	}
	valid := auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: liteLLMAPIGroupKeyFromRef(ref), DisplayName: "Engineering"}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), valid); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("unknown-principal validation error = %v", err)
	}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "cliproxy", APIGroupKey: valid.APIGroupKey, DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("wrong-source validation error = %v", err)
	}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:returned-token", DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("raw-token validation error = %v", err)
	}
	for _, apiGroupKey := range []string{valid.APIGroupKey + " ", valid.APIGroupKey + "\x00"} {
		if err := authenticator.ValidateViewerPrincipal(context.Background(), auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: apiGroupKey, DisplayName: "Engineering"}); !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
			t.Fatalf("noncanonical API group key %q validation error = %v", apiGroupKey, err)
		}
	}
}

func TestLiteLLMViewerRevalidatesOpaquePrincipalWithServerMasterKey(t *testing.T) {
	const (
		rawKey    = "sk-private-viewer-key"
		masterKey = "server-only-master-key"
	)
	canonical, err := canonicalLiteLLMKeyRef(rawKey)
	if err != nil {
		t.Fatalf("canonicalLiteLLMKeyRef returned error: %v", err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/key/info" {
			t.Fatalf("request = %s %s, want GET /key/info", r.Method, r.URL.Path)
		}
		switch requests {
		case 1:
			if r.Header.Get("Authorization") != "Bearer "+rawKey || r.URL.RawQuery != "" {
				t.Fatalf("login request used unexpected authentication or query")
			}
			_, _ = io.WriteString(w, `{"key":"`+rawKey+`","info":{"key_alias":"`+rawKey+`","blocked":false}}`)
		case 2:
			if r.Header.Get("Authorization") != "Bearer "+masterKey || r.URL.Query().Get("key") != canonical || len(r.URL.Query()) != 1 {
				t.Fatalf("revalidation request did not use the server master key and canonical hash")
			}
			_, _ = io.WriteString(w, `{"key":"`+canonical+`","info":{"key_alias":"`+canonical+`","blocked":false}}`)
		default:
			t.Fatalf("unexpected request count %d", requests)
		}
	}))
	defer server.Close()

	authenticator := NewLiteLLMViewerKeyAuthenticatorWithMasterKey(server.URL, masterKey, time.Second)
	principal, err := authenticator.AuthenticateViewerKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("AuthenticateViewerKey returned error: %v", err)
	}
	if principal.DisplayName != "LiteLLM key" || strings.Contains(principal.APIGroupKey, rawKey) || strings.Contains(principal.APIGroupKey, canonical) {
		t.Fatal("principal retained a credential or unsafe alias")
	}
	if err := authenticator.ValidateViewerPrincipal(context.Background(), principal); err != nil {
		t.Fatalf("ValidateViewerPrincipal returned error: %v", err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d, want login and revalidation", requests)
	}
}

func TestLiteLLMViewerPrivilegedRevalidationRejectsRedirectAndLeaksNoCredential(t *testing.T) {
	const (
		rawKey    = "sk-private-viewer-key"
		masterKey = "server-only-master-key"
	)
	redirected := make(chan struct{}, 1)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch {
		case r.URL.Path == "/key/info" && requests == 1:
			_, _ = io.WriteString(w, `{"key":"`+rawKey+`","info":{"key_alias":"Engineering","blocked":false}}`)
		case r.URL.Path == "/key/info":
			http.Redirect(w, r, "/redirected", http.StatusFound)
		case r.URL.Path == "/redirected":
			redirected <- struct{}{}
		default:
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	authenticator := NewLiteLLMViewerKeyAuthenticatorWithMasterKey(server.URL, masterKey, time.Second)
	principal, err := authenticator.AuthenticateViewerKey(context.Background(), rawKey)
	if err != nil {
		t.Fatalf("AuthenticateViewerKey returned error: %v", err)
	}
	err = authenticator.ValidateViewerPrincipal(context.Background(), principal)
	if !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("revalidation error = %v, want unavailable", err)
	}
	if strings.Contains(err.Error(), rawKey) || strings.Contains(err.Error(), masterKey) {
		t.Fatal("revalidation error leaked a credential")
	}
	select {
	case <-redirected:
		t.Fatal("privileged client followed redirect")
	default:
	}
}

package poller

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLiteLLMClientListsAndMapsSpendLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/spend/logs/v2" {
			t.Fatalf("unexpected request path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer master-key" {
			t.Fatal("unexpected spend-log authentication")
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{"data":[{"request_id":"req-1","api_key":"%s","model":"gpt-4","custom_llm_provider":"openai","spend":0.12,"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"startTime":"2026-09-06T00:00:00Z"}],"total_pages":1}`, strings.Repeat("a", 64)))
	}))
	defer server.Close()
	page, err := NewLiteLLMClient(server.URL, "master-key", time.Second).ListSpendLogs(context.Background(), time.Now().Add(-time.Hour), time.Now(), 1, 100)
	if err != nil || len(page.Data) != 1 {
		t.Fatalf("ListSpendLogs = %+v, %v", page, err)
	}
	event, err := MapLiteLLMSpendLog(page.Data[0])
	if err != nil || event.RequestID != "req-1" || !strings.HasPrefix(event.APIGroupKey, "litellm:lkey-") || event.CostUSD == nil || *event.CostUSD != 0.12 {
		t.Fatalf("mapped event = %+v, %v", event, err)
	}
}

func TestLiteLLMClientListUsersUsesUnfilteredPaginatedContract(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.URL.Path != "/user/list" {
			t.Fatalf("request path = %q, want /user/list", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Fatal("authorization header is missing")
		}
		_, _ = io.WriteString(w, `{"users":[{"user_id":"alice","user_email":"alice@example.com","user_alias":"Alice"}],"total_pages":2}`)
	}))
	defer server.Close()

	page, err := NewLiteLLMClient(server.URL, "fixture-credential", time.Second).ListUsers(context.Background(), 2, 100)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if gotQuery != "page=2&page_size=100" {
		t.Fatalf("query = %q, want exact unfiltered pagination", gotQuery)
	}
	if len(page.Users) != 1 || page.Users[0].UserID != "alice" || page.Users[0].Email != "alice@example.com" || page.TotalPages != 2 {
		t.Fatalf("ListUsers page = %#v", page)
	}
}

func TestLiteLLMClientListKeysRequestsFullObjects(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.URL.Path != "/key/list" {
			t.Fatalf("request path = %q, want /key/list", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"keys":[{"token":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","user_id":"alice","key_alias":"Engineering","blocked":false,"expires":"2099-01-01T00:00:00Z"}],"total_pages":3}`)
	}))
	defer server.Close()

	page, err := NewLiteLLMClient(server.URL, "fixture-credential", time.Second).ListKeys(context.Background(), 3, 100)
	if err != nil {
		t.Fatalf("ListKeys returned error: %v", err)
	}
	if gotQuery != "page=3&return_full_object=true&size=100" {
		t.Fatalf("query = %q, want full-object pagination", gotQuery)
	}
	if len(page.Keys) != 1 || page.Keys[0].Token == "" || page.Keys[0].UserID != "alice" || page.Keys[0].Alias != "Engineering" || page.Keys[0].Expires == nil || page.TotalPages != 3 {
		t.Fatalf("ListKeys page = %#v", page)
	}
}

func TestLiteLLMClientRejectsCatalogRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("redirect target must not be requested")
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer server.Close()

	_, err := NewLiteLLMClient(server.URL, "fixture-credential", time.Second).ListUsers(context.Background(), 1, 100)
	if err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("ListUsers redirect error = %v, want non-success response", err)
	}
}

func TestLiteLLMClientRejectsUnboundedCatalogPagination(t *testing.T) {
	client := NewLiteLLMClient("https://litellm.invalid", "fixture-credential", time.Second)
	if _, err := client.ListUsers(context.Background(), 0, 100); err == nil {
		t.Fatal("ListUsers accepted page zero")
	}
	if _, err := client.ListKeys(context.Background(), 1, liteLLMMaxCatalogPageSize+1); err == nil {
		t.Fatal("ListKeys accepted an oversized page")
	}
}

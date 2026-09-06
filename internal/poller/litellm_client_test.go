package poller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLiteLLMClientListsAndMapsSpendLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/spend/logs/v2" || r.Header.Get("Authorization") != "Bearer master-key" {
			t.Fatalf("unexpected request %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		io.WriteString(w, `{"data":[{"request_id":"req-1","api_key":"hash","model":"gpt-4","custom_llm_provider":"openai","spend":0.12,"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"startTime":"2026-09-06T00:00:00Z"}],"total_pages":1}`)
	}))
	defer server.Close()
	page, err := NewLiteLLMClient(server.URL, "master-key", time.Second).ListSpendLogs(context.Background(), time.Now().Add(-time.Hour), time.Now(), 1, 100)
	if err != nil || len(page.Data) != 1 {
		t.Fatalf("ListSpendLogs = %+v, %v", page, err)
	}
	event, err := MapLiteLLMSpendLog(page.Data[0])
	if err != nil || event.RequestID != "req-1" || event.APIGroupKey != "litellm:hash" || event.CostUSD == nil || *event.CostUSD != 0.12 {
		t.Fatalf("mapped event = %+v, %v", event, err)
	}
}

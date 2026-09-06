package poller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cpa-usage-keeper/internal/entities"
)

type LiteLLMSpendLog struct {
	RequestID        string    `json:"request_id"`
	APIKey           string    `json:"api_key"`
	Model            string    `json:"model"`
	ModelGroup       string    `json:"model_group"`
	Provider         string    `json:"custom_llm_provider"`
	Spend            float64   `json:"spend"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	TotalTokens      int64     `json:"total_tokens"`
	StartTime        time.Time `json:"startTime"`
}
type LiteLLMSpendLogPage struct {
	Data       []LiteLLMSpendLog `json:"data"`
	TotalPages int               `json:"total_pages"`
}

// LiteLLMHTTPError retains the upstream status so the ingestion runner can
// distinguish retryable transient responses from permanent request failures.
type LiteLLMHTTPError struct {
	StatusCode int
	Status     string
}

func (e *LiteLLMHTTPError) Error() string {
	if e == nil {
		return "LiteLLM HTTP error"
	}
	if e.Status != "" {
		return fmt.Sprintf("litellm spend logs: %s", e.Status)
	}
	return fmt.Sprintf("litellm spend logs: HTTP %d", e.StatusCode)
}

type LiteLLMClient struct {
	baseURL, key string
	client       *http.Client
}

func NewLiteLLMClient(baseURL, key string, timeout time.Duration) *LiteLLMClient {
	return &LiteLLMClient{baseURL: strings.TrimRight(baseURL, "/"), key: key, client: &http.Client{Timeout: timeout}}
}
func (c *LiteLLMClient) ListSpendLogs(ctx context.Context, start, end time.Time, page, pageSize int) (LiteLLMSpendLogPage, error) {
	u, _ := url.Parse(c.baseURL + "/spend/logs/v2")
	q := u.Query()
	q.Set("start_date", start.Format(time.RFC3339))
	q.Set("end_date", end.Format(time.RFC3339))
	q.Set("page", fmt.Sprint(page))
	q.Set("page_size", fmt.Sprint(pageSize))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return LiteLLMSpendLogPage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.client.Do(req)
	if err != nil {
		return LiteLLMSpendLogPage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return LiteLLMSpendLogPage{}, &LiteLLMHTTPError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	var out LiteLLMSpendLogPage
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
func MapLiteLLMSpendLog(log LiteLLMSpendLog) (entities.UsageEvent, error) {
	if strings.TrimSpace(log.RequestID) == "" {
		return entities.UsageEvent{}, fmt.Errorf("litellm request_id is required")
	}
	model := log.Model
	if model == "" {
		model = log.ModelGroup
	}
	cost := log.Spend
	return entities.UsageEvent{EventKey: log.RequestID, RequestID: log.RequestID, APIGroupKey: "litellm:" + log.APIKey, Source: "litellm", SourceSystem: "litellm", Provider: log.Provider, Model: model, Timestamp: log.StartTime, InputTokens: log.PromptTokens, OutputTokens: log.CompletionTokens, TotalTokens: log.TotalTokens, CostUSD: &cost, CostSource: "provider_reported"}, nil
}

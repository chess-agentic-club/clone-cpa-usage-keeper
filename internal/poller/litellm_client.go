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

const liteLLMSourceSystem = "litellm"

const liteLLMMaxCatalogPageSize = 1000

func liteLLMAPIGroupKey(token string) string {
	ref, err := opaqueLiteLLMKeyRef(token)
	if err != nil {
		return liteLLMSourceSystem + ":unattributed"
	}
	return liteLLMAPIGroupKeyFromRef(ref)
}

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

type LiteLLMUser struct {
	UserID      string `json:"user_id"`
	Email       string `json:"user_email"`
	DisplayName string `json:"user_alias"`
}

type LiteLLMUserPage struct {
	Users      []LiteLLMUser `json:"users"`
	TotalPages int           `json:"total_pages"`
}

type LiteLLMKey struct {
	Token   string     `json:"token"`
	UserID  string     `json:"user_id"`
	Alias   string     `json:"key_alias"`
	Blocked bool       `json:"blocked"`
	Expires *time.Time `json:"expires"`
}

type LiteLLMKeyPage struct {
	Keys       []LiteLLMKey `json:"keys"`
	TotalPages int          `json:"total_pages"`
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
	return &LiteLLMClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		key:     key,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *LiteLLMClient) ListUsers(ctx context.Context, page, pageSize int) (LiteLLMUserPage, error) {
	if err := validateLiteLLMCatalogPage(page, pageSize); err != nil {
		return LiteLLMUserPage{}, err
	}
	u, err := url.Parse(c.baseURL + "/user/list")
	if err != nil {
		return LiteLLMUserPage{}, err
	}
	q := u.Query()
	q.Set("page", fmt.Sprint(page))
	q.Set("page_size", fmt.Sprint(pageSize))
	u.RawQuery = q.Encode()
	var out LiteLLMUserPage
	err = c.getJSON(ctx, u, &out)
	return out, err
}

func (c *LiteLLMClient) ListKeys(ctx context.Context, page, pageSize int) (LiteLLMKeyPage, error) {
	if err := validateLiteLLMCatalogPage(page, pageSize); err != nil {
		return LiteLLMKeyPage{}, err
	}
	u, err := url.Parse(c.baseURL + "/key/list")
	if err != nil {
		return LiteLLMKeyPage{}, err
	}
	q := u.Query()
	q.Set("page", fmt.Sprint(page))
	q.Set("return_full_object", "true")
	q.Set("size", fmt.Sprint(pageSize))
	u.RawQuery = q.Encode()
	var out LiteLLMKeyPage
	err = c.getJSON(ctx, u, &out)
	return out, err
}

func validateLiteLLMCatalogPage(page, pageSize int) error {
	if page <= 0 || pageSize <= 0 || pageSize > liteLLMMaxCatalogPageSize {
		return fmt.Errorf("invalid LiteLLM catalog pagination")
	}
	return nil
}

func (c *LiteLLMClient) getJSON(ctx context.Context, u *url.URL, out any) error {
	if c == nil || c.client == nil || u == nil {
		return fmt.Errorf("LiteLLM client is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &LiteLLMHTTPError{StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *LiteLLMClient) ListSpendLogs(ctx context.Context, start, end time.Time, page, pageSize int) (LiteLLMSpendLogPage, error) {
	u, err := url.Parse(c.baseURL + "/spend/logs/v2")
	if err != nil {
		return LiteLLMSpendLogPage{}, err
	}
	q := u.Query()
	q.Set("start_date", start.Format(time.RFC3339))
	q.Set("end_date", end.Format(time.RFC3339))
	q.Set("page", fmt.Sprint(page))
	q.Set("page_size", fmt.Sprint(pageSize))
	u.RawQuery = q.Encode()
	var out LiteLLMSpendLogPage
	err = c.getJSON(ctx, u, &out)
	return out, err
}
func MapLiteLLMSpendLog(log LiteLLMSpendLog) (entities.UsageEvent, error) {
	if strings.TrimSpace(log.RequestID) == "" {
		return entities.UsageEvent{}, fmt.Errorf("litellm request_id is required")
	}
	apiGroupKey := liteLLMSourceSystem + ":unattributed"
	if strings.TrimSpace(log.APIKey) != "" {
		ref, err := opaqueLiteLLMKeyRef(log.APIKey)
		if err != nil {
			return entities.UsageEvent{}, ErrInvalidLiteLLMKeyRef
		}
		apiGroupKey = liteLLMAPIGroupKeyFromRef(ref)
	}
	model := log.Model
	if model == "" {
		model = log.ModelGroup
	}
	cost := log.Spend
	return entities.UsageEvent{EventKey: log.RequestID, RequestID: log.RequestID, APIGroupKey: apiGroupKey, Source: liteLLMSourceSystem, SourceSystem: liteLLMSourceSystem, Provider: log.Provider, Model: model, Timestamp: log.StartTime, InputTokens: log.PromptTokens, OutputTokens: log.CompletionTokens, TotalTokens: log.TotalTokens, CostUSD: &cost, CostSource: "provider_reported"}, nil
}

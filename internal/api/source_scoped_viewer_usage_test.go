package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
	servicedto "cpa-usage-keeper/internal/service/dto"
)

type sourceScopedUsageStub struct {
	filters []servicedto.UsageFilter
}

func (s *sourceScopedUsageStub) scoped(filter servicedto.UsageFilter) bool {
	s.filters = append(s.filters, filter)
	return filter.APIGroupKey == "litellm:token-a" && filter.APIKeyID == ""
}

func (s *sourceScopedUsageStub) GetUsageOverview(_ context.Context, filter servicedto.UsageFilter) (*servicedto.UsageOverviewSnapshot, error) {
	tokens := int64(999)
	if s.scoped(filter) {
		tokens = 11
	}
	return &servicedto.UsageOverviewSnapshot{Summary: servicedto.UsageOverviewSummary{InputTokens: tokens}, Series: servicedto.UsageOverviewSeries{Buckets: []string{"bucket"}, Tokens: []int64{tokens}}}, nil
}

func (s *sourceScopedUsageStub) GetUsageActivity(_ context.Context, filter servicedto.UsageFilter) (*servicedto.UsageActivitySnapshot, error) {
	tokens := int64(999)
	if s.scoped(filter) {
		tokens = 11
	}
	return &servicedto.UsageActivitySnapshot{Window: servicedto.UsageActivityWindowYear, TotalTokens: tokens, Blocks: []servicedto.UsageActivityBlock{}}, nil
}

func (s *sourceScopedUsageStub) GetUsageOverviewRealtime(_ context.Context, filter servicedto.UsageFilter) (*servicedto.UsageOverviewRealtime, error) {
	tokens := int64(999)
	if s.scoped(filter) {
		tokens = 11
	}
	return &servicedto.UsageOverviewRealtime{Window: "15m", TokenVelocity: []servicedto.RealtimeTokenVelocityPoint{{Bucket: "bucket", Tokens: tokens}}, CurrentUsage: servicedto.RealtimeCurrentUsage{Models: []servicedto.RealtimeUsageTopItem{{Key: "target-model", Tokens: tokens}}}}, nil
}

func (s *sourceScopedUsageStub) GetAnalysis(_ context.Context, filter servicedto.UsageFilter) (*servicedto.AnalysisSnapshot, error) {
	tokens := int64(999)
	if s.scoped(filter) {
		tokens = 11
	}
	return &servicedto.AnalysisSnapshot{ModelComposition: []servicedto.AnalysisCompositionItem{{Key: "target-model", TotalTokens: tokens}}}, nil
}

func (s *sourceScopedUsageStub) GetAnalysisLatency(_ context.Context, filter servicedto.UsageFilter) (*servicedto.AnalysisLatencyDiagnostics, error) {
	latency := int64(999)
	if s.scoped(filter) {
		latency = 11
	}
	return &servicedto.AnalysisLatencyDiagnostics{Points: []servicedto.AnalysisLatencyPoint{{LatencyMS: latency}}}, nil
}

func (s *sourceScopedUsageStub) ListUsageEvents(_ context.Context, filter servicedto.UsageFilter) (*servicedto.UsageEventsPage, error) {
	model := "other-model"
	if s.scoped(filter) {
		model = "target-model"
	}
	return &servicedto.UsageEventsPage{Events: []servicedto.UsageEventRecord{{ID: 1, Model: model, APIGroupKey: "litellm:token-a"}}, TotalCount: 1, Page: 1, PageSize: 100, TotalPages: 1}, nil
}

func (s *sourceScopedUsageStub) StreamUsageEvents(_ context.Context, filter servicedto.UsageFilter, emit func(servicedto.UsageEventRecord) error) error {
	model := "other-model"
	if s.scoped(filter) {
		model = "target-model"
	}
	return emit(servicedto.UsageEventRecord{ID: 1, Model: model, APIGroupKey: "litellm:token-a"})
}

func (s *sourceScopedUsageStub) ListUsageEventFilterOptions(_ context.Context, filter servicedto.UsageFilter) (*servicedto.UsageEventFilterOptions, error) {
	model := "other-model"
	if s.scoped(filter) {
		model = "target-model"
	}
	return &servicedto.UsageEventFilterOptions{Models: []string{model}}, nil
}

func TestSourceScopedViewerRoutesEnforceSessionScopeAcrossDashboardData(t *testing.T) {
	principal := auth.ViewerPrincipal{SourceSystem: "litellm", APIGroupKey: "litellm:token-a", DisplayName: "Token A"}
	sessions := auth.NewSessionManager(time.Hour)
	token, _, err := sessions.CreateAPIKeyViewerForPrincipalWithSourceAndMetadata(principal, auth.SessionSourceStandard, auth.SessionClientMetadata{})
	if err != nil {
		t.Fatalf("create source-scoped session: %v", err)
	}
	adapter := &authViewerKeyAdapterStub{principal: principal}
	handler := NewAuthHandler(AuthConfig{Enabled: true, SessionTTL: time.Hour}, sessions)
	handler.setViewerKeyAuthenticator(adapter, adapter)
	provider := &sourceScopedUsageStub{}
	router := NewRouter(nil, nil, provider, nil, handler.config, handler, "")

	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/key-overview?range=24h&api_key_id=99", `"input_tokens":11`},
		{"/api/v1/key-overview?range=24h&api_key_id=99", `"tokens":[11]`},
		{"/api/v1/key-overview/realtime?window=15m&api_key_id=99", `"tokens":11`},
		{"/api/v1/key-overview/realtime?window=15m&api_key_id=99", `"target-model"`},
		{"/api/v1/key-activity?window=year&api_key_id=99", `"total_tokens":11`},
		{"/api/v1/key-analysis?range=24h&api_key_id=99", `"target-model"`},
		{"/api/v1/key-analysis?range=24h&api_key_id=99", `"total_tokens":11`},
		{"/api/v1/key-analysis/latency?range=24h&api_key_id=99", `"latency_ms":11`},
		{"/api/v1/key-events?range=24h&api_key_id=not-a-number", `"target-model"`},
		{"/api/v1/key-events/export?range=24h&api_key_id=not-a-number&format=json", `"target-model"`},
		{"/api/v1/key-events/filters/models?api_key_id=99", `"target-model"`},
		{"/api/v1/key-events/filters/sources?api_key_id=99", `"sources":[]`},
	}
	for _, testCase := range tests {
		t.Run(testCase.path+testCase.want, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), testCase.want) {
				t.Fatalf("status=%d body=%s, want %s", response.Code, response.Body.String(), testCase.want)
			}
			if strings.Contains(response.Body.String(), principal.APIGroupKey) {
				t.Fatalf("canonical viewer group key leaked from %s: %s", testCase.path, response.Body.String())
			}
		})
	}
}

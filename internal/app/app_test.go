package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"cpa-usage-keeper/internal/config"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/poller"
	"cpa-usage-keeper/internal/pricing"
	"cpa-usage-keeper/internal/quota"
	"cpa-usage-keeper/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func TestAppCloseClosesDatabase(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	sqlDB, err := app.DB.DB()
	if err != nil {
		t.Fatalf("load sql db: %v", err)
	}

	if err := app.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if err := sqlDB.Ping(); err == nil {
		t.Fatal("expected database ping to fail after app close")
	}
}

func TestNewWithConfigBuildsQuotaAutoRefreshRunner(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()
	if app.QuotaAutoRefresh == nil {
		t.Fatal("expected quota scheduled refresh runner to be initialized")
	}
	if app.QuotaService == nil {
		t.Fatal("expected quota service to remain available for manual refresh")
	}
}

func TestAppCloseWaitsForQuotaRefreshTasksBeforeDatabaseClose(t *testing.T) {
	waitCalled := make(chan struct{}, 1)
	quotaService := &quotaContextRecorder{contextSet: make(chan context.Context, 1), waitCalled: waitCalled}
	app := &App{QuotaService: quotaService}

	if err := app.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case <-waitCalled:
	case <-time.After(time.Second):
		t.Fatal("expected App.Close to wait for quota refresh goroutines")
	}
}

func TestAppCloseStopsRealQuotaRefreshTasksBeforeDatabaseClose(t *testing.T) {
	db, err := repository.OpenDatabase(config.Config{SQLitePath: filepath.Join(t.TempDir(), "quota-close.db")})
	if err != nil {
		t.Fatalf("OpenDatabase returned error: %v", err)
	}
	if err := db.Create(&entities.UsageIdentity{Identity: "auth-1", Name: "auth-1", Provider: "claude", Type: "auth-file", AuthType: entities.UsageIdentityAuthTypeAuthFile}).Error; err != nil {
		t.Fatalf("seed usage identity returned error: %v", err)
	}
	block := make(chan struct{})
	handler := &appQuotaHandlerStub{block: block}
	quotaService := quota.NewServiceWithRegistry(
		db,
		quota.NewProviderRegistry(map[string]quota.ProviderHandler{"claude": handler}),
		pricing.NewCatalog(pricing.EmptySnapshot()),
	)
	quotaService.SetRefreshContext(context.Background())
	app := &App{DB: db, QuotaService: quotaService}

	response, err := quotaService.Refresh(context.Background(), quota.RefreshRequest{AuthIndexes: []string{"auth-1"}, Source: quota.RefreshSourceManual})
	if err != nil {
		t.Fatalf("Refresh returned error: %v", err)
	}
	waitForAppQuotaTaskStatus(t, quotaService, response.Tasks[0].AuthIndex, quota.RefreshTaskStatusRunning)

	if err := app.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	task, err := quotaService.GetRefreshTaskByAuthIndex(context.Background(), response.Tasks[0].AuthIndex)
	if err != nil {
		t.Fatalf("GetRefreshTaskByAuthIndex returned error after close: %v", err)
	}
	if task.Status != quota.RefreshTaskStatusFailed {
		t.Fatalf("expected app close to cancel and drain real quota worker before closing DB, got %+v", task)
	}
	if handler.callCount() != 0 {
		t.Fatalf("expected canceled quota worker not to complete provider call, got %d calls", handler.callCount())
	}
}

func TestNewWithConfigBuildsRedisIngestAndRouter(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()
	if app.Poller == nil {
		t.Fatal("expected poller status provider to be initialized")
	}
	if app.RedisIngest == nil {
		t.Fatal("expected redis ingest runner to be initialized")
	}
	if app.RedisProcess == nil {
		t.Fatal("expected redis process runner to be initialized")
	}
	if app.UsageAggregation == nil {
		t.Fatal("expected usage aggregation runner to be initialized")
	}
	if app.Router == nil {
		t.Fatal("expected router to be initialized")
	}
	if app.LogCloser == nil {
		t.Fatal("expected log closer to be initialized")
	}
	if app.BackupMaintenance == nil {
		t.Fatal("expected database backup runner to be initialized")
	}
	if app.MetadataSync == nil {
		t.Fatal("expected metadata sync runner to be initialized")
	}
}

func TestNewWithConfigWiresMetadataRefreshControl(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	runner, ok := app.RedisIngest.(*poller.RedisIngestRunner)
	if !ok {
		t.Fatalf("expected redis ingest runner, got %T", app.RedisIngest)
	}
	runnerValue := reflect.ValueOf(runner).Elem()
	writer := runnerValue.FieldByName("writer")
	if writer.IsNil() {
		t.Fatal("expected redis ingest writer")
	}
	if got := writer.Elem().Type().String(); got != "*poller.ControlAwareRedisInboxWriter" {
		t.Fatalf("expected control-aware redis inbox writer, got %s", got)
	}
	observer := runnerValue.FieldByName("controlObserver")
	if observer.IsNil() {
		t.Fatal("expected metadata sync runner to observe redis ingest control messages")
	}
	if got := observer.Elem().Type().String(); got != "*app.MetadataSyncRunner" {
		t.Fatalf("expected metadata sync runner observer, got %s", got)
	}
	metadataSyncPtr := reflect.ValueOf(app.MetadataSync).Pointer()
	if got := observer.Elem().Pointer(); got != metadataSyncPtr {
		t.Fatalf("expected redis ingest observer to share app metadata sync runner, got %x want %x", got, metadataSyncPtr)
	}
	writerObserver := writer.Elem().Elem().FieldByName("observer")
	if writerObserver.IsNil() {
		t.Fatal("expected redis inbox writer observer")
	}
	if got := writerObserver.Elem().Type().String(); got != "*app.MetadataSyncRunner" {
		t.Fatalf("expected redis inbox writer metadata sync observer, got %s", got)
	}
	if got := writerObserver.Elem().Pointer(); got != metadataSyncPtr {
		t.Fatalf("expected redis inbox writer observer to share app metadata sync runner, got %x want %x", got, metadataSyncPtr)
	}
}

func TestNewWithConfigExposesConfiguredCPAPublicURL(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.CPAPublicURL = "https://cpa.public.example.com/"
	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	app.Router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.Code)
	}
	body := resp.Body.String()
	if !strings.Contains(body, `"cpa_public_url":"https://cpa.public.example.com/"`) {
		t.Fatalf("expected CPA public URL in status response, got %s", body)
	}
	if strings.Contains(body, "cpa_management_url") {
		t.Fatalf("expected status response to use cpa_public_url instead of cpa_management_url, got %s", body)
	}
}

func TestNewWithConfigLiteLLMGatesCPAOnlyCapabilitiesAndRoutes(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.UsageSource = "litellm"
	cfg.LiteLLMBaseURL = "https://litellm.example.com"
	cfg.LiteLLMMasterKey = "master-key"
	cfg.LiteLLMSyncInterval = 10 * time.Second
	cfg.LiteLLMPageSize = 100
	cfg.LiteLLMOverlap = 5 * time.Minute

	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	if app.LiteLLMIngest == nil {
		t.Fatal("expected LiteLLM ingest runner")
	}
	if app.RedisIngest != nil || app.RedisProcess != nil || app.CPAErrors != nil || app.MetadataSync != nil || app.QuotaService != nil || app.QuotaAutoRefresh != nil {
		t.Fatalf("expected LiteLLM mode to omit CPA runtime dependencies: %+v", app)
	}

	status := httptest.NewRecorder()
	app.Router.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	if status.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", status.Code, status.Body.String())
	}
	for _, want := range []string{
		`"usage_source":"litellm"`,
		`"capabilities":{"api_key_analytics":true,"cpa_auth_files":false,"cpa_quota":false,"litellm_users":false,"litellm_teams":false,"viewer_key_login":true}`,
	} {
		if !strings.Contains(status.Body.String(), want) {
			t.Fatalf("expected LiteLLM status to include %s, got %s", want, status.Body.String())
		}
	}

	if !hasAppRoute(app.Router, http.MethodPost, "/api/v1/auth/api-key-login") {
		t.Fatal("expected LiteLLM to expose source-scoped viewer-key login")
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodPatch, "/api/v1/auth-files/status"},
		{http.MethodGet, "/api/v1/quota/inspection"},
		{http.MethodGet, "/api/v1/usage/api-keys/settings"},
		{http.MethodGet, "/api/v1/usage/events/:id/request-log"},
		{http.MethodGet, "/api/v1/usage/identities/:id/errors"},
	} {
		if hasAppRoute(app.Router, route.method, route.path) {
			t.Fatalf("expected LiteLLM to omit %s %s", route.method, route.path)
		}
	}
}

func TestNewWithConfigWiresEmbeddedJWTAuthModeAndRoutes(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.AuthEnabled = true
	cfg.AuthMode = config.AuthModeEmbeddedJWT
	cfg.UsageSource = "litellm"
	cfg.LiteLLMBaseURL = "https://litellm.example.com"
	cfg.LiteLLMMasterKey = "server-only-master"
	cfg.LiteLLMSyncInterval = 10 * time.Second
	cfg.LiteLLMPageSize = 100
	cfg.LiteLLMOverlap = 5 * time.Minute
	cfg.JWTIssuer = "https://webui.example.com"
	cfg.JWTAudience = "keeper"
	cfg.JWKSURL = "https://webui.example.com/.well-known/jwks.json"
	cfg.JWTAllowedAlgorithms = []string{"RS256"}
	cfg.JWTRoleClaim = "role"
	cfg.AuthSessionTTL = time.Hour
	cfg.ViewerKeyRevalidationTTL = time.Minute

	application, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer application.Close()

	if !hasAppRoute(application.Router, http.MethodPost, "/api/v1/auth/sso/exchange") {
		t.Fatal("embedded app did not expose SSO exchange")
	}
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/api-key-login"} {
		if hasAppRoute(application.Router, http.MethodPost, path) {
			t.Fatalf("embedded app exposed standalone auth route %s", path)
		}
	}
	response := httptest.NewRecorder()
	application.Router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"auth_mode":"embedded_jwt"`) || strings.Contains(response.Body.String(), `"viewer_key_login":true`) {
		t.Fatalf("unexpected embedded bootstrap: %d %s", response.Code, response.Body.String())
	}
}

func TestViewerKeyLoginCapabilityRequiresRegisteredSourceAdapter(t *testing.T) {
	if capabilities := sourceCapabilitiesFor(config.Config{UsageSource: "litellm"}); !capabilities.ViewerKeyLogin {
		t.Fatalf("registered LiteLLM adapter must advertise viewer-key login: %+v", capabilities)
	}
	if capabilities := sourceCapabilitiesFor(config.Config{UsageSource: "future-source"}); capabilities != (SourceCapabilities{}) {
		t.Fatalf("unsupported source must not advertise capabilities before adapter registration: %+v", capabilities)
	}
}

func TestNewWithConfigCLIProxyKeepsCPAOnlyRoutes(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.CPARequestLogAccessEnabled = true
	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/auth/api-key-login"},
		{http.MethodPatch, "/api/v1/auth-files/status"},
		{http.MethodGet, "/api/v1/quota/inspection"},
		{http.MethodGet, "/api/v1/usage/api-keys/settings"},
		{http.MethodGet, "/api/v1/usage/events/:id/request-log"},
		{http.MethodGet, "/api/v1/usage/identities/:id/errors"},
	} {
		if !hasAppRoute(app.Router, route.method, route.path) {
			t.Fatalf("expected CLIProxy to retain %s %s", route.method, route.path)
		}
	}
}

func hasAppRoute(router *gin.Engine, method, path string) bool {
	for _, route := range router.Routes() {
		if route.Method == method && route.Path == path {
			return true
		}
	}
	return false
}

func TestNewWithConfigLeavesExistingUsageForBackgroundAggregationRunner(t *testing.T) {
	// 准备：创建包含未聚合历史事件的旧数据库，并关闭 seed 连接模拟真实重启。
	dbPath := filepath.Join(t.TempDir(), "app-startup-overview-catchup.db")
	seedDB, err := repository.OpenDatabase(config.Config{SQLitePath: dbPath})
	if err != nil {
		t.Fatalf("OpenDatabase returned error: %v", err)
	}
	if _, _, err := repository.InsertUsageEvents(seedDB, []entities.UsageEvent{
		{EventKey: "legacy-event", APIGroupKey: "provider-a", Model: "claude-sonnet", Timestamp: time.Date(2026, 4, 16, 10, 10, 0, 0, time.UTC), TotalTokens: 150},
	}); err != nil {
		t.Fatalf("InsertUsageEvents returned error: %v", err)
	}
	seedSQL, err := seedDB.DB()
	if err != nil {
		t.Fatalf("load seed sql db: %v", err)
	}
	if err := seedSQL.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	logDir := t.TempDir()

	// 执行：构造 App，但不启动后台 Runner。
	cfg := testAppConfig(t)
	cfg.SQLitePath = dbPath
	cfg.LogFileEnabled = true
	cfg.LogDir = logDir
	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	// 断言：构造阶段不做同步 catch-up，工作保留给 App.Run 启动的后台任务。
	var checkpointCount int64
	if err := app.DB.Model(&entities.UsageAggregationCheckpoint{}).Where("name = ?", entities.UsageAggregationCheckpointOverview).Count(&checkpointCount).Error; err != nil {
		t.Fatalf("count overview checkpoints returned error: %v", err)
	}
	if checkpointCount != 0 {
		t.Fatalf("expected constructor not to block on overview catch-up, got %d checkpoints", checkpointCount)
	}
	logContent := readAppLogFile(t, logDir)
	if strings.Contains(logContent, "usage overview aggregation catch-up") {
		t.Fatalf("expected constructor log without synchronous catch-up, got %s", logContent)
	}
}

func TestNewWithConfigContinuesWhenRecentUsageCacheInitializationFails(t *testing.T) {
	cacheErr := errors.New("recent cache unavailable")
	previousNewRecentUsageCache := newUsageRecentEventCache
	newUsageRecentEventCache = func(*gorm.DB, repository.UsageRecentEventCacheOptions) (*repository.UsageRecentEventCache, error) {
		return nil, cacheErr
	}
	t.Cleanup(func() { newUsageRecentEventCache = previousNewRecentUsageCache })

	logDir := t.TempDir()
	cfg := testAppConfig(t)
	cfg.LogFileEnabled = true
	cfg.LogDir = logDir
	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()

	if app.RecentUsageCache != nil {
		t.Fatalf("expected recent usage cache to be nil after initialization failure, got %T", app.RecentUsageCache)
	}
	logContent := readAppLogFile(t, logDir)
	if !strings.Contains(logContent, "| error |") || !strings.Contains(logContent, "recent usage event cache initialization failed") || !strings.Contains(logContent, cacheErr.Error()) {
		t.Fatalf("expected error log for recent usage cache initialization failure, got %s", logContent)
	}
}

func TestNewWithConfigSkipsBackupRunnerWhenDisabled(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.BackupEnabled = false
	app, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()
	if app.BackupMaintenance != nil {
		t.Fatal("expected database backup runner to be skipped when backups are disabled")
	}
}

func TestNewWithConfigSelectsRedisIngestRunners(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()
	if _, ok := app.Poller.(*poller.RedisPoller); !ok {
		t.Fatalf("expected redis status provider to use redis poller, got %T", app.Poller)
	}
	if _, ok := app.RedisIngest.(*poller.RedisIngestRunner); !ok {
		t.Fatalf("expected redis ingest runner, got %T", app.RedisIngest)
	}
	if _, ok := app.RedisProcess.(*poller.RedisProcessRunner); !ok {
		t.Fatalf("expected redis process runner, got %T", app.RedisProcess)
	}
	if app.Maintenance == nil {
		t.Fatal("expected maintenance cleanup runner to be initialized")
	}
}

func TestNewWithConfigCreatesIndependentMaintenanceRunner(t *testing.T) {
	app, err := NewWithConfig(testAppConfig(t))
	if err != nil {
		t.Fatalf("NewWithConfig returned error: %v", err)
	}
	defer app.Close()
	if app.Poller == nil {
		t.Fatal("expected sync status provider to be initialized")
	}
	if app.RedisIngest == nil {
		t.Fatal("expected independent redis ingest runner to be initialized")
	}
	if app.RedisProcess == nil {
		t.Fatal("expected independent redis process runner to be initialized")
	}
	if app.Maintenance == nil {
		t.Fatal("expected independent maintenance runner to be initialized")
	}
}

func TestRunStartsPollerAndMaintenanceIndependently(t *testing.T) {
	// 准备：为每个后台 runner 配置独立启动信号，并使用非法端口让 HTTP 立即返回。
	cfg := testAppConfig(t)
	cfg.AppPort = "invalid-port"
	pullStarted := make(chan struct{})
	processStarted := make(chan struct{})
	aggregationStarted := make(chan struct{})
	maintenanceStarted := make(chan struct{})
	metadataStarted := make(chan struct{}, 1)
	backupStarted := make(chan struct{})
	maintenance := NewStorageCleanupRunner(&maintenanceSyncStub{})
	maintenance.sleep = func(context.Context, time.Duration) bool {
		close(maintenanceStarted)
		return false
	}
	metadataRunner := NewMetadataSyncRunner(&metadataSyncStub{}, time.Second)
	metadataRunner.onStart = func() {
		select {
		case metadataStarted <- struct{}{}:
		default:
		}
	}
	backupRunner := NewDatabaseBackupRunner(&databaseBackupWriterStub{}, nil, time.Second, 0)
	backupRunner.sleep = func(context.Context, time.Duration) bool {
		close(backupStarted)
		return false
	}
	statusProvider := &appRunStub{started: make(chan struct{})}
	app := &App{
		Config:            &cfg,
		Router:            gin.New(),
		Poller:            statusProvider,
		RedisIngest:       &appRunStub{started: pullStarted},
		RedisProcess:      &appRunStub{started: processStarted},
		UsageAggregation:  &appRunStub{started: aggregationStarted},
		Maintenance:       maintenance,
		MetadataSync:      metadataRunner,
		BackupMaintenance: backupRunner,
	}

	// 执行：启动 App，让所有后台任务共享同一生命周期 context。
	if err := app.Run(); err == nil {
		t.Fatal("expected Run to return an error for invalid port")
	}
	// 断言：ingest、process、aggregation、maintenance、metadata 与 backup 都已独立启动。
	select {
	case <-pullStarted:
	case <-time.After(time.Second):
		t.Fatal("expected redis ingest runner to start")
	}
	select {
	case <-processStarted:
	case <-time.After(time.Second):
		t.Fatal("expected redis process runner to start")
	}
	select {
	case <-aggregationStarted:
	case <-time.After(time.Second):
		t.Fatal("expected usage aggregation runner to start")
	}
	select {
	case <-statusProvider.started:
		t.Fatal("expected poller status provider not to be started as a background runner")
	default:
	}
	select {
	case <-maintenanceStarted:
	case <-time.After(time.Second):
		t.Fatal("expected maintenance runner to start")
	}
	select {
	case <-metadataStarted:
	case <-time.After(time.Second):
		t.Fatal("expected metadata sync runner to start")
	}
	select {
	case <-backupStarted:
	case <-time.After(time.Second):
		t.Fatal("expected database backup runner to start")
	}
}
func TestRunSetsQuotaServiceContext(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.AppPort = "invalid-port"
	quotaService := &quotaContextRecorder{contextSet: make(chan context.Context, 1)}
	app := &App{
		Config:       &cfg,
		Router:       gin.New(),
		QuotaService: quotaService,
	}

	if err := app.Run(); err == nil {
		t.Fatal("expected Run to return an error for invalid port")
	}
	select {
	case ctx := <-quotaService.contextSet:
		if ctx == nil {
			t.Fatal("expected quota service context to be non-nil")
		}
	case <-time.After(time.Second):
		t.Fatal("expected quota service context to be set")
	}
}

func TestRunSynchronizesCatalogBeforeStartingCatalogRunner(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.AppPort = "invalid-port"
	preflight := make(chan struct{}, 1)
	runnerStarted := make(chan struct{}, 1)
	catalog := &catalogSyncRecorder{preflight: preflight, started: runnerStarted}
	app := &App{Config: &cfg, Router: gin.New(), CatalogSync: catalog}

	if err := app.Run(); err == nil {
		t.Fatal("Run() succeeded with an invalid listen port")
	}
	select {
	case <-preflight:
	case <-time.After(time.Second):
		t.Fatal("catalog did not complete its startup synchronization")
	}
	select {
	case <-runnerStarted:
	case <-time.After(time.Second):
		t.Fatal("catalog runner did not start after startup synchronization")
	}
}

func TestRunCancelsBackgroundTasksWhenRouterStops(t *testing.T) {
	cfg := testAppConfig(t)
	cfg.AppPort = "invalid-port"
	backupStarted := make(chan struct{})
	backupCanceled := make(chan struct{})
	backupRunner := NewDatabaseBackupRunner(&databaseBackupWriterStub{}, nil, time.Second, 0)
	backupRunner.sleep = func(ctx context.Context, _ time.Duration) bool {
		close(backupStarted)
		<-ctx.Done()
		close(backupCanceled)
		return false
	}
	app := &App{
		Config:            &cfg,
		Router:            gin.New(),
		BackupMaintenance: backupRunner,
	}

	if err := app.Run(); err == nil {
		t.Fatal("expected Run to return an error for invalid port")
	}
	select {
	case <-backupStarted:
	case <-time.After(time.Second):
		t.Fatal("expected database backup runner to start")
	}
	select {
	case <-backupCanceled:
	case <-time.After(time.Second):
		t.Fatal("expected database backup runner context to be canceled")
	}
}

type quotaContextRecorder struct {
	contextSet chan context.Context
	waitCalled chan struct{}
}

func (r *quotaContextRecorder) SetRefreshContext(ctx context.Context) {
	r.contextSet <- ctx
}

func (r *quotaContextRecorder) StartAutoRefresh(context.Context) error {
	return nil
}

func (r *quotaContextRecorder) WaitRefreshTasks() {
	if r.waitCalled != nil {
		r.waitCalled <- struct{}{}
	}
}

func (r *quotaContextRecorder) StopRefreshTasks() {
	r.WaitRefreshTasks()
}

type appQuotaHandlerStub struct {
	block <-chan struct{}
	calls int
}

func (s *appQuotaHandlerStub) Check(ctx context.Context, input quota.ProviderInput) (quota.ProviderOutput, error) {
	select {
	case <-ctx.Done():
		return quota.ProviderOutput{}, ctx.Err()
	case <-s.block:
	}
	s.calls++
	return quota.ProviderOutput{Result: quota.ClaudeResult{Usage: &quota.ClaudeUsagePayload{FiveHour: &quota.ClaudeUsageWindow{Utilization: 25}}}}, nil
}

func (s *appQuotaHandlerStub) callCount() int {
	return s.calls
}

func waitForAppQuotaTaskStatus(t *testing.T, service *quota.Service, authIndex string, status quota.RefreshTaskStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var task quota.RefreshTaskResponse
	var err error
	for time.Now().Before(deadline) {
		task, err = service.GetRefreshTaskByAuthIndex(context.Background(), authIndex)
		if err == nil && task.Status == status {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("auth_index %s did not reach status %s, last task=%+v err=%v", authIndex, status, task, err)
}

type appRunStub struct {
	started chan struct{}
}

func (s *appRunStub) Run(context.Context) error {
	close(s.started)
	return nil
}

func (s *appRunStub) Status() poller.Status {
	return poller.Status{}
}

func captureAppInfoLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previousOutput := logrus.StandardLogger().Out
	previousFormatter := logrus.StandardLogger().Formatter
	previousLevel := logrus.GetLevel()
	logrus.SetOutput(&logs)
	logrus.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	logrus.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() {
		logrus.SetOutput(previousOutput)
		logrus.SetFormatter(previousFormatter)
		logrus.SetLevel(previousLevel)
	})
	return &logs
}

func readAppLogFile(t *testing.T, logDir string) string {
	t.Helper()
	path := filepath.Join(logDir, "cpa-usage-keeper-"+time.Now().Format("2006-01-02")+".log")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read app log file: %v", err)
	}
	return string(content)
}

func testAppConfig(t *testing.T) config.Config {
	t.Helper()
	return config.Config{
		AppPort:                   "8080",
		CPABaseURL:                "https://cpa.example.com",
		CPAManagementKey:          "secret",
		RedisQueueIdleInterval:    time.Second,
		MetadataSyncInterval:      30 * time.Second,
		SourceCatalogSyncInterval: 30 * time.Second,
		SQLitePath:                t.TempDir() + "/app.db",
		BackupEnabled:             true,
		BackupDir:                 t.TempDir() + "/backups",
		BackupRetentionDays:       7,
		RequestTimeout:            5 * time.Second,
		LogLevel:                  "info",
		LogFileEnabled:            false,
		LogRetentionDays:          7,
	}
}

type catalogSyncRecorder struct {
	preflight chan<- struct{}
	started   chan<- struct{}
}

func (r *catalogSyncRecorder) SyncOnce(context.Context) error {
	r.preflight <- struct{}{}
	return nil
}

func (r *catalogSyncRecorder) Run(ctx context.Context) error {
	r.started <- struct{}{}
	<-ctx.Done()
	return nil
}

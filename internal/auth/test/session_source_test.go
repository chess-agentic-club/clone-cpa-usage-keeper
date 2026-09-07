package test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
	"cpa-usage-keeper/internal/entities"
	"cpa-usage-keeper/internal/timeutil"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSessionManagerCreatesStandardSessionByDefault(t *testing.T) {
	manager := auth.NewSessionManager(time.Hour)

	token, _, err := manager.Create()
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	session, ok := manager.Get(token)
	if !ok {
		t.Fatal("expected created session to validate")
	}
	if session.Source != auth.SessionSourceStandard {
		t.Fatalf("expected default session source %q, got %q", auth.SessionSourceStandard, session.Source)
	}
	records := manager.List()
	if len(records) != 1 || records[0].Source != auth.SessionSourceStandard {
		t.Fatalf("expected listed session to expose standard source, got %+v", records)
	}
}

func TestSessionManagerCreatesEmbedSessionWithSource(t *testing.T) {
	manager := auth.NewSessionManager(time.Hour)

	token, _, err := manager.CreateWithSource(auth.SessionSourceEmbed)
	if err != nil {
		t.Fatalf("CreateWithSource returned error: %v", err)
	}
	session, ok := manager.Get(token)
	if !ok {
		t.Fatal("expected created session to validate")
	}
	if session.Source != auth.SessionSourceEmbed {
		t.Fatalf("expected embed session source, got %q", session.Source)
	}
	records := manager.List()
	if len(records) != 1 || records[0].Source != auth.SessionSourceEmbed {
		t.Fatalf("expected listed session to expose embed source, got %+v", records)
	}
}

func TestPersistentSessionManagerPreservesSessionSource(t *testing.T) {
	db := openAuthSourceDatabase(t)
	store := auth.NewGormSessionStore(db)
	manager := auth.NewPersistentSessionManager(time.Hour, store)

	token, _, err := manager.CreateWithSource(auth.SessionSourceEmbed)
	if err != nil {
		t.Fatalf("CreateWithSource returned error: %v", err)
	}

	restarted := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	session, ok := restarted.Get(token)
	if !ok {
		t.Fatal("expected persisted session to validate after restart")
	}
	if session.Source != auth.SessionSourceEmbed {
		t.Fatalf("expected persisted session source %q, got %q", auth.SessionSourceEmbed, session.Source)
	}
	records := restarted.List()
	if len(records) != 1 || records[0].Source != auth.SessionSourceEmbed {
		t.Fatalf("expected persisted list to expose embed source, got %+v", records)
	}
}

func TestPersistentSessionManagerNormalizesBlankSessionSource(t *testing.T) {
	db := openAuthSourceDatabase(t)
	now := timeutil.NormalizeStorageTime(time.Now())
	expiresAt := now.Add(time.Hour)
	token := "blank-source-token"
	if err := db.Exec(
		"INSERT INTO auth_sessions (token_hash, role, source, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		auth.SessionTokenHash(token),
		string(auth.RoleAdmin),
		"",
		expiresAt,
		now,
		now,
	).Error; err != nil {
		t.Fatalf("insert blank source session: %v", err)
	}

	manager := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	session, ok := manager.Get(token)
	if !ok {
		t.Fatal("expected blank-source persisted session to validate")
	}
	if session.Source != auth.SessionSourceStandard {
		t.Fatalf("expected blank source to normalize to %q, got %q", auth.SessionSourceStandard, session.Source)
	}
}

func TestPersistentSessionManagerPersistsSourceScopedViewerPrincipal(t *testing.T) {
	db := openAuthSourceDatabase(t)
	manager := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	principal := auth.ViewerPrincipal{
		SourceSystem: "litellm",
		APIGroupKey:  "cliproxy:principal-7f3a",
		DisplayName:  "LiteLLM Engineering",
	}
	metadata := auth.SessionClientMetadata{IP: "203.0.113.41", UserAgent: "Keeper-Test/1.0"}

	token, _, err := manager.CreateAPIKeyViewerForPrincipalWithSourceAndMetadata(principal, auth.SessionSourceEmbed, metadata)
	if err != nil {
		t.Fatalf("create source-scoped viewer session: %v", err)
	}

	created, ok := manager.Get(token)
	if !ok {
		t.Fatal("expected newly created source-scoped viewer session")
	}
	assertSourceScopedViewerSession(t, created, principal, auth.SessionSourceEmbed, metadata)

	restarted := auth.NewPersistentSessionManager(time.Hour, auth.NewGormSessionStore(db))
	persisted, ok := restarted.Get(token)
	if !ok {
		t.Fatal("expected source-scoped viewer session after restart")
	}
	assertSourceScopedViewerSession(t, persisted, principal, auth.SessionSourceEmbed, metadata)

	records := restarted.List()
	if len(records) != 1 {
		t.Fatalf("expected one persisted source-scoped viewer session, got %+v", records)
	}
	if records[0].ViewerSourceSystem != principal.SourceSystem || records[0].ViewerAPIGroupKey != principal.APIGroupKey || records[0].ViewerDisplayName != principal.DisplayName || records[0].CPAAPIKeyID != 0 {
		t.Fatalf("expected listed source-scoped viewer principal with no CPA key ID, got %+v", records[0])
	}
}

func TestSessionManagerRejectsIncompleteViewerPrincipalBeforeSaving(t *testing.T) {
	manager := auth.NewSessionManager(time.Hour)

	_, _, err := manager.CreateAPIKeyViewerForPrincipalWithSourceAndMetadata(auth.ViewerPrincipal{
		SourceSystem: "litellm",
		APIGroupKey:  "cliproxy:principal-7f3a",
	}, auth.SessionSourceStandard, auth.SessionClientMetadata{})
	if !errors.Is(err, auth.ErrViewerPrincipalUnavailable) {
		t.Fatalf("expected incomplete principal rejection, got %v", err)
	}
	if records := manager.List(); len(records) != 0 {
		t.Fatalf("expected incomplete principal not to create a session, got %+v", records)
	}
}

func assertSourceScopedViewerSession(t *testing.T, session auth.Session, principal auth.ViewerPrincipal, source auth.SessionSource, metadata auth.SessionClientMetadata) {
	t.Helper()
	if session.Role != auth.RoleAPIKeyViewer || session.Source != source || session.ViewerSourceSystem != principal.SourceSystem || session.ViewerAPIGroupKey != principal.APIGroupKey || session.ViewerDisplayName != principal.DisplayName || session.CPAAPIKeyID != 0 {
		t.Fatalf("unexpected source-scoped viewer session: %+v", session)
	}
	if session.LoginIP != metadata.IP || session.LastSeenIP != metadata.IP || session.UserAgent != metadata.UserAgent {
		t.Fatalf("unexpected source-scoped viewer metadata: %+v", session)
	}
}

func openAuthSourceDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "auth-source.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	if err := db.AutoMigrate(&entities.AuthSession{}); err != nil {
		t.Fatalf("auto migrate auth sessions: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql database: %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("close sqlite database: %v", err)
		}
	})
	return db
}

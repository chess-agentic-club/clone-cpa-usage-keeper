package test

import (
	"strings"
	"testing"

	"cpa-usage-keeper/internal/config"
)

var embeddedJWTEnvKeys = []string{
	"AUTH_MODE",
	"JWT_ISSUER",
	"JWT_AUDIENCE",
	"JWKS_URL",
	"JWT_ALLOWED_ALGORITHMS",
	"JWT_ROLE_CLAIM",
}

func TestAuthModeDefaultsToStandalone(t *testing.T) {
	clearEmbeddedJWTEnv(t)
	t.Setenv("LOGIN_PASSWORD", "")
	t.Setenv("TZ", "UTC")

	cfg, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, "LOGIN_PASSWORD=private-test-password\n")})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AuthMode != "standalone" {
		t.Fatalf("expected standalone auth mode by default, got %q", cfg.AuthMode)
	}
}

func TestEmbeddedJWTAuthLoadsStrictSettingsWithoutLoginPassword(t *testing.T) {
	clearEmbeddedJWTEnv(t)
	t.Setenv("LOGIN_PASSWORD", "")
	t.Setenv("TZ", "UTC")
	env := strings.Join([]string{
		"AUTH_MODE=embedded_jwt",
		"JWT_ISSUER=https://webui.example.com",
		"JWT_AUDIENCE=keeper",
		"JWKS_URL=https://webui.example.com/.well-known/jwks.json",
		"JWT_ALLOWED_ALGORITHMS=RS256",
		"JWT_ROLE_CLAIM=user_role",
		"LOGIN_PASSWORD=" + publicLoginPasswordPlaceholder,
		"",
	}, "\n")

	cfg, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, env)})
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AuthMode != "embedded_jwt" || cfg.JWTIssuer != "https://webui.example.com" || cfg.JWTAudience != "keeper" || cfg.JWKSURL != "https://webui.example.com/.well-known/jwks.json" || cfg.JWTRoleClaim != "user_role" {
		t.Fatalf("unexpected embedded JWT config: %+v", cfg)
	}
	if len(cfg.JWTAllowedAlgorithms) != 1 || cfg.JWTAllowedAlgorithms[0] != "RS256" {
		t.Fatalf("unexpected allowed algorithms: %v", cfg.JWTAllowedAlgorithms)
	}
}

func TestAuthModeRejectsUnsupportedValues(t *testing.T) {
	clearEmbeddedJWTEnv(t)
	t.Setenv("LOGIN_PASSWORD", "")
	t.Setenv("TZ", "UTC")

	_, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, "AUTH_MODE=oauth\nLOGIN_PASSWORD=private-test-password\n")})
	if err == nil || !strings.Contains(err.Error(), "AUTH_MODE") {
		t.Fatalf("expected AUTH_MODE validation error, got %v", err)
	}
}

func TestEmbeddedJWTAuthRequiresEveryJWTSetting(t *testing.T) {
	settings := []struct {
		key   string
		value string
	}{
		{key: "JWT_ISSUER", value: "https://webui.example.com"},
		{key: "JWT_AUDIENCE", value: "keeper"},
		{key: "JWKS_URL", value: "https://webui.example.com/.well-known/jwks.json"},
		{key: "JWT_ALLOWED_ALGORITHMS", value: "RS256"},
		{key: "JWT_ROLE_CLAIM", value: "role"},
	}
	for _, missing := range settings {
		t.Run(missing.key, func(t *testing.T) {
			clearEmbeddedJWTEnv(t)
			t.Setenv("LOGIN_PASSWORD", "")
			t.Setenv("TZ", "UTC")
			lines := []string{"AUTH_MODE=embedded_jwt"}
			for _, setting := range settings {
				if setting.key != missing.key {
					lines = append(lines, setting.key+"="+setting.value)
				}
			}

			_, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, strings.Join(lines, "\n")+"\n")})
			if err == nil || !strings.Contains(err.Error(), missing.key) {
				t.Fatalf("expected missing %s error, got %v", missing.key, err)
			}
		})
	}
}

func TestEmbeddedJWTAuthAllowsOnlyAnExactRS256AlgorithmList(t *testing.T) {
	for _, value := range []string{"HS256", "RS512", "RS256,HS256", "RS256,"} {
		t.Run(value, func(t *testing.T) {
			clearEmbeddedJWTEnv(t)
			t.Setenv("LOGIN_PASSWORD", "")
			t.Setenv("TZ", "UTC")
			env := strings.Join([]string{
				"AUTH_MODE=embedded_jwt",
				"JWT_ISSUER=https://webui.example.com",
				"JWT_AUDIENCE=keeper",
				"JWKS_URL=https://webui.example.com/.well-known/jwks.json",
				"JWT_ALLOWED_ALGORITHMS=" + value,
				"JWT_ROLE_CLAIM=role",
				"",
			}, "\n")

			_, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, env)})
			if err == nil || !strings.Contains(err.Error(), "JWT_ALLOWED_ALGORITHMS") {
				t.Fatalf("expected strict RS256 validation error, got %v", err)
			}
		})
	}
}

func TestEmbeddedJWTAuthRejectsUnsafeJWKSURLs(t *testing.T) {
	for _, value := range []string{"/jwks.json", "ftp://webui.example.com/jwks.json", "https://user:password@webui.example.com/jwks.json"} {
		t.Run(value, func(t *testing.T) {
			clearEmbeddedJWTEnv(t)
			t.Setenv("LOGIN_PASSWORD", "")
			t.Setenv("TZ", "UTC")
			env := strings.Join([]string{
				"AUTH_MODE=embedded_jwt",
				"JWT_ISSUER=https://webui.example.com",
				"JWT_AUDIENCE=keeper",
				"JWKS_URL=" + value,
				"JWT_ALLOWED_ALGORITHMS=RS256",
				"JWT_ROLE_CLAIM=role",
				"",
			}, "\n")

			_, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, env)})
			if err == nil || !strings.Contains(err.Error(), "JWKS_URL") {
				t.Fatalf("expected JWKS_URL validation error, got %v", err)
			}
		})
	}
}

func TestStandaloneProtectedAuthStillRequiresLoginPassword(t *testing.T) {
	clearEmbeddedJWTEnv(t)
	t.Setenv("LOGIN_PASSWORD", "")
	t.Setenv("TZ", "UTC")

	_, err := config.Load(config.LoadOptions{EnvFile: writeAuthConfig(t, "AUTH_MODE=standalone\nAUTH_ENABLED=true\nLOGIN_PASSWORD=\n")})
	if err == nil || !strings.Contains(err.Error(), "LOGIN_PASSWORD is required") {
		t.Fatalf("expected standalone login password validation error, got %v", err)
	}
}

func clearEmbeddedJWTEnv(t *testing.T) {
	t.Helper()
	for _, key := range embeddedJWTEnvKeys {
		t.Setenv(key, "")
	}
}

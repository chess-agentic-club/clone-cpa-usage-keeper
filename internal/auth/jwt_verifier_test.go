package auth_test

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cpa-usage-keeper/internal/auth"
)

const maxTestJWKSBodyBytes = 1 << 20

func TestJWTVerifierAcceptsValidUserAndAdministratorAssertions(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	verifier := newTestVerifier(server.URL)

	tests := []struct {
		name          string
		role          string
		administrator bool
	}{
		{name: "user", role: "user"},
		{name: "administrator", role: "admin", administrator: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims()
			claims["role"] = test.role
			raw := signRS256(t, key, "active", claims)

			principal, err := verifier.Verify(context.Background(), raw)
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if principal.Issuer != "open-webui" || principal.Subject != "user-123" || principal.Email != "alice@example.com" || principal.DisplayName != "Alice" || principal.IsAdministrator != test.administrator {
				t.Fatalf("unexpected principal: %+v", principal)
			}
		})
	}

	var _ auth.EmbeddedIdentityVerifier = verifier
}

func TestJWTVerifierUsesConfiguredRoleClaim(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	verifier := auth.NewJWTVerifier(auth.JWTVerifierConfig{
		Issuer:             "open-webui",
		Audience:           "keeper",
		JWKSURL:            server.URL,
		AllowedAlgorithms:  []string{"RS256"},
		RoleClaim:          "user_role",
		JWKSRequestTimeout: time.Second,
	})
	claims := validClaims()
	delete(claims, "role")
	claims["user_role"] = "admin"

	principal, err := verifier.Verify(context.Background(), signRS256(t, key, "active", claims))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !principal.IsAdministrator {
		t.Fatal("configured administrator role was not honored")
	}
}

func TestJWTVerifierPropagatesValidatedAssertionExpiry(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	verifier := newTestVerifier(server.URL)
	expiresAt := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	claims := validClaims()
	claims["exp"] = expiresAt.Unix()

	principal, err := verifier.Verify(context.Background(), signRS256(t, key, "active", claims))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !principal.AssertionExpiresAt.Equal(expiresAt) {
		t.Fatalf("assertion expiry = %s, want exact validated expiry %s", principal.AssertionExpiresAt, expiresAt)
	}
}

func TestJWTVerifierRejectsExtremeNotBeforeNumericDate(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	claims := validClaims()
	claims["nbf"] = json.Number("-1e1000")

	_, err := newTestVerifier(server.URL).Verify(context.Background(), signRS256(t, key, "active", claims))
	if !isInvalidAssertion(err) {
		t.Fatalf("expected out-of-range nbf rejection, got %v", err)
	}
}

func TestJWTVerifierRejectsInvalidRegisteredAndIdentityClaims(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong issuer", mutate: func(claims map[string]any) { claims["iss"] = "attacker" }},
		{name: "missing issuer", mutate: func(claims map[string]any) { delete(claims, "iss") }},
		{name: "wrong audience", mutate: func(claims map[string]any) { claims["aud"] = "other" }},
		{name: "missing audience", mutate: func(claims map[string]any) { delete(claims, "aud") }},
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{name: "missing expiration", mutate: func(claims map[string]any) { delete(claims, "exp") }},
		{name: "not active", mutate: func(claims map[string]any) { claims["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{name: "missing not before", mutate: func(claims map[string]any) { delete(claims, "nbf") }},
		{name: "missing subject", mutate: func(claims map[string]any) { delete(claims, "sub") }},
		{name: "blank subject", mutate: func(claims map[string]any) { claims["sub"] = " \t" }},
		{name: "missing role", mutate: func(claims map[string]any) { delete(claims, "role") }},
		{name: "blank role", mutate: func(claims map[string]any) { claims["role"] = " " }},
		{name: "invalid role", mutate: func(claims map[string]any) { claims["role"] = "owner" }},
		{name: "non-string role", mutate: func(claims map[string]any) { claims["role"] = []string{"admin"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validClaims()
			test.mutate(claims)
			verifier := newTestVerifier(server.URL)

			_, err := verifier.Verify(context.Background(), signRS256(t, key, "active", claims))
			if !isInvalidAssertion(err) {
				t.Fatalf("expected invalid identity assertion, got %v", err)
			}
		})
	}
}

func TestJWTVerifierRejectsAlgorithmConfusionAndMissingKeyID(t *testing.T) {
	key := newRSAKey(t)
	attackerKey := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	verifier := newTestVerifier(server.URL)
	claims := validClaims()

	tests := []struct {
		name string
		raw  string
	}{
		{name: "none", raw: signNone(t, "active", claims)},
		{name: "HS256 with RSA public material", raw: signHS256(t, marshalPublicKey(t, &key.PublicKey), "active", claims)},
		{name: "RS256 with wrong signing key", raw: signRS256(t, attackerKey, "active", claims)},
		{name: "missing key id", raw: signRS256(t, key, "", claims)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), test.raw)
			if !isInvalidAssertion(err) {
				t.Fatalf("expected invalid identity assertion, got %v", err)
			}
		})
	}
}

func TestJWTVerifierRejectsInvalidVerifierConfiguration(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	raw := signRS256(t, key, "active", validClaims())
	valid := auth.JWTVerifierConfig{
		Issuer:             "open-webui",
		Audience:           "keeper",
		JWKSURL:            server.URL,
		AllowedAlgorithms:  []string{"RS256"},
		RoleClaim:          "role",
		JWKSRequestTimeout: time.Second,
	}

	tests := []struct {
		name   string
		mutate func(*auth.JWTVerifierConfig)
	}{
		{name: "blank issuer", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.Issuer = "" }},
		{name: "blank audience", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.Audience = "" }},
		{name: "relative JWKS URL", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.JWKSURL = "/jwks.json" }},
		{name: "JWKS URL credentials", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.JWKSURL = "https://user:secret@example.com/jwks.json" }},
		{name: "HS256 allowed", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.AllowedAlgorithms = []string{"HS256"} }},
		{name: "multiple algorithms allowed", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.AllowedAlgorithms = []string{"RS256", "HS256"} }},
		{name: "blank role claim", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.RoleClaim = "" }},
		{name: "negative timeout", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.JWKSRequestTimeout = -time.Second }},
		{name: "negative cache TTL", mutate: func(cfg *auth.JWTVerifierConfig) { cfg.JWKSCacheTTL = -time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			_, err := auth.NewJWTVerifier(cfg).Verify(context.Background(), raw)
			if !isInvalidAssertion(err) {
				t.Fatalf("expected invalid verifier config to fail closed, got %v", err)
			}
		})
	}
}

func TestJWTVerifierRejectsKeyRemovedFromFreshJWKS(t *testing.T) {
	key := newRSAKey(t)
	var requests atomic.Int32
	var mu sync.RWMutex
	current := jwksDocument(t, testJWK("active", &key.PublicKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current)
	}))
	t.Cleanup(server.Close)
	verifier := newTestVerifierWithCacheTTL(server.URL, 20*time.Millisecond)
	raw := signRS256(t, key, "active", validClaims())

	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		t.Fatalf("prime verifier cache: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		t.Fatalf("reuse fresh verifier cache: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected known key reuse within freshness window, got %d requests", got)
	}
	mu.Lock()
	current = jwksDocument(t)
	mu.Unlock()
	time.Sleep(30 * time.Millisecond)

	if _, err := verifier.Verify(context.Background(), raw); !isInvalidAssertion(err) {
		t.Fatalf("expected removed cached key rejection, got %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected stale cached key to trigger one refresh, got %d requests", got)
	}
}

func TestJWTVerifierRejectsOldSignatureAfterSameKeyIDRotation(t *testing.T) {
	oldKey := newRSAKey(t)
	newKey := newRSAKey(t)
	var requests atomic.Int32
	var mu sync.RWMutex
	current := jwksDocument(t, testJWK("active", &oldKey.PublicKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current)
	}))
	t.Cleanup(server.Close)
	verifier := newTestVerifierWithCacheTTL(server.URL, 20*time.Millisecond)
	oldAssertion := signRS256(t, oldKey, "active", validClaims())
	newAssertion := signRS256(t, newKey, "active", validClaims())

	if _, err := verifier.Verify(context.Background(), oldAssertion); err != nil {
		t.Fatalf("prime verifier cache: %v", err)
	}
	mu.Lock()
	current = jwksDocument(t, testJWK("active", &newKey.PublicKey))
	mu.Unlock()
	time.Sleep(30 * time.Millisecond)

	if _, err := verifier.Verify(context.Background(), oldAssertion); !isInvalidAssertion(err) {
		t.Fatalf("expected rotated same-kid signature rejection, got %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected exactly one freshness refresh for same-kid rotation, got %d requests", got)
	}
	if _, err := verifier.Verify(context.Background(), newAssertion); err != nil {
		t.Fatalf("expected replacement same-kid signature acceptance: %v", err)
	}
}

func TestJWTVerifierFailsClosedWhenStaleJWKSRefreshFails(t *testing.T) {
	key := newRSAKey(t)
	var unavailable atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unavailable.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksDocument(t, testJWK("active", &key.PublicKey)))
	}))
	t.Cleanup(server.Close)
	verifier := newTestVerifierWithCacheTTL(server.URL, 20*time.Millisecond)
	raw := signRS256(t, key, "active", validClaims())

	if _, err := verifier.Verify(context.Background(), raw); err != nil {
		t.Fatalf("prime verifier cache: %v", err)
	}
	unavailable.Store(true)
	time.Sleep(30 * time.Millisecond)

	if _, err := verifier.Verify(context.Background(), raw); !isInvalidAssertion(err) {
		t.Fatalf("expected stale key rejection when refresh fails, got %v", err)
	}
}

func TestJWTVerifierRefreshesJWKSOnceForAnUnknownKeyID(t *testing.T) {
	oldKey := newRSAKey(t)
	newKey := newRSAKey(t)
	missingKey := newRSAKey(t)
	var requests atomic.Int32
	var mu sync.RWMutex
	current := jwksDocument(t, testJWK("old", &oldKey.PublicKey))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(current)
	}))
	t.Cleanup(server.Close)
	verifier := newTestVerifier(server.URL)

	if _, err := verifier.Verify(context.Background(), signRS256(t, oldKey, "old", validClaims())); err != nil {
		t.Fatalf("prime verifier cache: %v", err)
	}
	mu.Lock()
	current = jwksDocument(t, testJWK("new", &newKey.PublicKey))
	mu.Unlock()
	if _, err := verifier.Verify(context.Background(), signRS256(t, newKey, "new", validClaims())); err != nil {
		t.Fatalf("rotated key was not accepted after refresh: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected one initial fetch and one unknown-kid refresh, got %d requests", got)
	}

	before := requests.Load()
	_, err := verifier.Verify(context.Background(), signRS256(t, missingKey, "missing", validClaims()))
	if !isInvalidAssertion(err) {
		t.Fatalf("expected unknown key rejection, got %v", err)
	}
	if got := requests.Load(); got != before+1 {
		t.Fatalf("unknown kid must trigger exactly one refresh, got %d additional requests", got-before)
	}
}

func TestJWTVerifierRejectsMalformedOrAmbiguousJWKSKeys(t *testing.T) {
	key := newRSAKey(t)
	weakKey := newRSAKeyWithBits(t, 1024)
	valid := testJWK("active", &key.PublicKey)
	duplicate := testJWK("active", &key.PublicKey)
	blank := testJWK(" ", &key.PublicKey)
	wrongAlgorithm := testJWK("active", &key.PublicKey)
	wrongAlgorithm["alg"] = "RS512"
	wrongUse := testJWK("active", &key.PublicKey)
	wrongUse["use"] = "enc"
	nonRSA := testJWK("active", &key.PublicKey)
	nonRSA["kty"] = "oct"
	weakRSA := testJWK("active", &weakKey.PublicKey)

	tests := []struct {
		name       string
		keys       []map[string]any
		signingKey *rsa.PrivateKey
	}{
		{name: "duplicate key ids", keys: []map[string]any{valid, duplicate}},
		{name: "blank key id", keys: []map[string]any{blank}},
		{name: "wrong key algorithm", keys: []map[string]any{wrongAlgorithm}},
		{name: "wrong key use", keys: []map[string]any{wrongUse}},
		{name: "non RSA key", keys: []map[string]any{nonRSA}},
		{name: "weak RSA modulus", keys: []map[string]any{weakRSA}, signingKey: weakKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newStaticJWKSServer(t, jwksDocument(t, test.keys...))
			verifier := newTestVerifier(server.URL)
			signingKey := test.signingKey
			if signingKey == nil {
				signingKey = key
			}
			_, err := verifier.Verify(context.Background(), signRS256(t, signingKey, "active", validClaims()))
			if !isInvalidAssertion(err) {
				t.Fatalf("expected malformed JWKS rejection, got %v", err)
			}
		})
	}
}

func TestJWTVerifierRejectsJWKSRedirectsOversizedBodiesAndTimeouts(t *testing.T) {
	key := newRSAKey(t)
	raw := signRS256(t, key, "active", validClaims())

	t.Run("redirect", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			targetRequests.Add(1)
			_, _ = w.Write(jwksDocument(t, testJWK("active", &key.PublicKey)))
		}))
		defer target.Close()
		redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		}))
		defer redirect.Close()

		_, err := newTestVerifier(redirect.URL).Verify(context.Background(), raw)
		if !isInvalidAssertion(err) {
			t.Fatalf("expected redirect rejection, got %v", err)
		}
		if got := targetRequests.Load(); got != 0 {
			t.Fatalf("redirect target received %d requests", got)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"keys":[],"padding":"%s"}`, strings.Repeat("x", maxTestJWKSBodyBytes))
		}))
		defer server.Close()

		_, err := newTestVerifier(server.URL).Verify(context.Background(), raw)
		if !isInvalidAssertion(err) {
			t.Fatalf("expected oversized JWKS rejection, got %v", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		verifier := auth.NewJWTVerifier(auth.JWTVerifierConfig{
			Issuer:             "open-webui",
			Audience:           "keeper",
			JWKSURL:            server.URL,
			AllowedAlgorithms:  []string{"RS256"},
			RoleClaim:          "role",
			JWKSRequestTimeout: 25 * time.Millisecond,
		})
		started := time.Now()

		_, err := verifier.Verify(context.Background(), raw)
		if !isInvalidAssertion(err) {
			t.Fatalf("expected JWKS timeout rejection, got %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("JWKS request exceeded timeout bound: %s", elapsed)
		}
	})
}

func TestJWTVerifierDoesNotLeakRawAssertionsInErrors(t *testing.T) {
	key := newRSAKey(t)
	server := newStaticJWKSServer(t, jwksDocument(t, testJWK("active", &key.PublicKey)))
	verifier := newTestVerifier(server.URL)
	claims := validClaims()
	claims["aud"] = "secret-audience-marker"
	raw := signRS256(t, key, "active", claims)

	_, err := verifier.Verify(context.Background(), raw)
	if !isInvalidAssertion(err) {
		t.Fatalf("expected invalid identity assertion, got %v", err)
	}
	if strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "secret-audience-marker") {
		t.Fatalf("verification error leaked assertion material: %q", err)
	}
}

func newTestVerifier(jwksURL string) *auth.JWTVerifier {
	return newTestVerifierWithCacheTTL(jwksURL, 0)
}

func newTestVerifierWithCacheTTL(jwksURL string, cacheTTL time.Duration) *auth.JWTVerifier {
	return auth.NewJWTVerifier(auth.JWTVerifierConfig{
		Issuer:             "open-webui",
		Audience:           "keeper",
		JWKSURL:            jwksURL,
		AllowedAlgorithms:  []string{"RS256"},
		RoleClaim:          "role",
		JWKSRequestTimeout: time.Second,
		JWKSCacheTTL:       cacheTTL,
	})
}

func validClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   "open-webui",
		"aud":   "keeper",
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"sub":   "user-123",
		"role":  "user",
		"email": "alice@example.com",
		"name":  "Alice",
	}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	return newRSAKeyWithBits(t, 2048)
}

func newRSAKeyWithBits(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func testJWK(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func jwksDocument(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return body
}

func newStaticJWKSServer(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	unsigned := unsignedJWT(t, "RS256", kid, claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func signHS256(t *testing.T, secret []byte, kid string, claims map[string]any) string {
	t.Helper()
	unsigned := unsignedJWT(t, "HS256", kid, claims)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signNone(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	return unsignedJWT(t, "none", kid, claims) + "."
}

func unsignedJWT(t *testing.T, algorithm, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": algorithm, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	encodedHeader := encodeJSON(t, header)
	encodedClaims := encodeJSON(t, claims)
	return encodedHeader + "." + encodedClaims
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JWT part: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func marshalPublicKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	raw, err := json.Marshal(testJWK("active", key))
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return raw
}

func isInvalidAssertion(err error) bool {
	return errors.Is(err, auth.ErrInvalidIdentityAssertion)
}

package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultJWKSRequestTimeout = 5 * time.Second
	maxJWKSBodyBytes          = 1 << 20
	minimumRSAModulusBits     = 2048
)

// ErrInvalidIdentityAssertion is returned for every untrusted assertion or
// JWKS failure. The intentionally stable error does not expose bearer tokens
// or identity-provider response details.
var ErrInvalidIdentityAssertion = errors.New("invalid identity assertion")

// EmbeddedIdentityVerifier authenticates an assertion supplied by a trusted
// embedding application and returns only the resulting identity.
type EmbeddedIdentityVerifier interface {
	Verify(context.Context, string) (ExternalPrincipal, error)
}

// JWTVerifierConfig defines the exact Open WebUI JWT trust boundary.
type JWTVerifierConfig struct {
	Issuer             string
	Audience           string
	JWKSURL            string
	AllowedAlgorithms  []string
	RoleClaim          string
	JWKSRequestTimeout time.Duration
}

// JWTVerifier validates embedded Open WebUI assertions against a cached JWKS.
type JWTVerifier struct {
	config      JWTVerifierConfig
	configValid bool
	client      *http.Client

	cacheMu      sync.RWMutex
	keys         map[string]*rsa.PublicKey
	cacheLoaded  bool
	cacheVersion uint64
	refreshMu    sync.Mutex
}

// NewJWTVerifier constructs a verifier. Invalid verifier configuration fails
// closed from Verify because the constructor's established interface does not
// return an error.
func NewJWTVerifier(config JWTVerifierConfig) *JWTVerifier {
	config.AllowedAlgorithms = append([]string(nil), config.AllowedAlgorithms...)
	timeout := config.JWKSRequestTimeout
	if timeout == 0 {
		timeout = defaultJWKSRequestTimeout
	}
	return &JWTVerifier{
		config:      config,
		configValid: validJWTVerifierConfig(config),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Verify validates the signature and all required identity claims. Every
// failure is collapsed to ErrInvalidIdentityAssertion so raw assertions and
// upstream JWKS details cannot escape through returned errors.
func (verifier *JWTVerifier) Verify(ctx context.Context, raw string) (ExternalPrincipal, error) {
	if verifier == nil || !verifier.configValid || strings.TrimSpace(raw) == "" {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, ErrInvalidIdentityAssertion
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" || kid != strings.TrimSpace(kid) {
			return nil, ErrInvalidIdentityAssertion
		}
		key, ok := verifier.keyForID(ctx, kid)
		if !ok {
			return nil, ErrInvalidIdentityAssertion
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(verifier.config.Issuer),
		jwt.WithAudience(verifier.config.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithNotBeforeRequired(),
		jwt.WithJSONNumber(),
		jwt.WithStrictDecoding(),
	)
	if err != nil || token == nil || !token.Valid {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}

	subject, ok := requiredExactStringClaim(claims, "sub")
	if !ok {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}
	role, ok := requiredExactStringClaim(claims, verifier.config.RoleClaim)
	if !ok || (role != "user" && role != "admin") {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}
	email, ok := optionalStringClaim(claims, "email")
	if !ok {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}
	displayName, ok := optionalStringClaim(claims, "name")
	if !ok {
		return ExternalPrincipal{}, ErrInvalidIdentityAssertion
	}

	return ExternalPrincipal{
		Issuer:          verifier.config.Issuer,
		Subject:         subject,
		Email:           email,
		DisplayName:     displayName,
		IsAdministrator: role == "admin",
	}, nil
}

func validJWTVerifierConfig(config JWTVerifierConfig) bool {
	if config.Issuer == "" || config.Issuer != strings.TrimSpace(config.Issuer) ||
		config.Audience == "" || config.Audience != strings.TrimSpace(config.Audience) ||
		config.RoleClaim == "" || config.RoleClaim != strings.TrimSpace(config.RoleClaim) ||
		len(config.AllowedAlgorithms) != 1 || config.AllowedAlgorithms[0] != "RS256" ||
		config.JWKSRequestTimeout < 0 {
		return false
	}
	parsed, err := url.ParseRequestURI(config.JWKSURL)
	return err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.User == nil
}

func requiredExactStringClaim(claims jwt.MapClaims, name string) (string, bool) {
	value, ok := claims[name].(string)
	return value, ok && value != "" && value == strings.TrimSpace(value)
}

func optionalStringClaim(claims jwt.MapClaims, name string) (string, bool) {
	value, present := claims[name]
	if !present {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

func (verifier *JWTVerifier) keyForID(ctx context.Context, kid string) (*rsa.PublicKey, bool) {
	key, loaded, version := verifier.cachedKey(kid)
	if key != nil {
		return key, true
	}

	verifier.refreshMu.Lock()
	defer verifier.refreshMu.Unlock()
	key, currentLoaded, currentVersion := verifier.cachedKey(kid)
	if key != nil {
		return key, true
	}
	if currentVersion != version || loaded != currentLoaded {
		return nil, false
	}

	keys, ok := verifier.fetchKeys(ctx)
	if !ok {
		return nil, false
	}
	verifier.cacheMu.Lock()
	verifier.keys = keys
	verifier.cacheLoaded = true
	verifier.cacheVersion++
	key = verifier.keys[kid]
	verifier.cacheMu.Unlock()
	return key, key != nil
}

func (verifier *JWTVerifier) cachedKey(kid string) (*rsa.PublicKey, bool, uint64) {
	verifier.cacheMu.RLock()
	defer verifier.cacheMu.RUnlock()
	return verifier.keys[kid], verifier.cacheLoaded, verifier.cacheVersion
}

type jwksPayload struct {
	Keys []json.RawMessage `json:"keys"`
}

type rsaJWK struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func (verifier *JWTVerifier) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, bool) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, verifier.config.JWKSURL, nil)
	if err != nil {
		return nil, false
	}
	response, err := verifier.client.Do(request)
	if err != nil {
		return nil, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBodyBytes+1))
	if err != nil || len(body) > maxJWKSBodyBytes {
		return nil, false
	}

	var payload jwksPayload
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&payload); err != nil || payload.Keys == nil {
		return nil, false
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, false
	}
	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, rawKey := range payload.Keys {
		var encoded rsaJWK
		if err := json.Unmarshal(rawKey, &encoded); err != nil {
			return nil, false
		}
		if encoded.KeyID == "" || encoded.KeyID != strings.TrimSpace(encoded.KeyID) {
			return nil, false
		}
		if _, duplicate := keys[encoded.KeyID]; duplicate {
			return nil, false
		}
		if encoded.KeyType != "RSA" || encoded.Use != "sig" || encoded.Algorithm != "RS256" {
			return nil, false
		}
		key, ok := decodeRSAPublicKey(encoded.Modulus, encoded.Exponent)
		if !ok {
			return nil, false
		}
		keys[encoded.KeyID] = key
	}
	return keys, true
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return err
}

func decodeRSAPublicKey(modulus, exponent string) (*rsa.PublicKey, bool) {
	decode := base64.RawURLEncoding.Strict().DecodeString
	nBytes, err := decode(modulus)
	if err != nil || len(nBytes) == 0 {
		return nil, false
	}
	eBytes, err := decode(exponent)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, false
	}
	n := new(big.Int).SetBytes(nBytes)
	eBig := new(big.Int).SetBytes(eBytes)
	if n.Sign() <= 0 || n.BitLen() < minimumRSAModulusBits || !eBig.IsInt64() {
		return nil, false
	}
	e64 := eBig.Int64()
	if e64 < 3 || e64%2 == 0 || int64(int(e64)) != e64 {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: int(e64)}, true
}

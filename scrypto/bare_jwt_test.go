package scrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestIsActivationClaims(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		ClaimKeyPurpose.String(): ClaimPurposeActivation.String(),
	}
	if !IsActivationClaims(claims) {
		t.Error("expected activation claims to be recognized")
	}
	claims[ClaimKeyPurpose.String()] = ClaimPurposeAuthentication.String()
	if IsActivationClaims(claims) {
		t.Error("expected activation claims not to be recognized after change")
	}
}

func TestIsAuthenticationClaims(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		ClaimKeyPurpose.String(): ClaimPurposeAuthentication.String(),
	}
	if !IsAuthenticationClaims(claims) {
		t.Error("expected authentication claims to be recognized")
	}
	claims[ClaimKeyPurpose.String()] = ClaimPurposeActivation.String()
	if IsAuthenticationClaims(claims) {
		t.Error("expected authentication claims not to be recognized after change")
	}
}

func TestIsRefreshClaims(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		ClaimKeyPurpose.String(): ClaimPurposeRefresh.String(),
	}
	if !IsRefreshClaims(claims) {
		t.Error("expected refresh claims to be recognized")
	}
	claims[ClaimKeyPurpose.String()] = ClaimPurposeActivation.String()
	if IsRefreshClaims(claims) {
		t.Error("expected refresh claims not to be recognized after change")
	}
}

func TestEDDSASignAndParse(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	jwk := NewJWK(
		ED25519,
		priv,
		pub,
		"EdDSA",
		"test-ed25519",
	)

	issuer := "test-issuer-ed25519"
	bareJWT := NewBareJWT(jwk, issuer)

	customClaims := map[AllowedClaimKeys]any{
		ClaimKeyPurpose: ClaimPurposeActivation.String(),
		ClaimKeyNonce:   "nonce-value",
	}
	exp := time.Now().Add(1 * time.Hour)

	tokenStr, jti, err := bareJWT.SignWithClaims(customClaims, exp)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	if tokenStr == "" || jti == "" {
		t.Error("expected non-empty token string and jti")
	}

	parsedJWT, err := ParseBareJWT(tokenStr, jwk, ClaimKeyPurpose, ClaimKeyNonce)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if parsedJWT.Iss != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, parsedJWT.Iss)
	}
	if parsedJWT.Jti != jti {
		t.Errorf("expected jti %s, got %s", jti, parsedJWT.Jti)
	}
}

func TestRSASignAndParse(t *testing.T) {
	t.Parallel()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := NewJWK(
		RSA,
		rsaPriv,
		&rsaPriv.PublicKey,
		"RS256",
		"test-rsa",
	)

	issuer := "test-issuer-rsa"
	bareJWT := NewBareJWT(jwk, issuer)

	customClaims := map[AllowedClaimKeys]any{
		ClaimKeyPurpose: ClaimPurposeAuthentication.String(),
		ClaimKeyUID:     "user-123",
	}
	exp := time.Now().Add(1 * time.Hour)

	tokenStr, jti, err := bareJWT.SignWithClaims(customClaims, exp)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	if tokenStr == "" || jti == "" {
		t.Error("expected non-empty token string and jti")
	}

	parsedJWT, err := ParseBareJWT(tokenStr, jwk, ClaimKeyPurpose, ClaimKeyUID)
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if parsedJWT.Iss != issuer {
		t.Errorf("expected issuer %s, got %s", issuer, parsedJWT.Iss)
	}
	if parsedJWT.Jti != jti {
		t.Errorf("expected jti %s, got %s", jti, parsedJWT.Jti)
	}
}

func TestGetStringClaim_ExistingKey(t *testing.T) {
	t.Parallel()
	claims := jwt.MapClaims{
		"key1": "value1",
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	value := getClaim[string](bareJWT.MapClaims, "key1")
	if value != "value1" {
		t.Errorf("expected 'value1', got '%s'", value)
	}
}

func TestGetStringClaim_KeyNotFound(t *testing.T) {
	t.Parallel()
	claims := jwt.MapClaims{
		"key1": "value1",
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	value := getClaim[string](bareJWT.MapClaims, "missingKey")
	if value != "" {
		t.Errorf("expected empty string for non-existing key, got '%s'", value)
	}
}

func TestGetStringClaim_NonStringValuePanics(t *testing.T) {
	t.Parallel()
	claims := jwt.MapClaims{
		"key2": 123, // non-string value
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	// This call should panic because the value is not a string.
	value := getClaim[string](bareJWT.MapClaims, "key2")
	assert.Equal(t, "", value) // This line should not be reached due to panic.
}

func TestGetInt32Claim_ExistingKey(t *testing.T) {
	t.Parallel()
	// Set a claim value that is an integer.
	claims := jwt.MapClaims{
		"intClaim": int32(42),
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	value := getClaim[int32](bareJWT.MapClaims, "intClaim")
	if value != 42 {
		t.Errorf("expected 42, got %d", value)
	}
}

func TestGetInt32Claim_KeyNotFound(t *testing.T) {
	t.Parallel()
	// If the key is not present, assume the default value 0 is returned.
	claims := jwt.MapClaims{
		"anotherKey": int32(100),
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	value := getClaim[int32](bareJWT.MapClaims, "missingKey")
	if value != 0 {
		t.Errorf("expected 0 for missing key, got %d", value)
	}
}

func TestGetInt32Claim_NonIntValuePanics(t *testing.T) {
	t.Parallel()
	// If the claim value is not an integer, we expect a panic.
	claims := jwt.MapClaims{
		"intClaim": "not an integer",
	}
	bareJWT := BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{
		MapClaims: claims,
	}

	v := getClaim[int32](bareJWT.MapClaims, "intClaim")
	assert.Equal(t, int32(0), v)
}

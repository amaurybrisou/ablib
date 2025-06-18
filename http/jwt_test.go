package ablibhttp

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/amaurybrisou/ablib/scrypto"
	"github.com/google/uuid"
)

// TestValidateJWTMiddleware_MissingToken checks that a request with no token returns 401.
func TestValidateJWTMiddleware_MissingToken(t *testing.T) {
	pubKey := &rsa.PublicKey{}
	middleware := ValidateJWTMiddleware(
		&scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{PublicKey: pubKey},
	)

	// nextHandler simply returns 200 if called.
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No header or cookie set.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

// TestValidateJWTMiddleware_InvalidToken ensures that an invalid token leads to a 401 response.
func TestValidateJWTMiddleware_InvalidToken(t *testing.T) {
	pubKey := &rsa.PublicKey{}
	middleware := ValidateJWTMiddleware(
		&scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{PublicKey: pubKey},
	)

	nextHandlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Provide an invalid token.
	req.Header.Set("Authorization", "Bearer invalid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if nextHandlerCalled {
		t.Errorf("next handler should not be called on invalid token")
	}
}

func TestWithHeaderJWT_True(t *testing.T) {
	config := middlewareConfig[*rsa.PrivateKey, *rsa.PublicKey]{}
	opt := WithHeaderJWT[*rsa.PrivateKey, *rsa.PublicKey](true)
	opt(&config)

	if !config.allowHeaderJWT {
		t.Error("WithHeaderJWT(true) did not set AllowHeaderJWT to true")
	}
}

func TestWithHeaderJWT_False(t *testing.T) {
	conf := middlewareConfig[*rsa.PrivateKey, *rsa.PublicKey]{}
	// Change config so that it is not already false.
	conf.allowHeaderJWT = true

	opt := WithHeaderJWT[*rsa.PrivateKey, *rsa.PublicKey](false)
	opt(&conf)

	if conf.allowHeaderJWT {
		t.Error("WithHeaderJWT(false) did not set AllowHeaderJWT to false")
	}
}

// TestDefaultConfig_EmptyToken ensures that an empty token returns scrypto.ErrInvalidToken.
func TestDefaultConfig_EmptyToken(t *testing.T) {
	// Create a dummy jwk using a dummy rsa public key.
	dummyJWK := &scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{
		PublicKey: &rsa.PublicKey{},
	}

	// Use the default config.
	config := defaultConfig(dummyJWK)

	errExpected := scrypto.ErrInvalidToken
	_, err := config.parseTokenFunc("")
	if !errors.Is(err, errExpected) {
		t.Errorf("expected error %v, got %v", errExpected, err)
	}
}

// TestDefaultConfig_InvalidPurpose tests that a token with wrong purpose returns scrypto.ErrInvalidPurpose.
func TestDefaultConfig_InvalidPurpose(t *testing.T) {
	// Override with mock implementation
	parseTokenFunc := func(tokenStr string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		return nil, scrypto.ErrInvalidPurpose
	}

	dummyJWK := scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{
		PublicKey: &rsa.PublicKey{},
	}
	config := defaultConfig(&dummyJWK, WithParseTokenFunc(parseTokenFunc))

	_, err := config.parseTokenFunc("some-token")
	if !errors.Is(err, scrypto.ErrInvalidPurpose) {
		t.Errorf("expected error %v, got %v", scrypto.ErrInvalidPurpose, err)
	}
}

// TestDefaultConfig_ValidToken verifies that a valid token is properly parsed.
func TestDefaultConfig_ValidToken(t *testing.T) {
	parseTokenFunc := func(tokenStr string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		// If the token string is "valid", return a token with the correct purpose.
		if tokenStr == "valid" {
			return &scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey]{
				Purpose: scrypto.ClaimPurposeAuthentication.String(),
			}, nil
		}
		return nil, scrypto.ErrInvalidToken
	}

	dummyJWK := scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{
		PublicKey: &rsa.PublicKey{},
	}
	config := defaultConfig(&dummyJWK, WithParseTokenFunc(parseTokenFunc))

	token, err := config.parseTokenFunc("valid")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if token == nil {
		t.Errorf("expected a valid token, got nil")
	}
}

// Optional: A simple integration test using defaultConfig through the middleware.
func TestValidateJWTMiddleware_WithValidToken(t *testing.T) {
	parseTokenFunc := func(tokenStr string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		if tokenStr == "valid-token" {
			return &scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey]{
				Purpose: scrypto.ClaimPurposeAuthentication.String(),
			}, nil
		}
		return nil, scrypto.ErrInvalidToken
	}

	dummyJWK := scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{
		PublicKey: &rsa.PublicKey{},
	}
	middleware := ValidateJWTMiddleware(&dummyJWK, WithParseTokenFunc(parseTokenFunc))

	nextHandlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextHandlerCalled = true
	})

	handler := middleware(nextHandler)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextHandlerCalled {
		t.Errorf("expected next handler to be called for a valid token")
	}
}

func BenchmarkValidateJWTMiddleware(b *testing.B) {
	priv, pub, _ := scrypto.GenerateRSAKeys(2048)
	if priv == nil || pub == nil {
		b.Fatal("failed to generate RSA keys")
	}
	jwk := &scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{
		PrivateKey: priv,
		PublicKey:  pub,
		Kid:        "test-key",
	}

	token := scrypto.NewJWT(jwk, "test-issuer", uuid.NewString(), "")
	validTokenStr, _, _ := token.SignWithClaims(map[scrypto.AllowedClaimKeys]any{
		scrypto.ClaimKeyPurpose: scrypto.ClaimPurposeAuthentication,
	}, time.Now().Add(time.Hour))

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := ValidateJWTMiddleware(jwk)(nextHandler)

	b.Run("valid_token", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validTokenStr)
		rec := httptest.NewRecorder()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			middleware.ServeHTTP(rec, req)
		}
	})

	b.Run("invalid_token", func(b *testing.B) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer invalid.token")
		rec := httptest.NewRecorder()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			middleware.ServeHTTP(rec, req)
		}
	})
}

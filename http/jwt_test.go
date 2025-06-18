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

// helper to create a request with the Authorization header set when a token is
// provided.
func newJWTRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// helper to create a middleware handler with a provided parsing function. It
// returns the handler and a pointer to a bool that records whether the next
// handler has been called.
func newJWTMiddleware(parse func(string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error)) (http.Handler, *bool) {
	jwk := &scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{PublicKey: &rsa.PublicKey{}}
	called := new(bool)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { *called = true })
	handler := ValidateJWTMiddleware(jwk, WithParseTokenFunc(parse))(next)
	return handler, called
}

func TestValidateJWTMiddleware(t *testing.T) {
	t.Parallel()
	parseToken := func(tokenStr string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		if tokenStr == "valid" {
			return &scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey]{Purpose: scrypto.ClaimPurposeAuthentication.String()}, nil
		}
		if tokenStr == "" {
			return nil, scrypto.ErrInvalidToken
		}
		return nil, scrypto.ErrInvalidToken
	}

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		nextCalled     bool
	}{
		{name: "missing token", token: "", expectedStatus: http.StatusUnauthorized, nextCalled: false},
		{name: "invalid token", token: "invalid", expectedStatus: http.StatusUnauthorized, nextCalled: false},
		{name: "valid token", token: "valid", expectedStatus: http.StatusOK, nextCalled: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			handler, called := newJWTMiddleware(parseToken)
			req := newJWTRequest(tt.token)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
			if *called != tt.nextCalled {
				t.Errorf("expected next called %v, got %v", tt.nextCalled, *called)
			}
		})
	}
}

func TestWithHeaderJWT(t *testing.T) {
	tests := []struct {
		name  string
		allow bool
	}{
		{name: "true", allow: true},
		{name: "false", allow: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conf := middlewareConfig[*rsa.PrivateKey, *rsa.PublicKey]{}
			if !tt.allow {
				conf.allowHeaderJWT = true
			}

			WithHeaderJWT[*rsa.PrivateKey, *rsa.PublicKey](tt.allow)(&conf)

			if conf.allowHeaderJWT != tt.allow {
				t.Errorf("expected allowHeaderJWT %v, got %v", tt.allow, conf.allowHeaderJWT)
			}
		})
	}
}

// TestDefaultConfig_EmptyToken ensures that an empty token returns scrypto.ErrInvalidToken.
func TestDefaultConfig(t *testing.T) {
	dummy := &scrypto.JWK[*rsa.PrivateKey, *rsa.PublicKey]{PublicKey: &rsa.PublicKey{}}

	invalidPurpose := func(string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		return nil, scrypto.ErrInvalidPurpose
	}
	validParse := func(tokenStr string) (*scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
		if tokenStr == "valid" {
			return &scrypto.JWT[*rsa.PrivateKey, *rsa.PublicKey]{Purpose: scrypto.ClaimPurposeAuthentication.String()}, nil
		}
		return nil, scrypto.ErrInvalidToken
	}

	tests := []struct {
		name      string
		config    *middlewareConfig[*rsa.PrivateKey, *rsa.PublicKey]
		token     string
		expectErr error
	}{
		{name: "empty token", config: defaultConfig(dummy), token: "", expectErr: scrypto.ErrInvalidToken},
		{name: "invalid purpose", config: defaultConfig(dummy, WithParseTokenFunc(invalidPurpose)), token: "some-token", expectErr: scrypto.ErrInvalidPurpose},
		{name: "valid token", config: defaultConfig(dummy, WithParseTokenFunc(validParse)), token: "valid", expectErr: nil},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tok, err := tt.config.parseTokenFunc(tt.token)
			if !errors.Is(err, tt.expectErr) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}
			if tt.expectErr == nil && tok == nil {
				t.Error("expected token, got nil")
			}
		})
	}
}

// Optional: A simple integration test using defaultConfig through the middleware.

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

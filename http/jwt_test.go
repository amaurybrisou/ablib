package ablibhttp

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestValidateJWTMiddleware_MissingToken checks that a request with no token returns 401.
func TestValidateJWTMiddleware_MissingToken(t *testing.T) {
	pubKey := &rsa.PublicKey{}
	middleware := ValidateJWTMiddleware(pubKey)

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
	middleware := ValidateJWTMiddleware(pubKey)

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
	config := MiddlewareConfig{}
	opt := WithHeaderJWT(true)
	opt(&config)

	if !config.AllowHeaderJWT {
		t.Error("WithHeaderJWT(true) did not set AllowHeaderJWT to true")
	}
}

func TestWithHeaderJWT_False(t *testing.T) {
	conf := MiddlewareConfig{}
	// Change config so that it is not already false.
	conf.AllowHeaderJWT = true

	opt := WithHeaderJWT(false)
	opt(&conf)

	if conf.AllowHeaderJWT {
		t.Error("WithHeaderJWT(false) did not set AllowHeaderJWT to false")
	}
}

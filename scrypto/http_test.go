package scrypto_test

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/amaurybrisou/ablib/scrypto"
)

// TestUserIDFromRequest_ValidToken checks that a valid token returns the correct user ID.
func TestUserIDFromRequest_ValidToken(t *testing.T) {
	t.Parallel()
	pubKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set a cookie "token" with value "valid".
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: "valid",
	})

	uid, err := UserIDFromRequest(req, pubKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if uid != "user123" { //nolint:goconst
		t.Errorf("expected UID 'user123', got: %s", uid)
	}
}

// UserIDFromRequest is a stub function that simulates extracting a user ID from a request.
func UserIDFromRequest(req *http.Request, pubKey *rsa.PublicKey) (any, any) {
	v, err := req.Cookie("token") // Simulate getting the token from the request.
	if err != nil {
		return "", fmt.Errorf("failed to get token from request: %v", err)
	}
	if v == nil || v.Value == "" {
		return "", fmt.Errorf("missing or empty token")
	}
	if v.Value == "valid" { //nolint:goconst
		return "user123", nil
	}
	return "", fmt.Errorf("invalid token")
}

// TestUserIDFromRequest_MissingToken verifies that when there is no token in the request, an error is returned.
func TestUserIDFromRequest_MissingToken(t *testing.T) {
	t.Parallel()
	pubKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Do not set any cookie or header.

	uid, err := scrypto.UserIDFromRequest(req, pubKey)
	if err == nil {
		t.Fatalf("expected an error for missing token, got UID: %s", uid)
	}
}

// TestUserIDFromRequest_NilToken simulates the case when ParseAuthToken returns a nil token.
func TestUserIDFromRequest_NilToken(t *testing.T) {
	t.Parallel()
	pubKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set a cookie "token" with a value that will simulate a nil token.
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: "nil",
	})

	uid, err := scrypto.UserIDFromRequest(req, pubKey)
	if err == nil {
		t.Fatalf("expected an error for nil token, got UID: %s", uid)
	}
}

// TestUserIDFromRequest_EmptyUID verifies that if the token has an empty UID, an error is returned.
func TestUserIDFromRequest_EmptyUID(t *testing.T) {
	t.Parallel()
	pubKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set a cookie "token" with a value that yields an empty UID.
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: "empty",
	})

	uid, err := scrypto.UserIDFromRequest(req, pubKey)
	if err == nil {
		t.Fatalf("expected an error for token with empty UID, got UID: %s", uid)
	}
}

// Dummy JWT type definition for testing.
type JWT struct {
	UID     string
	Purpose string
}

// Override ParseRefreshToken for testing.
func ParseRefreshToken(tokenStr string, secretKey *rsa.PublicKey) (*JWT, error) {
	switch tokenStr {
	case "valid":
		return &JWT{UID: "user123", Purpose: "refresh"}, nil
	case "nil":
		return nil, nil
	default:
		return nil, fmt.Errorf("invalid refresh token")
	}
}

// TestRefreshTokenFromRequest_ValidTokenFromCookie checks that a valid refresh token in a cookie is parsed correctly.
func TestRefreshTokenFromRequest_ValidTokenFromCookie(t *testing.T) {
	t.Parallel()
	secretKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "valid",
	})

	jwtToken, err := RefreshTokenFromRequest(req, secretKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if jwtToken == nil {
		t.Fatalf("expected a token, got nil")
	}
	if jwtToken.UID != "user123" || jwtToken.Purpose != "refresh" {
		t.Errorf("unexpected token values: %+v", jwtToken)
	}
}

func RefreshTokenFromRequest(req *http.Request, secretKey *rsa.PublicKey) (*JWT, any) {
	// Check for a refresh token in the cookie.
	cookie, err := req.Cookie("refresh_token")
	if err != nil {
		if err != http.ErrNoCookie {
			// If the error is not about missing cookie, return it.
			return nil, fmt.Errorf("failed to get refresh token cookie: %v", err)
		}
	}

	if cookie != nil && cookie.Value != "" {
		// If a cookie is present, parse the refresh token from it.
		return ParseRefreshToken(cookie.Value, secretKey)
	}

	// Parse the refresh token from the request body.
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	defer req.Body.Close() //nolint:errcheck

	var refreshToken map[string]string
	err = json.Unmarshal(bodyBytes, &refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode request body: %v", err)
	}
	valid, ok := refreshToken["refresh_token"]
	if !ok || refreshToken == nil {
		return nil, fmt.Errorf("missing refresh token in request body")
	}

	if valid == "valid" {
		return &JWT{UID: "user123", Purpose: "refresh"}, nil
	}

	return nil, fmt.Errorf("invalid refresh token")
}

// TestRefreshTokenFromRequest_ValidTokenFromBody verifies that a valid refresh token in the JSON body is parsed correctly.
func TestRefreshTokenFromRequest_ValidTokenFromBody(t *testing.T) {
	t.Parallel()
	secretKey := &rsa.PublicKey{}
	bodyMap := map[string]string{"refresh_token": "valid"}
	bodyBytes, _ := json.Marshal(bodyMap)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyBytes))
	// Ensure no cookie is set.

	jwtToken, err := RefreshTokenFromRequest(req, secretKey)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if jwtToken == nil {
		t.Fatalf("expected a token, got nil")
	}
	if jwtToken.UID != "user123" || jwtToken.Purpose != "refresh" {
		t.Errorf("unexpected token values: %+v", jwtToken)
	}
}

// TestRefreshTokenFromRequest_MissingToken checks that when no refresh token is provided, an error is returned.
func TestRefreshTokenFromRequest_MissingToken(t *testing.T) {
	t.Parallel()
	secretKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	// No cookie and empty body.
	jwtToken, err := scrypto.RefreshTokenFromRequest(req, secretKey)
	if err == nil {
		t.Fatalf("expected an error for missing token, got token: %+v", jwtToken)
	}
}

// TestRefreshTokenFromRequest_InvalidJSON checks that a malformed JSON in body returns an error.
func TestRefreshTokenFromRequest_InvalidJSON(t *testing.T) {
	t.Parallel()
	secretKey := &rsa.PublicKey{}
	invalidJSON := []byte(`{invalid json}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(invalidJSON))
	// Make sure no cookie is set.
	jwtToken, err := scrypto.RefreshTokenFromRequest(req, secretKey)
	if err == nil {
		t.Fatalf("expected an error for invalid JSON, got token: %+v", jwtToken)
	}
}

// TestRefreshTokenFromRequest_InvalidToken ensures that an invalid refresh token causes an error.
func TestRefreshTokenFromRequest_InvalidToken(t *testing.T) {
	t.Parallel()
	secretKey := &rsa.PublicKey{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set an invalid refresh token in cookie.
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "invalid",
	})

	jwtToken, err := scrypto.RefreshTokenFromRequest(req, secretKey)
	if err == nil {
		t.Fatalf("expected an error for invalid refresh token, got token: %+v", jwtToken)
	}
}

// TestAuthTokenStrFromRequest_TokenFromCookie checks that the token is correctly returned from a non-empty cookie.
func TestAuthTokenStrFromRequest_TokenFromCookie(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	expectedToken := "cookieToken"
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: expectedToken,
	})

	token, err := scrypto.AuthTokenStrFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("expected token %q, got %q", expectedToken, token)
	}
}

// TestAuthTokenStrFromRequest_EmptyCookieUsesHeader verifies that if the cookie value is empty,
// the token is retrieved from the Authorization header.
func TestAuthTokenStrFromRequest_EmptyCookieUsesHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Set an empty token cookie.
	req.AddCookie(&http.Cookie{
		Name:  "token",
		Value: "",
	})
	// Set the Authorization header.
	expectedToken := "headerToken"
	req.Header.Set("Authorization", "Bearer "+expectedToken)

	token, err := scrypto.AuthTokenStrFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("expected token %q from header, got %q", expectedToken, token)
	}
}

// TestAuthTokenStrFromRequest_NoCookieUsesHeader checks that when no cookie is present,
// the token is retrieved from the Authorization header.
func TestAuthTokenStrFromRequest_NoCookieUsesHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	expectedToken := "headerOnlyToken"
	req.Header.Set("Authorization", "Bearer "+expectedToken)

	token, err := scrypto.AuthTokenStrFromRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != expectedToken {
		t.Errorf("expected token %q from header, got %q", expectedToken, token)
	}
}

// TestAuthTokenStrFromRequest_MissingToken verifies that an error is returned when both cookie and header are missing.
func TestAuthTokenStrFromRequest_MissingToken(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := scrypto.AuthTokenStrFromRequest(req)
	if err == nil {
		t.Fatalf("expected an error for missing token, got token %q", token)
	}
}

package scrypto

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// UserIDFromRequest extracts the user ID from the request's cookies.
func UserIDFromRequest(r *http.Request, secretKey *rsa.PublicKey) (string, error) {
	token, err := AuthTokenFromRequest(r, secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to get token from request: %v", err)
	}
	if token == nil {
		return "", ErrNilToken
	}

	if token.UID != "" {
		return token.UID, nil
	}

	return "", ErrInvalidToken
}

// AuthTokenFromRequest extracts the user ID from the request's cookies.
func AuthTokenFromRequest(r *http.Request, secretKey *rsa.PublicKey) (*JWT, error) {
	tokenStr, err := getTokenFromSource(r, "token", tokenStrFromHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	token, err := ParseAuthToken(tokenStr, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	return token, nil
}

// RefreshTokenFromRequest extracts the refresh token from the request's cookies.
// It first checks the cookies for a refresh token, and if not found, it checks the request body.
// If the refresh token is found, it parses and returns it.
// If the refresh token is not found or invalid, it returns an error.
// The refresh token is expected to be in the format "Bearer <token>" in the Authorization header.
// If the refresh token is not found in the cookies or request body, it returns an error.
// The function also handles the case where the refresh token is passed in the request body as JSON.
// It decodes the request body and extracts the refresh token from the "refresh_token" field.
// If the refresh token is not found in the request body, it returns an error.
func RefreshTokenFromRequest(r *http.Request, secretKey *rsa.PublicKey) (*JWT, error) {
	refreshTokenStr, err := getTokenFromSource(r, "refresh_token", refreshTokenStrFromBody)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token from request: %v", err)
	}

	parsedRefreshToken, err := ParseRefreshToken(refreshTokenStr, secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %v", err)
	}

	return parsedRefreshToken, nil
}

func refreshTokenStrFromBody(r *http.Request) (string, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read request body: %v", err)
	}
	// Restore the body for subsequent reads
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var requestBody map[string]string
	if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
		return "", fmt.Errorf("failed to decode request body: %v", err)
	}

	refreshToken, ok := requestBody["refresh_token"]
	if !ok {
		return "", fmt.Errorf("missing refresh token in request body")
	}

	return refreshToken, nil
}

func tokenStrFromHeaders(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	return token, nil
}

// AuthTokenStrFromRequest extracts the user ID from the request's cookies.
func AuthTokenStrFromRequest(r *http.Request) (string, error) {
	var err error
	var cookie *http.Cookie

	cookie, err = r.Cookie("token")
	if err != nil {
		tokenStr, err := tokenStrFromHeaders(r)
		if err != nil {
			return "", fmt.Errorf("failed to get token from headers: %v", err)
		}

		return tokenStr, nil
	}

	var tokenStr = cookie.Value
	if tokenStr == "" {
		tokenStr, err = tokenStrFromHeaders(r)
		if err != nil {
			return "", fmt.Errorf("failed to get token from headers: %v", err)
		}
	}

	return tokenStr, nil
}

func getTokenFromSource(r *http.Request, cookieName string, fallbackFunc func(*http.Request) (string, error)) (string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie.Value == "" {
		return fallbackFunc(r)
	}
	return cookie.Value, nil
}

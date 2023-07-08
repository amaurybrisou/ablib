package jwtlib_test

import (
	"testing"
	"time"

	"github.com/amaurybrisou/ablib/jwtlib"
)

func TestGenerateToken(t *testing.T) {
	jwt := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	})

	subject := "user123"
	expiration := time.Now().Add(time.Hour)
	notBefore := time.Now()

	token, err := jwt.GenerateToken(subject, expiration, notBefore)
	if err != nil {
		t.Errorf("GenerateToken returned an error: %v", err)
	}

	if token == "" {
		t.Errorf("GenerateToken returned an empty token")
	}

	// Verify the generated token
	claims, err := jwt.VerifyToken(token)
	if err != nil {
		t.Errorf("Failed to verify the generated token: %v", err)
	}

	if subject != claims["sub"] {
		t.Errorf("Generated token has incorrect subject: expected %s, got %s", subject, claims["sub"])
	}

	exp := expiration.Unix()
	if exp != int64(claims["exp"].(float64)) {
		t.Errorf("Generated token has incorrect expiration: expected %d, got %f", exp, claims["exp"].(float64))
	}

	iat := time.Now().Unix()
	if iat != int64(claims["iat"].(float64)) {
		t.Errorf("Generated token has incorrect issued-at time: expected %d, got %f", iat, claims["iat"].(float64))
	}

	nbf := notBefore.Unix()
	if nbf != int64(claims["nbf"].(float64)) {
		t.Errorf("Generated token has incorrect not-before time: expected %d, got %f", nbf, claims["nbf"].(float64))
	}

	if jwt.Issuer != claims["iss"] {
		t.Errorf("Generated token has incorrect issuer: expected %s, got %s", jwt.Issuer, claims["iss"])
	}

	if jwt.Audience != claims["aud"] {
		t.Errorf("Generated token has incorrect audience: expected %s, got %s", jwt.Audience, claims["aud"])
	}
}

func TestGenerateToken_Error(t *testing.T) {
	jwt := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	})

	subject := "user123"
	expiration := time.Now().Add(time.Hour)
	notBefore := time.Now()

	// Simulate an error in token generation
	jwt.SecretKey = "" // Invalid secret key
	_, err := jwt.GenerateToken(subject, expiration, notBefore)
	if err == nil {
		t.Errorf("GenerateToken should return an error for an invalid secret key")
	}

	// Restore valid secret key
	jwt.SecretKey = "my-secret-key"

	// Simulate an error in token signing
	expiration = time.Now().Add(-time.Hour) // Expired token
	_, err = jwt.GenerateToken(subject, expiration, notBefore)
	if err == nil {
		t.Errorf("GenerateToken should return an error for an expired token")
	}
}

func TestVerifyToken(t *testing.T) {
	jwt := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	})

	token := "invalid-token"

	_, err := jwt.VerifyToken(token)
	if err == nil {
		t.Errorf("VerifyToken should return an error for an invalid token")
	}

	validToken, _ := jwt.GenerateToken("user123", time.Now().Add(time.Hour), time.Now())
	claims, err := jwt.VerifyToken(validToken)
	if err != nil {
		t.Errorf("Failed to verify a valid token: %v", err)
	}

	if _, ok := claims["sub"]; !ok {
		t.Errorf("Verified token missing subject claim")
	}

	if _, ok := claims["exp"]; !ok {
		t.Errorf("Verified token missing expiration claim")
	}

	if _, ok := claims["iat"]; !ok {
		t.Errorf("Verified token missing issued-at claim")
	}

	if _, ok := claims["nbf"]; !ok {
		t.Errorf("Verified token missing not-before claim")
	}

	if _, ok := claims["iss"]; !ok {
		t.Errorf("Verified token missing issuer claim")
	}

	if _, ok := claims["aud"]; !ok {
		t.Errorf("Verified token missing audience claim")
	}
}

func TestVerifyToken_Error(t *testing.T) {
	jwt := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	})

	// Simulate an error in token verification
	token := "manipulated-token"
	_, err := jwt.VerifyToken(token)
	if err == nil {
		t.Errorf("VerifyToken should return an error for a manipulated token")
	}

	// Simulate an error in token parsing
	jwt.SecretKey = "" // Invalid secret key
	validToken, _ := jwt.GenerateToken("user123", time.Now().Add(time.Hour), time.Now())
	_, err = jwt.VerifyToken(validToken)
	if err == nil {
		t.Errorf("VerifyToken should return an error for an invalid secret key")
	}

	// Restore valid secret key
	jwt.SecretKey = "my-secret-key"

	// Simulate an error in token expiration
	expiredToken, _ := jwt.GenerateToken("user123", time.Now().Add(-time.Hour), time.Now())
	_, err = jwt.VerifyToken(expiredToken)
	if err == nil {
		t.Errorf("VerifyToken should return an error for an expired token")
	}
}

// Function to generate invalid tokens for testing purposes

func GenerateInvalidToken() (string, error) {
	invalidToken := "invalid-token-string"
	return invalidToken, nil
}

func GenerateExpiredToken() (string, error) {
	expiredToken, _ := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	}).GenerateToken("user123", time.Now().Add(-time.Hour), time.Now())
	return expiredToken, nil
}

func GenerateTokenWithInvalidSignature() (string, error) {
	validToken, _ := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	}).GenerateToken("user123", time.Now().Add(time.Hour), time.Now())

	invalidSignatureToken := validToken + "invalid-signature"
	return invalidSignatureToken, nil
}

func GenerateTokenWithInvalidIssuer() (string, error) {
	invalidIssuerToken, _ := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "invalid-issuer",
		Audience:  "my-audience",
	}).GenerateToken("user123", time.Now().Add(time.Hour), time.Now())
	return invalidIssuerToken, nil
}

func GenerateTokenWithInvalidAudience() (string, error) {
	invalidAudienceToken, _ := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "invalid-audience",
	}).GenerateToken("user123", time.Now().Add(time.Hour), time.Now())
	return invalidAudienceToken, nil
}

func GenerateValidToken() (string, error) {
	validToken, _ := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	}).GenerateToken("user123", time.Now().Add(time.Hour), time.Now())
	return validToken, nil
}

// Unit test function to test the VerifyToken function

func TestVerifyToken_InvalidTokens(t *testing.T) {
	jwt := jwtlib.New(jwtlib.Config{
		SecretKey: "my-secret-key",
		Issuer:    "my-issuer",
		Audience:  "my-audience",
	})

	// Generate invalid tokens for testing
	invalidToken, _ := GenerateInvalidToken()
	expiredToken, _ := GenerateExpiredToken()
	invalidSignatureToken, _ := GenerateTokenWithInvalidSignature()
	invalidIssuerToken, _ := GenerateTokenWithInvalidIssuer()
	invalidAudienceToken, _ := GenerateTokenWithInvalidAudience()

	// Test invalid tokens
	_, err := jwt.VerifyToken(invalidToken)
	if err == nil {
		t.Errorf("Expected error, got nil for invalid token")
	}

	_, err = jwt.VerifyToken(expiredToken)
	if err == nil {
		t.Errorf("Expectederror, got nil for expired token")
	}

	_, err = jwt.VerifyToken(invalidSignatureToken)
	if err == nil {
		t.Errorf("Expected error, got nil for token with invalid signature")
	}

	_, err = jwt.VerifyToken(invalidIssuerToken)
	if err == nil {
		t.Errorf("Expected error, got nil for token with invalid issuer")
	}

	_, err = jwt.VerifyToken(invalidAudienceToken)
	if err == nil {
		t.Errorf("Expected error, got nil for token with invalid audience")
	}
}

// Unit test function to test the VerifyToken function with a valid token

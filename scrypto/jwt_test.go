package scrypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

var (
	privateKey, _ = ParseED25519PrivateKeyFromB64("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUxVNzZyNjBqNlovUWlXRFZiYnYrUUIyL3N5WUFHLzY5QWxydWJIcWllVGsKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=")
	publicKey, _  = ParseED25519PublicKeyFromB64("LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQU13VXZQUDFQMmJMZFIwZ2tIV1hGY0Q3WlR6Z0x1MkcwRXArVXEvRUt1VUk9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=")
)

func TestNewJWT(t *testing.T) {
	uid := uuid.NewString()
	companyID := uuid.NewString()

	jwt := NewJWT(JWK{PrivateKey: privateKey}, "test-issuer", uid, companyID)

	require.Equal(t, uid, jwt.UID)
	require.Equal(t, "test-issuer", jwt.Iss)
}

func TestParseToken(t *testing.T) {
	uid := uuid.NewString()
	companyID := uuid.NewString()

	token := NewJWT(JWK{PrivateKey: privateKey}, "test-issuer", uid, companyID)

	exp := time.Now().Add(time.Hour).Unix()
	tokenString, _, err := token.SignED25519(time.Unix(exp, 0),
		map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
	require.NoError(t, err)

	parsedJWT, err := ParseTokenED25519(tokenString, publicKey)
	require.NoError(t, err)
	require.Equal(t, uid, parsedJWT.UID)
	require.Equal(t, "test-issuer", parsedJWT.Iss)
}

func TestSign(t *testing.T) {
	uid := uuid.NewString()
	companyID := uuid.NewString()

	t.Run("not expired", func(t *testing.T) {
		token := NewJWT(JWK{PrivateKey: privateKey}, "test-issuer", uid, companyID)

		// Set expiration to 1 hour from now
		exp := time.Now().Add(time.Hour)

		tokenString, _, err := token.SignED25519(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Verify token
		parsedToken, err := ParseTokenED25519(tokenString, publicKey)
		require.NoError(t, err)

		require.Equal(t, uid, parsedToken.UID)
	})

	t.Run("expired", func(t *testing.T) {
		token := NewJWT(JWK{PrivateKey: privateKey}, "test-issuer", uid, companyID)

		// Set expiration to 1 hour from now
		exp := time.Now().Add(-time.Hour)

		tokenString, _, err := token.SignED25519(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Verify token
		parsedToken, err := ParseTokenED25519(tokenString, publicKey)
		require.Error(t, err, ErrExpiredToken)

		require.Nil(t, parsedToken)
	})
}

// generateRSAKey creates a new RSA key pair for testing.
func generateRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return rsaPriv, &rsaPriv.PublicKey
}

func TestValidateContextGRPC(t *testing.T) {
	rsaPriv, rsaPub := generateRSAKey(t)

	t.Run("missing metadata", func(t *testing.T) {
		ctx := context.Background()
		token, err := ValidateContextGRPC(ctx, rsaPub)
		require.Error(t, err)
		require.Nil(t, token)
	})

	t.Run("invalid token", func(t *testing.T) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Authorization", "Bearer invalidtoken"))
		token, err := ValidateContextGRPC(ctx, rsaPub)
		require.Error(t, err)
		require.Nil(t, token)
	})

	t.Run("valid token", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT using RSA signing.
		jwtInstance := NewJWT(JWK{PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.Sign(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Authorization", "Bearer "+tokenString))
		parsedJWT, err := ValidateContextGRPC(ctx, rsaPub)
		require.NoError(t, err)
		require.Equal(t, uid, parsedJWT.UID)
		require.Equal(t, "test-issuer", parsedJWT.Iss)
	})
}
func TestParseRefreshToken(t *testing.T) {
	// Generate an RSA key pair for testing.
	rsaPriv, rsaPub := generateRSAKey(t)

	t.Run("valid refresh token", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT and sign it with RSA using a refresh purpose.
		jwtInstance := NewJWT(JWK{PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.Sign(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := ParseRefreshToken(tokenString, rsaPub)
		require.NoError(t, err)
		require.Equal(t, "test-issuer", parsedJWT.Iss)
		require.Equal(t, ClaimPurposeRefresh.String(), parsedJWT.Purpose)
	})

	t.Run("invalid token purpose", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT token but sign it with an authentication purpose.
		// This should fail when parsing as a refresh token.
		jwtInstance := NewJWT(JWK{PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.Sign(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := ParseRefreshToken(tokenString, rsaPub)
		require.Error(t, err)
		require.Nil(t, parsedJWT)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT token with a refresh purpose but an expiration time in the past.
		jwtInstance := NewJWT(JWK{PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(-time.Hour)
		tokenString, _, err := jwtInstance.Sign(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := ParseRefreshToken(tokenString, rsaPub)
		// Expect an error because the token is expired.
		require.Error(t, err)
		require.Nil(t, parsedJWT)
	})
}

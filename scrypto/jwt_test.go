package scrypto

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// Setup variables for keys
var (
	privateED25519Key, publicED25519Key, _ = GenerateED25519Keys()
	rsaPriv, rsaPub                        = generateRSAKey(nil)
)

func TestNewJWT(t *testing.T) {
	t.Parallel()
	uid := uuid.NewString()
	companyID := uuid.NewString()

	privateED25519Key, _, err := GenerateED25519Keys()
	require.NoError(t, err)

	jwt := NewJWT(&JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privateED25519Key, Kid: "test-key"}, "test-issuer", uid, companyID)

	require.Equal(t, uid, jwt.UID)
	require.Equal(t, "test-issuer", jwt.Iss)
}

func TestParseToken(t *testing.T) {
	t.Parallel()
	uid := uuid.NewString()
	companyID := uuid.NewString()

	privateED25519Key, publicED25519Key, err := GenerateED25519Keys()
	require.NoError(t, err)

	token := NewJWT(&JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privateED25519Key, Kid: "test-key"}, "test-issuer", uid, companyID)

	exp := time.Now().Add(time.Hour).Unix()
	tokenString, _, err := token.signED25519(time.Unix(exp, 0),
		map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
	require.NoError(t, err)

	parsedJWT, err := ParseAuthTokenED25519(tokenString, publicED25519Key)
	require.NoError(t, err)
	require.Equal(t, uid, parsedJWT.UID)
	require.Equal(t, "test-issuer", parsedJWT.Iss)
}

func TestSignED25519(t *testing.T) {
	t.Parallel()
	uid := uuid.NewString()
	companyID := uuid.NewString()

	t.Run("not expired", func(t *testing.T) {
		privKey, pubKey, err := GenerateED25519Keys()
		require.NoError(t, err)

		token := NewJWT(&JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privKey, Kid: "test-key"}, "test-issuer", uid, companyID)

		exp := time.Now().Add(time.Hour)
		tokenString, _, err := token.signED25519(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedToken, err := ParseAuthTokenED25519(tokenString, pubKey)
		require.NoError(t, err)
		require.Equal(t, uid, parsedToken.UID)
	})

	t.Run("Invalid Purpose", func(t *testing.T) {
		privKey, pubKey, err := GenerateED25519Keys()
		require.NoError(t, err)

		token := NewJWT(&JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privKey, Kid: "test-key"}, "test-issuer", uid, companyID)

		exp := time.Now().Add(time.Hour)
		tokenString, _, err := token.signED25519(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedToken, err := ParseAuthTokenED25519(tokenString, pubKey)
		require.Error(t, err)
		require.Equal(t, ErrInvalidPurpose, err)
		require.Nil(t, parsedToken)
	})

	t.Run("expired", func(t *testing.T) {
		privKey, pubKey, err := GenerateED25519Keys()
		require.NoError(t, err)

		token := NewJWT(&JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privKey, Kid: "test-key"}, "test-issuer", uid, companyID)

		exp := time.Now().Add(-time.Hour)
		tokenString, _, err := token.signED25519(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedToken, err := ParseAuthTokenED25519(tokenString, pubKey)
		require.Error(t, err)
		require.Equal(t, "token has invalid claims: token is expired", err.Error())
		require.Nil(t, parsedToken)
	})
}

// generateRSAKey creates a new RSA key pair for testing.
func generateRSAKey(_ *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, pub, err := GenerateRSAKeys(2048)
	if err != nil {
		panic(err) // In test setup code, panicking is acceptable
	}
	return priv, pub
}

func TestSignRSA(t *testing.T) {
	t.Parallel()
	uid := uuid.NewString()
	companyID := uuid.NewString()

	t.Run("not expired", func(t *testing.T) {
		rsaPriv, rsaPub := generateRSAKey(nil)
		token := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)

		exp := time.Now().Add(time.Hour)
		tokenString, _, err := token.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedToken, err := ParseAuthTokenRSA(tokenString, rsaPub)
		require.NoError(t, err)
		require.Equal(t, uid, parsedToken.UID)
	})

	t.Run("Invalid Purpose", func(t *testing.T) {
		token := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)

		// Set expiration to 1 hour from now
		exp := time.Now().Add(time.Hour)

		tokenString, _, err := token.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Verify token
		parsedToken, err := ParseAuthTokenRSA(tokenString, rsaPub)
		require.Error(t, err, ErrInvalidPurpose)
		require.Nil(t, parsedToken)
	})

	t.Run("expired", func(t *testing.T) {
		token := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)

		// Set expiration to 1 hour from now
		exp := time.Now().Add(-time.Hour)

		tokenString, _, err := token.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		// Verify token
		parsedToken, err := ParseAuthTokenRSA(tokenString, rsaPub)
		require.Error(t, err, ErrExpiredToken)

		require.Nil(t, parsedToken)
	})
}

func TestValidateContextGRPC(t *testing.T) {
	t.Parallel()
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
		jwtInstance := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.signRSA(exp, map[AllowedClaimKeys]any{
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
	t.Parallel()
	// Generate an RSA key pair for testing.
	rsaPriv, rsaPub := generateRSAKey(t)

	t.Run("valid refresh token", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT and sign it with RSA using a refresh purpose.
		jwtInstance := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := parseRefreshTokenRSA(tokenString, rsaPub)
		require.NoError(t, err)
		require.Equal(t, "test-issuer", parsedJWT.Iss)
		require.Equal(t, ClaimPurposeRefresh.String(), parsedJWT.Purpose)
	})

	t.Run("invalid token purpose", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT token but sign it with an authentication purpose.
		// This should fail when parsing as a refresh token.
		jwtInstance := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(time.Hour)
		tokenString, _, err := jwtInstance.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeAuthentication,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := parseRefreshTokenRSA(tokenString, rsaPub)
		require.Error(t, err)
		require.Nil(t, parsedJWT)
	})

	t.Run("expired refresh token", func(t *testing.T) {
		uid := uuid.NewString()
		companyID := uuid.NewString()

		// Create a JWT token with a refresh purpose but an expiration time in the past.
		jwtInstance := NewJWT(&JWK[*rsa.PrivateKey, *rsa.PublicKey]{KeyType: RSA, PrivateKey: rsaPriv, Kid: "test-key"}, "test-issuer", uid, companyID)
		exp := time.Now().Add(-time.Hour)
		tokenString, _, err := jwtInstance.signRSA(exp, map[AllowedClaimKeys]any{
			ClaimKeyPurpose: ClaimPurposeRefresh,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenString)

		parsedJWT, err := parseRefreshTokenRSA(tokenString, rsaPub)
		// Expect an error because the token is expired.
		require.Error(t, err)
		require.Nil(t, parsedJWT)
	})
}

// TestParseAuthTokenValid tests parsing a valid JWT token.
func TestParseAuthTokenValid(t *testing.T) {
	t.Parallel()
	// Generate a new uid and companyID.
	uid := uuid.NewString()
	companyID := uuid.NewString()

	// Construct a JWK for signing (private key) and for verifying (public key).
	jwkPriv := &JWK[ed25519.PrivateKey, ed25519.PublicKey]{PrivateKey: privateED25519Key, Kid: "test-key"}
	jwtInstance := NewJWT(jwkPriv, "test-issuer", uid, companyID)

	// Sign the token with an expiration 1 hour in the future.
	exp := time.Now().Add(time.Hour)
	tokenString, _, err := jwtInstance.signED25519(exp, map[AllowedClaimKeys]any{
		ClaimKeyPurpose: ClaimPurposeAuthentication,
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	// Prepare a public key JWK for parsing.
	jwkPub := &JWK[ed25519.PrivateKey, ed25519.PublicKey]{PublicKey: publicED25519Key, Kid: "test-key"}

	parsedJWT, err := ParseAuthToken(tokenString, jwkPub)
	require.NoError(t, err)
	require.NotNil(t, parsedJWT)
	require.Equal(t, uid, parsedJWT.UID)
	require.Equal(t, "test-issuer", parsedJWT.Iss)
}

// TestParseAuthTokenInvalid tests that parsing an invalid token returns an error.
func TestParseAuthTokenInvalid(t *testing.T) {
	t.Parallel()
	// Prepare a public key JWK.
	jwkPub := &JWK[ed25519.PrivateKey, ed25519.PublicKey]{PublicKey: publicED25519Key, Kid: "test-key"}

	// Attempt to parse an invalid token string.
	invalidToken := "this.is.not.a.valid.token"
	parsedJWT, err := ParseAuthToken(invalidToken, jwkPub)
	require.Error(t, err)
	require.Nil(t, parsedJWT)
}

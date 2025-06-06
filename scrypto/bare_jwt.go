// Package scrypto provides utilities for working with JSON Web Tokens (JWTs).
package scrypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// BareJWT represents a JSON Web Token (JWT) with additional fields.
type BareJWT[PRIV PrivateKeyPair, PUB PublicKeyPair] struct {
	// JWK represents the JSON Web Key (JWK) used to sign the JWT.
	*JWK[PRIV, PUB] `json:"jwk"`
	// Iss is the issuer of the JWT.
	Iss string `json:"iss"`
	// Iat is the issued at time of the JWT.
	Iat int64 `json:"iat"`
	// Exp is the expiration time of the JWT.
	Exp int64 `json:"exp"`
	// Jti is the JWT ID, a unique identifier for the JWT.
	Kid string `json:"kid"`
	// Jti is the JWT ID, a unique identifier for the JWT.
	Jti string `json:"jti"`
	jwt.MapClaims
}

// NewBareJWT creates a new BareJWT instance with the provided private key and issuer.
func NewBareJWT[PRIV PrivateKeyPair, PUB PublicKeyPair](privateKey *JWK[PRIV, PUB], issuer string) BareJWT[PRIV, PUB] {
	return BareJWT[PRIV, PUB]{
		JWK: privateKey,
		Iss: issuer,
		Kid: privateKey.Kid,
	}
}

// SignWithClaims signs the JWT with the provided claims and expiration time.
func (m *BareJWT[PRIV, PUB]) SignWithClaims(customClaims map[AllowedClaimKeys]any, exp time.Time) (string, string, error) {
	var method jwt.SigningMethod
	switch m.KeyType {
	case ED25519:
		method = jwt.SigningMethodEdDSA
	case RSA:
		method = jwt.SigningMethodRS256
	default:
		return "", "", fmt.Errorf("unsupported key type: %v", m.KeyType)
	}
	return signWithClaimsCommon(customClaims, exp, m.PrivateKey, method, m.Kid, m.Iss)
}

func signWithClaimsCommon(customClaims map[AllowedClaimKeys]any, exp time.Time, privateKey any, method jwt.SigningMethod, kid, iss string) (string, string, error) {
	jti := uuid.NewString()

	claims := make(map[string]any)
	for k, v := range customClaims {
		claims[string(k)] = v
	}
	claims["jti"] = jti
	claims["exp"] = exp.Unix()
	claims["iss"] = iss
	claims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(method, jwt.MapClaims(claims), func(token *jwt.Token) {
		token.Header["kid"] = kid
	})
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// ParseBareJWT parses a JWT token string and returns a BareJWT object.
func ParseBareJWT[PRIV PrivateKeyPair, PUB PublicKeyPair](tokenString string, jwk *JWK[PRIV, PUB], claimKeys ...AllowedClaimKeys) (BareJWT[PRIV, PUB], error) {
	var method jwt.SigningMethod
	switch jwk.KeyType {
	case ED25519:
		method = jwt.SigningMethodEdDSA
	case RSA:
		method = jwt.SigningMethodRS256
	default:
		return BareJWT[PRIV, PUB]{}, fmt.Errorf("unsupported key type: %v", jwk.KeyType)
	}

	bareJWT, err := parseBareJWTCommon[PRIV, PUB](tokenString, jwk.PublicKey, method)
	if err != nil {
		return BareJWT[PRIV, PUB]{}, err
	}

	return bareJWT, nil
}

// parseBareJWTED25519 parses a JWT token string and returns a BareJWT object.
func parseBareJWTED25519(tokenString string, publicKey ed25519.PublicKey, claimKeys ...AllowedClaimKeys) (BareJWT[ed25519.PrivateKey, ed25519.PublicKey], error) {
	bareJWT, err := parseBareJWTCommon[ed25519.PrivateKey, ed25519.PublicKey](tokenString, publicKey, jwt.SigningMethodEdDSA)
	if err != nil {
		return BareJWT[ed25519.PrivateKey, ed25519.PublicKey]{}, err
	}

	return bareJWT, nil
}

// parseBareJWTRSA parses a JWT token string and returns a BareJWT object.
// It uses the provided public key to verify the token's signature.
// The token must be signed using the RS256 algorithm.
// The function also accepts a variable number of claim keys to extract from the token claims.
// If the claim keys are provided, they will be added to the MapClaims of the BareJWT object.
// If the token is invalid or the claims cannot be parsed, an error will be returned.
func parseBareJWTRSA(tokenString string, publicKey *rsa.PublicKey, claimKeys ...AllowedClaimKeys) (BareJWT[*rsa.PrivateKey, *rsa.PublicKey], error) {
	bareJWT, err := parseBareJWTCommon[*rsa.PrivateKey, *rsa.PublicKey](tokenString, publicKey, jwt.SigningMethodRS256)
	if err != nil {
		return BareJWT[*rsa.PrivateKey, *rsa.PublicKey]{}, err
	}

	return bareJWT, nil
}

func parseBareJWTCommon[PRIV PrivateKeyPair, PUB PublicKeyPair](tokenString string, publicKey any, method jwt.SigningMethod) (BareJWT[PRIV, PUB], error) {
	token, err := parseTokenCommon(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != method {
			return nil, ErrUnexpectedMethod
		}
		return publicKey, nil
	})
	if err != nil {
		return BareJWT[PRIV, PUB]{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		parsedJWT := BareJWT[PRIV, PUB]{
			Jti: getClaim[string](claims, "jti"),
			Iss: getClaim[string](claims, "iss"),
			Exp: int64(claims["exp"].(float64)),
			Iat: int64(claims["iat"].(float64)),
			Kid: getClaim[string](claims, "kid"),
		}

		parsedJWT.MapClaims = claims

		return parsedJWT, nil
	}

	return BareJWT[PRIV, PUB]{}, ErrInvalidClaims
}

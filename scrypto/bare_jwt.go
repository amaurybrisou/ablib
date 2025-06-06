// Package scrypto provides utilities for working with JSON Web Tokens (JWTs).
package scrypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// BareJWT represents a JSON Web Token (JWT) with additional fields.
type BareJWT struct {
	// JWK represents the JSON Web Key (JWK) used to sign the JWT.
	JWK
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
func NewBareJWT(privateKey JWK, issuer string) BareJWT {
	return BareJWT{
		JWK: privateKey,
		Iss: issuer,
		Kid: privateKey.Kid,
	}
}

// SignWithClaims signs the JWT with the provided claims and expiration time.
func (m *BareJWT) SignWithClaims(customClaims map[AllowedClaimKeys]any, exp time.Time) (string, string, error) {
	return signWithClaimsCommon(customClaims, exp, m.PrivateKey.(*rsa.PrivateKey), jwt.SigningMethodRS256, m.Kid, m.Iss)
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

// ParseBareJWTED25519 parses a JWT token string and returns a BareJWT object.
func ParseBareJWTED25519(tokenString string, publicKey ed25519.PublicKey, claimKeys ...AllowedClaimKeys) (BareJWT, error) {
	bareJWT, err := parseBareJWTCommon(tokenString, publicKey, jwt.SigningMethodEdDSA)
	if err != nil {
		return BareJWT{}, err
	}

	if len(claimKeys) > 0 {
		for _, key := range claimKeys {
			if value, ok := bareJWT.MapClaims[string(key)]; ok {
				bareJWT.MapClaims[string(key)] = value
			}
		}
	}
	return bareJWT, nil
}

// ParseBareJWTRSA parses a JWT token string and returns a BareJWT object.
// It uses the provided public key to verify the token's signature.
// The token must be signed using the RS256 algorithm.
// The function also accepts a variable number of claim keys to extract from the token claims.
// If the claim keys are provided, they will be added to the MapClaims of the BareJWT object.
// If the token is invalid or the claims cannot be parsed, an error will be returned.
func ParseBareJWTRSA(tokenString string, publicKey *rsa.PublicKey, claimKeys ...AllowedClaimKeys) (BareJWT, error) {
	bareJWT, err := parseBareJWTCommon(tokenString, publicKey, jwt.SigningMethodRS256)
	if err != nil {
		return BareJWT{}, err
	}

	if len(claimKeys) > 0 {
		for _, key := range claimKeys {
			if value, ok := bareJWT.MapClaims[string(key)]; ok {
				bareJWT.MapClaims[string(key)] = value
			}
		}
	}
	return bareJWT, nil
}

func parseBareJWTCommon(tokenString string, publicKey any, method jwt.SigningMethod) (BareJWT, error) {
	token, err := parseTokenCommon(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != method {
			return nil, ErrUnexpectedMethod
		}
		return publicKey, nil
	})
	if err != nil {
		return BareJWT{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		parsedJWT := BareJWT{
			Jti: getClaim[string](claims, "jti"),
			Iss: getClaim[string](claims, "iss"),
			Exp: int64(claims["exp"].(float64)),
			Iat: int64(claims["iat"].(float64)),
			Kid: getClaim[string](claims, "kid"),
		}

		parsedJWT.MapClaims = claims

		return parsedJWT, nil
	}

	return BareJWT{}, ErrInvalidClaims
}

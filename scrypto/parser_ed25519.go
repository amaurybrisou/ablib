package scrypto

import (
	"crypto/ed25519"
)

// ParseAuthTokenED25519 parses a JWT token and returns the JWT struct
// It checks if the token is valid and if the purpose is "authentication"
// If the token is invalid or the purpose is not "authentication", it returns an error
// The function also checks if the token is expired
func ParseAuthTokenED25519(tokenString string, publicKey ed25519.PublicKey) (*JWT[ed25519.PrivateKey, ed25519.PublicKey], error) {
	token, err := parseBareJWTED25519(tokenString, publicKey, ClaimKeyPurpose, ClaimKeyUID)
	if err != nil {
		return nil, err
	}

	if claims := token.MapClaims; claims != nil {
		parsedJWT := &JWT[ed25519.PrivateKey, ed25519.PublicKey]{
			BareJWT: token,
			UID:     getClaim[string](claims, "uid"),
			Purpose: getClaim[string](claims, "purpose"),
		}

		if !IsAuthenticationClaims(claims) {
			return nil, ErrInvalidPurpose
		}

		return parsedJWT, nil
	}

	return nil, ErrInvalidClaims
}

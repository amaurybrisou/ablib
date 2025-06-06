package scrypto

import (
	"crypto/rsa"
	"errors"
)

// ParseAuthToken parses a JWT token and returns the JWT struct
// It checks if the token is valid and if the purpose is "authentication"
// If the token is invalid or the purpose is not "authentication", it returns an error
// The function also checks if the token is expired
// If the token is expired, it returns an error
func ParseAuthToken(tokenString string, publicKey *rsa.PublicKey) (*JWT, error) {
	token, err := ParseBareJWTRSA(tokenString, publicKey, ClaimKeyPurpose, ClaimKeyUID, ClaimKeyRole, ClaimKeyCompanyID, ClaimKeyCompanyRole)
	if err != nil {
		return nil, err
	}

	if claims := token.MapClaims; claims != nil {
		parsedJWT := &JWT{
			BareJWT:     token,
			UID:         getClaim[string](claims, "uid"),
			Role:        getClaim[string](claims, "role"),
			CompanyID:   getClaim[string](claims, "company_id"),
			CompanyRole: getClaim[string](claims, "company_role"),
			Purpose:     getClaim[string](claims, "purpose"),
		}

		if !IsAuthenticationClaims(claims) {
			return nil, errors.New("invalid token purpose")
		}

		return parsedJWT, nil
	}

	return nil, errors.New("invalid token claims")
}

// ParseRefreshToken parses a refresh token and returns the JWT struct
// It checks if the token is valid and if the purpose is "refresh"
// If the token is invalid or the purpose is not "refresh", it returns an error
// The function also checks if the token is expired
// If the token is expired, it returns an error
func ParseRefreshToken(tokenString string, publicKey *rsa.PublicKey) (*JWT, error) {
	token, err := ParseBareJWTRSA(tokenString, publicKey, ClaimKeyPurpose)
	if err != nil {
		return nil, err
	}

	if claims := token.MapClaims; claims != nil {
		parsedJWT := &JWT{
			BareJWT: token,
			Purpose: getClaim[string](claims, "purpose"),
		}

		if !IsRefreshClaims(claims) {
			return nil, ErrInvalidPurpose
		}

		return parsedJWT, nil
	}

	return nil, ErrInvalidClaims
}

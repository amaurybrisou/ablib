package scrypto

import (
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SignED25519 signs the JWT using Ed25519 algorithm
// nolint:dupl
func (m *JWT) SignED25519(exp time.Time, additionalClaims map[AllowedClaimKeys]any) (string, string, error) {
	if _, err := uuid.Parse(m.UID); err != nil {
		return "", "", errors.New("cannot sign jwt, invalid uid as type uuid")
	}

	jti := uuid.NewString()
	claims := jwt.MapClaims{
		"jti":        jti,
		"exp":        exp.Unix(),
		"iss":        m.Iss,
		"iat":        time.Now().Unix(),
		"uid":        m.UID,
		"company_id": m.CompanyRole,
	}

	for k, v := range additionalClaims {
		if v != nil {
			claims[k.String()] = v
		}
	}

	m.MapClaims = claims

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims, func(token *jwt.Token) {
		token.Header["kid"] = m.Kid
		token.Header["alg"] = jwt.SigningMethodEdDSA.Alg()
		token.Header["typ"] = "JWT"
	})
	tokenString, err := token.SignedString(m.PrivateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

// SignWithClaimsEDDSA signs the JWT with the provided claims and expiration time using EdDSA.
func (m *BareJWT) SignWithClaimsEDDSA(customClaims map[AllowedClaimKeys]any, exp time.Time) (string, string, error) {
	return signWithClaimsCommon(customClaims, exp, m.PrivateKey.(ed25519.PrivateKey), jwt.SigningMethodEdDSA, m.Kid, m.Iss)
}

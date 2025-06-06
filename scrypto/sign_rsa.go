package scrypto

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Sign signs the JWT using RSA algorithm
// It takes the expiration time and additional claims as parameters
// It returns the signed token string and the JTI (JWT ID)
// If there is an error during signing, it returns an error
// The function also checks if the UID is a valid UUID
// The function also sets the claims for the JWT: jti, exp, iss, iat, uid, company_id
// The function also adds any additional claims provided in the map
// The function also sets the header for the JWT: kid, alg, typ
// The function also sets the signing method to RS256
// The function also sets the private key for signing the JWT
//
//nolint:dupl
func (m *JWT) Sign(exp time.Time, additionalClaims map[AllowedClaimKeys]any) (string, string, error) {
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
		"company_id": m.CompanyID,
	}

	for k, v := range additionalClaims {
		if v != nil {
			claims[k.String()] = v
		}
	}

	m.MapClaims = claims

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims, func(token *jwt.Token) {
		token.Header["kid"] = m.Kid
		token.Header["alg"] = jwt.SigningMethodRS256.Alg()
		token.Header["typ"] = "JWT"
	})
	tokenString, err := token.SignedString(m.PrivateKey)
	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

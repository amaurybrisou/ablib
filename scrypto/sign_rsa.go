package scrypto

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// signRSA signs the JWT using RSA algorithm
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
func (m *JWT[PRIV, PUB]) signRSA(exp time.Time, additionalClaims map[AllowedClaimKeys]any) (string, string, error) {
	if _, err := uuid.Parse(m.UID); err != nil {
		return "", "", errors.New("cannot sign jwt, invalid uid as type uuid")
	}

	// Merge JWT-specific claims with additional claims
	mergedClaims := make(map[AllowedClaimKeys]any)
	mergedClaims[ClaimKeyUID] = m.UID
	mergedClaims[ClaimKeyCompanyID] = m.CompanyID

	// Add additional claims
	for k, v := range additionalClaims {
		if v != nil {
			mergedClaims[k] = v
		}
	}

	// Use the BareJWT's SignWithClaims method
	return m.SignWithClaims(mergedClaims, exp)
}

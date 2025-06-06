package scrypto

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// signED25519 signs the JWT using Ed25519 algorithm
// nolint:dupl
func (m *JWT[PRIV, PUB]) signED25519(exp time.Time, additionalClaims map[AllowedClaimKeys]any) (string, string, error) {
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

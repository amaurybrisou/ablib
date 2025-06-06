package scrypto

// JWT represents a JSON Web Token
// It contains the JWK, issuer, expiration time, and claims.
// The JWT struct is used to create and parse JWTs.
// It also contains the uid, role, company_id, and company_role claims.
type JWT[PRIV PrivateKeyPair, PUB PublicKeyPair] struct {
	BareJWT[PRIV, PUB]

	UID         string `json:"uid"`
	Role        string `json:"role"`
	CompanyID   string `json:"company_id"`
	CompanyRole string `json:"company_role"`
	Purpose     string `json:"purpose"`
}

// NewJWT creates a new JWT instance with the provided private key, issuer, uid, and company ID
// It initializes the JWT struct with the provided values and returns it
func NewJWT[PRIV PrivateKeyPair, PUB PublicKeyPair](privateKey *JWK[PRIV, PUB], issuer, uid, cid string) JWT[PRIV, PUB] {
	return JWT[PRIV, PUB]{
		BareJWT:   NewBareJWT(privateKey, issuer),
		UID:       uid,
		CompanyID: cid,
	}
}

// ParseAuthToken parses and validates a JWT token string using the provided public key
func ParseAuthToken[PRIV PrivateKeyPair, PUB PublicKeyPair](tokenStr string, jwk *JWK[PRIV, PUB]) (*JWT[PRIV, PUB], error) {
	bareJWT, err := ParseBareJWT(tokenStr, jwk,
		ClaimKeyUID,
		ClaimKeyRole,
		ClaimKeyCompanyID,
		ClaimKeyCompanyRole,
		ClaimKeyPurpose,
	)
	if err != nil {
		return nil, err
	}

	jwt := &JWT[PRIV, PUB]{
		BareJWT:     bareJWT,
		UID:         getClaim[string](bareJWT.MapClaims, string(ClaimKeyUID)),
		Role:        getClaim[string](bareJWT.MapClaims, string(ClaimKeyRole)),
		CompanyID:   getClaim[string](bareJWT.MapClaims, string(ClaimKeyCompanyID)),
		CompanyRole: getClaim[string](bareJWT.MapClaims, string(ClaimKeyCompanyRole)),
		Purpose:     getClaim[string](bareJWT.MapClaims, string(ClaimKeyPurpose)),
	}

	return jwt, nil
}

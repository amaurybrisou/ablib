package scrypto

// JWT represents a JSON Web Token
// It contains the JWK, issuer, expiration time, and claims.
// The JWT struct is used to create and parse JWTs.
// It also contains the uid, role, company_id, and company_role claims.
type JWT struct {
	BareJWT

	UID         string `json:"uid"`
	Role        string `json:"role"`
	CompanyID   string `json:"company_id"`
	CompanyRole string `json:"company_role"`
	Purpose     string `json:"purpose"`
}

// NewJWT creates a new JWT instance with the provided private key, issuer, uid, and company ID
// It initializes the JWT struct with the provided values and returns it
func NewJWT(privateKey JWK, issuer, uid, cid string) JWT {
	return JWT{
		BareJWT:   NewBareJWT(privateKey, issuer),
		UID:       uid,
		CompanyID: cid,
	}
}

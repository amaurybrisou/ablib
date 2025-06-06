package scrypto

// JWK represents a JSON Web Key
// It contains the private key, public key, algorithm, and key ID.
type JWK struct {
	PrivateKey any    `json:"-"`
	PublicKey  any    `json:"public_key"`
	Alg        string `json:"alg"`
	Kid        string `json:"kid"`
}

func (j JWK) String() string {
	return j.Kid
}

// AllowedClaimKeys represents the allowed keys for claims in the JWT.
type AllowedClaimKeys string

// String returns the string representation of the AllowedClaimKeys.
func (a AllowedClaimKeys) String() string {
	return string(a)
}

const (
	// ClaimKeyNonce       AllowedClaimKeys = "nonce"
	ClaimKeyNonce AllowedClaimKeys = "nonce"
	// ClaimKeyPurpose     AllowedClaimKeys = "purpose"
	ClaimKeyPurpose AllowedClaimKeys = "purpose"
	// ClaimKeyUID        AllowedClaimKeys = "uid"
	ClaimKeyUID AllowedClaimKeys = "uid"
	// ClaimKeyRole       AllowedClaimKeys = "role"
	ClaimKeyRole AllowedClaimKeys = "role"
	// ClaimKeyCompanyRole AllowedClaimKeys = "company_role"
	ClaimKeyCompanyRole AllowedClaimKeys = "company_role"
	// ClaimKeyCompanyID  AllowedClaimKeys = "company_id"
	ClaimKeyCompanyID AllowedClaimKeys = "company_id"
	// ClaimKeyUsername AllowedClaimKeys = "username"
	ClaimKeyUsername AllowedClaimKeys = "username"
)

// AllowedClaimPurposeValue represents the allowed values for the purpose claim.
type AllowedClaimPurposeValue string

// String returns the string representation of the AllowedClaimPurposeValue.
func (a AllowedClaimPurposeValue) String() string {
	return string(a)
}

const (
	// ClaimPurposeActivation     AllowedClaimPurposeValue = "activation"
	ClaimPurposeActivation AllowedClaimPurposeValue = "activation"
	// ClaimPurposeAuthentication AllowedClaimPurposeValue = "authentication"
	ClaimPurposeAuthentication AllowedClaimPurposeValue = "authentication"
	// ClaimPurposeRefresh        AllowedClaimPurposeValue = "refresh"
	ClaimPurposeRefresh AllowedClaimPurposeValue = "refresh"
)

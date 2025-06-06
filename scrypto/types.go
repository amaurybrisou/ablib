package scrypto

import (
	"crypto/ed25519"
	"crypto/rsa"
)

type ScryptoKey int8

const (
	// ED25519 represents the Ed25519 key type.
	ED25519 ScryptoKey = iota
	// RSA represents the RSA key type.
	RSA
)

// KeyPair defines the constraints for private and public key pairs
type PrivateKeyPair interface {
	// ED25519 pair
	ed25519.PrivateKey |
		// RSA pair
		*rsa.PrivateKey
}

type PublicKeyPair interface {
	// ED25519 pair
	ed25519.PublicKey |
		// RSA pair
		*rsa.PublicKey
}

// JWK represents a JSON Web Key with type-safe key pairs
type JWK[PRV PrivateKeyPair, PUB PublicKeyPair] struct {
	KeyType    ScryptoKey `json:"-"`
	PrivateKey PRV        `json:"-"`
	PublicKey  PUB        `json:"public_key"`
	Alg        string     `json:"alg"`
	Kid        string     `json:"kid"`
}

func (j JWK[PRV, PUB]) String() string {
	return j.Kid
}
func NewJWK[PRV PrivateKeyPair, PUB PublicKeyPair](keyType ScryptoKey, privateKey PRV, publicKey PUB, alg string, kid string) *JWK[PRV, PUB] {
	return &JWK[PRV, PUB]{
		KeyType:    keyType,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Alg:        alg,
		Kid:        kid,
	}
}
func (j JWK[PRV, PUB]) Pub() PUB {
	return j.PublicKey
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

package scrypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ParseED25519PublicKeyFromB64 parses an ED25519 public key from a base64 encoded string.
// It expects the key to be in PEM format.
func ParseED25519PublicKeyFromB64(b64Key string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *ed25519.PublicKey, got %T", pubKey)
	}

	return ed25519PubKey, nil
}

// ParseED25519PrivateKeyFromB64 parses an ED25519 private key from a base64 encoded string.
// It expects the key to be in PEM format.
func ParseED25519PrivateKeyFromB64(b64Key string) (ed25519.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded private key: %w", err)
		}
	}

	ed25519PrivKey, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ed25519.PrivateKey, got %T", privKey)
	}

	return ed25519PrivKey, nil
}

// ParseRSAPrivateKeyFromB64 parses an RSA private key from a base64 encoded string.
// It expects the key to be in PEM format.
func ParseRSAPrivateKeyFromB64(b64Key string) (*rsa.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	return ParseRSAPrivateKeyFromBytes(key)
}

// ParseRSAPrivateKeyFromBytes parses an RSA private key from a byte slice.
// It expects the key to be in PEM format.
func ParseRSAPrivateKeyFromBytes(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER encoded private key: %w", err)
		}
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privKey)
	}

	return rsaPrivKey, nil
}

// ParseRSAPublicKeyFromB64 parses an RSA public key from a base64 encoded string.
// It expects the key to be in PEM format.
func ParseRSAPublicKeyFromB64(b64Key string) (*rsa.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	return ParseRSAPublicKeyFromBytes(key)
}

// ParseRSAPublicKeyFromBytes parses an RSA public key from a byte slice.
// It expects the key to be in PEM format.
func ParseRSAPublicKeyFromBytes(key []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *rsa.PublicKey, got %T", pubKey)
	}

	return rsaPubKey, nil
}

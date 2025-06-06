package scrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
)

// GenerateRSAKeys generates a new RSA private key and returns both the private and public keys in PEM format.
func GenerateRSAKeys(bits int) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	// Generate a new RSA private key
	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	// Extract the public key from the private key
	publicKey = &privateKey.PublicKey

	return privateKey, publicKey, nil
}

func GenerateED25519Keys() (privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, err error) {
	// Generate a new ED25519 key pair
	publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

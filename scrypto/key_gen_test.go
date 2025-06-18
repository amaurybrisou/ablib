package scrypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestGenerateED25519Keys(t *testing.T) {
	t.Parallel()
	privateKey, publicKey, err := GenerateED25519Keys()
	if err != nil {
		t.Fatalf("GenerateED25519Keys returned error: %v", err)
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		t.Errorf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(privateKey))
	}

	if len(publicKey) != ed25519.PublicKeySize {
		t.Errorf("expected public key size %d, got %d", ed25519.PublicKeySize, len(publicKey))
	}

	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)

	if !ed25519.Verify(publicKey, message, signature) {
		t.Error("failed to verify signature with generated key pair")
	}
}

func TestGenerateRSAKeys(t *testing.T) {
	t.Parallel()
	bits := 2048
	privateKey, publicKey, err := GenerateRSAKeys(bits)
	if err != nil {
		t.Fatalf("GenerateRSAKeys returned error: %v", err)
	}
	if privateKey == nil {
		t.Fatal("expected non-nil private key")
	}
	if publicKey == nil {
		t.Fatal("expected non-nil public key")
	}

	// Test RSA encryption and decryption using OAEP with SHA256 hash function.
	message := []byte("test RSA encryption")
	hash := sha256.New()

	encrypted, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, message, nil)
	if err != nil {
		t.Fatalf("rsa.EncryptOAEP returned error: %v", err)
	}

	decrypted, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, encrypted, nil)
	if err != nil {
		t.Fatalf("rsa.DecryptOAEP returned error: %v", err)
	}

	if string(decrypted) != string(message) {
		t.Errorf("decrypted message mismatch: expected %q, got %q", message, decrypted)
	}
}

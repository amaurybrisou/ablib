package scrypto

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

// Hash hashes the given password using bcrypt and returns the hashed password.
func Hash(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost {
		return "", bcrypt.ErrHashTooShort
	}
	if cost > bcrypt.MaxCost {
		return "", bcrypt.InvalidCostError(cost)
	}

	if password == "" {
		return "", ErrEmptyPassword
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// ValidateHash compares a plain-text password with a bcrypt hashed password and returns true if they match.
func ValidateHash(password, hashedPassword string) bool {
	if password == "" || hashedPassword == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// GenerateRandomPassword generates a random password with the specified length.
func GenerateRandomPassword(length int) (string, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	randomPassword := base64.URLEncoding.EncodeToString(randomBytes)
	return randomPassword[:length], nil
}

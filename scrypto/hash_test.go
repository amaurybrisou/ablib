package scrypto

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHash_CostTooLow(t *testing.T) {
	password := "samplepassword"
	invalidCost := bcrypt.MinCost - 1

	hashed, err := Hash(password, invalidCost)
	if err != bcrypt.ErrHashTooShort {
		t.Fatalf("expected error bcrypt.ErrHashTooShort, got: %v", err)
	}
	if hashed != "" {
		t.Errorf("expected empty hashed string, got: %s", hashed)
	}
}

func TestHash_CostTooHigh(t *testing.T) {
	password := "samplepassword"
	invalidCost := bcrypt.MaxCost + 1

	hashed, err := Hash(password, invalidCost)
	if err == nil {
		t.Fatal("expected error due to invalid cost, got nil")
	}
	if hashed != "" {
		t.Errorf("expected empty hashed string, got: %s", hashed)
	}
}

func TestHash_EmptyPassword(t *testing.T) {
	var emptyPassword string
	cost := bcrypt.MinCost

	hashed, err := Hash(emptyPassword, cost)
	if err != ErrEmptyPassword {
		t.Fatalf("expected ErrEmptyPassword, got: %v", err)
	}
	if hashed != "" {
		t.Errorf("expected empty hashed string, got: %s", hashed)
	}
}

func TestHash_Success(t *testing.T) {
	password := "correcthorsebatterystaple"
	cost := bcrypt.DefaultCost

	hashed, err := Hash(password, cost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hashed == "" {
		t.Fatal("expected a non-empty hash")
	}

	// Verify that the hashed password matches the original password.
	err = bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err != nil {
		t.Errorf("hashed password did not match the original: %v", err)
	}
}

func TestValidateHash_EmptyInput(t *testing.T) {
	// Both password and hashedPassword are empty.
	if ValidateHash("", "") {
		t.Error("expected false when both password and hashedPassword are empty")
	}

	// Empty password with a valid hashedPassword.
	hashed, err := bcrypt.GenerateFromPassword([]byte("somepassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate hash: %v", err)
	}
	if ValidateHash("", string(hashed)) {
		t.Error("expected false when password is empty")
	}

	// Empty hashedPassword with a valid password.
	if ValidateHash("somepassword", "") {
		t.Error("expected false when hashedPassword is empty")
	}
}

func TestValidateHash_Invalid(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate hash: %v", err)
	}

	if ValidateHash(wrongPassword, string(hashed)) {
		t.Error("expected false when validating with an incorrect password")
	}
}

func TestValidateHash_Valid(t *testing.T) {
	password := "correctpassword"

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate hash: %v", err)
	}

	if !ValidateHash(password, string(hashed)) {
		t.Error("expected true when validating with the correct password and hash")
	}
}
func TestGenerateRandomPassword_Length(t *testing.T) {
	desiredLength := 16
	password, err := GenerateRandomPassword(desiredLength)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(password) != desiredLength {
		t.Errorf("expected password length %d, got %d", desiredLength, len(password))
	}
}

func TestGenerateRandomPassword_Unique(t *testing.T) {
	desiredLength := 16
	password1, err := GenerateRandomPassword(desiredLength)
	if err != nil {
		t.Fatalf("unexpected error during first generation: %v", err)
	}
	password2, err := GenerateRandomPassword(desiredLength)
	if err != nil {
		t.Fatalf("unexpected error during second generation: %v", err)
	}
	if password1 == password2 {
		t.Error("expected different random passwords, got identical passwords")
	}
}

func TestGenerateRandomPassword_ZeroLength(t *testing.T) {
	password, err := GenerateRandomPassword(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(password) != 0 {
		t.Errorf("expected empty password for zero length, got length %d", len(password))
	}
}

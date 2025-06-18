package scrypto

import (
	"fmt"
)

// Error types for better error handling
type JWTError struct {
	Code    string
	Message string
	Err     error
}

func (e *JWTError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *JWTError) Unwrap() error {
	return e.Err
}

func (e *JWTError) AddContext(v any) {
	e.Message = fmt.Sprintf("%s, %v", e.Message, v)
}

var (
	ErrExpiredToken     = &JWTError{Code: "expired_token", Message: "expired token"}
	ErrInvalidSignature = &JWTError{Code: "invalid_signature", Message: "invalid signature"}
	ErrInvalidToken     = &JWTError{Code: "invalid_token", Message: "invalid token"}
	ErrNilToken         = &JWTError{Code: "nil_token", Message: "nil token"}
	ErrInvalidClaims    = &JWTError{Code: "invalid_claims", Message: "invalid_claims"}
	ErrInvalidExp       = &JWTError{Code: "invalid_exp", Message: "invalid_exp"}
	ErrInvalidPurpose   = &JWTError{Code: "invalid_purpose", Message: "invalid token purpose"}
	ErrUnexpectedMethod = &JWTError{Code: "unexpected_signing_method", Message: "unexpected signing method"}
	ErrEmptyPassword    = &JWTError{Code: "empty_password", Message: "password cannot be empty"}

	ErrValueTooLong      = &JWTError{Code: "value_too_long", Message: "cookie value too long"}
	ErrInvalidValue      = &JWTError{Code: "invalid_value", Message: "invalid cookie value"}
	ErrInvalidCookieName = &JWTError{Code: "invalid_cookie_name", Message: "invalid cookie name, must not be empty"}

	ErrUnsupportedKeyType = &JWTError{Code: "unsupported_key_type", Message: "unsupported key type"}
)

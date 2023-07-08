package jwtlib

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWT struct {
	SecretKey string
	Issuer    string
	Audience  string
}

type Config struct {
	SecretKey, Issuer, Audience string
}

func New(cfg Config) *JWT {
	return &JWT{
		SecretKey: cfg.SecretKey,
		Issuer:    cfg.Issuer,
		Audience:  cfg.Audience,
	}
}

func (j *JWT) GenerateToken(subject string, expiration time.Time, notBefore time.Time) (string, error) {
	if j.SecretKey == "" {
		return "", errors.New("secret key is empty, define secured secret key")
	}

	if expiration.Before(time.Now()) {
		return "", errors.New("expiration cannot be anterior to the current time")
	}

	claims := jwt.MapClaims{
		"sub": subject,
		"exp": expiration.Unix(),
		"iat": time.Now().Unix(),
		"nbf": notBefore.Unix(),
		"iss": j.Issuer,
		"aud": j.Audience,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
}

func (j *JWT) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	// Parse the token and validate the signing method
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(j.SecretKey), nil
	})
	if err != nil {
		return nil, err
	}

	// Verify token signature
	if !token.Valid {
		return nil, jwt.NewValidationError("invalid token signature", jwt.ValidationErrorSignatureInvalid)
	}

	// Extract claims from token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, jwt.NewValidationError("invalid claims", jwt.ValidationErrorClaimsInvalid)
	}

	// Validate expiration claim
	err = claims.Valid()
	if err != nil {
		return nil, err
	}

	// Verify issuer
	err = j.verifyIssuer(claims["iss"])
	if err != nil {
		return nil, err
	}

	// Verify audience
	err = j.verifyAudience(claims["aud"])
	if err != nil {
		return nil, err
	}

	// Verify not before
	err = j.verifyNotBefore(claims["nbf"])
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (j *JWT) verifyIssuer(issuer interface{}) error {
	if issuer != j.Issuer {
		return jwt.NewValidationError("invalid issuer", jwt.ValidationErrorIssuer)
	}
	return nil
}

func (j *JWT) verifyAudience(audience interface{}) error {
	if audience != j.Audience {
		return jwt.NewValidationError("invalid audience", jwt.ValidationErrorAudience)
	}
	return nil
}

func (j *JWT) verifyNotBefore(notBefore interface{}) error {
	nbf, ok := notBefore.(float64)
	if !ok {
		return jwt.NewValidationError("invalid not before claim", jwt.ValidationErrorClaimsInvalid)
	}

	notBeforeTime := time.Unix(int64(nbf), 0)
	if time.Now().Before(notBeforeTime) {
		return jwt.NewValidationError("token not yet valid", jwt.ValidationErrorNotValidYet)
	}

	return nil
}

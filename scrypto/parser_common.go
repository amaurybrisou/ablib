package scrypto

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func parseTokenCommon(tokenString string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, ErrNilToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	expiration, ok := claims["exp"].(float64)
	if !ok {
		return nil, ErrInvalidExp
	}

	if time.Unix(int64(expiration), 0).Before(time.Now()) {
		return nil, ErrExpiredToken
	}

	return token, nil
}

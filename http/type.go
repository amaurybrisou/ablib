package ablibhttp

import (
	"errors"
	"net/http"
)

type AuthHandler interface {
	Login(http.ResponseWriter, *http.Request)
}

var (
	ErrUserNotFound = errors.New("user not found")
)

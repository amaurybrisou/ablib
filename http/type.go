package ablibhttp

import (
	"context"
	"errors"
	"net/http"

	ablibmodels "github.com/amaurybrisou/ablib/models"
)

type AuthHandler interface {
	Login(http.ResponseWriter, *http.Request)
}

var (
	ErrUserNotFound = errors.New("user not found")
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (ablibmodels.UserInterface, error)
	GetUserByID(ctx context.Context, userID string) (ablibmodels.UserInterface, error)
	// GetRefreshTokenByUserID(ctx context.Context, userID string) (string, error)
	// AddRefreshToken adds a new refresh token for a user ID.
	AddRefreshToken(ctx context.Context, userID, refreshToken string) error
	// RemoveRefreshToken removes a refresh token for a user ID.
	RemoveRefreshToken(ctx context.Context, userID string) error
}

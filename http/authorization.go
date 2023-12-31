package ablibhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	coremodels "github.com/amaurybrisou/ablib/models"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type AuthMiddleware interface {
	Middleware(next http.Handler) http.Handler
}

func IsAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAdmin := IsAdmin(r.Context())
		if !isAdmin {
			log.Ctx(r.Context()).Error().Err(errors.New("not admin")).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func createUserContext(ctx context.Context, user coremodels.UserInterface) context.Context {
	// Add user values to the new context
	ctx = context.WithValue(ctx, UserIDCtxKey, user.GetID())
	ctx = context.WithValue(ctx, ExternalIDCtxKey, user.GetExternalID())
	ctx = context.WithValue(ctx, UserEmail, user.GetEmail())
	ctx = context.WithValue(ctx, UserFirstname, user.GetFirstname())
	ctx = context.WithValue(ctx, UserLastname, user.GetLastname())
	ctx = context.WithValue(ctx, UserRole, user.GetRole())
	ctx = context.WithValue(ctx, UserCreatedAt, user.GetCreatedAt())
	ctx = context.WithValue(ctx, UserUpdatedAt, user.GetUpdatedAt())
	ctx = context.WithValue(ctx, UserDeletedAt, user.GetDeletedAt())

	return ctx
}

type UserCtxKey string

const (
	UserIDCtxKey     UserCtxKey = "user_id"
	ExternalIDCtxKey UserCtxKey = "external_id"
	UserEmail        UserCtxKey = "user_email"
	UserFirstname    UserCtxKey = "user_firstname"
	UserLastname     UserCtxKey = "user_lastname"
	UserRole         UserCtxKey = "user_role"
	UserStripeKey    UserCtxKey = "user_stripe_key"
	UserCreatedAt    UserCtxKey = "user_created_at"
	UserUpdatedAt    UserCtxKey = "user_updated_at"
	UserDeletedAt    UserCtxKey = "user_deleted_at"
)

func User(ctx context.Context) coremodels.UserInterface {
	userID := ctx.Value(UserIDCtxKey)
	if userID == nil {
		return nil
	}

	u := coremodels.User{
		ID:         ctx.Value(UserIDCtxKey).(uuid.UUID),
		ExternalID: ctx.Value(ExternalIDCtxKey).(string),
		Email:      ctx.Value(UserEmail).(string),
		Firstname:  ctx.Value(UserFirstname).(string),
		Lastname:   ctx.Value(UserLastname).(string),
		Role:       ctx.Value(UserRole).(coremodels.GatewayRole),
		CreatedAt:  ctx.Value(UserCreatedAt).(time.Time),
		UpdatedAt:  ctx.Value(UserUpdatedAt).(*time.Time),
		DeletedAt:  ctx.Value(UserDeletedAt).(*time.Time),
	}

	return u
}

func IsAdmin(ctx context.Context) bool {
	user := User(ctx)
	if user == nil {
		return false
	}

	return user.GetRole() == coremodels.ADMIN
}

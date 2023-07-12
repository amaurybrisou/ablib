package ablibhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/amaurybrisou/ablib/cryptlib"
	"github.com/amaurybrisou/ablib/jwtlib"
	ablibmodels "github.com/amaurybrisou/ablib/models"
	coremodels "github.com/amaurybrisou/ablib/models"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type JwtAuth struct {
	getUserByEmail func(ctx context.Context, email string) (ablibmodels.UserInterface, error)
	getUserByID    func(ctx context.Context, userID uuid.UUID) (coremodels.UserInterface, error)
	jwt            *jwtlib.JWT
}

func NewJwtAuth(jwt *jwtlib.JWT,
	getUserByEmail func(ctx context.Context, email string) (ablibmodels.UserInterface, error),
	getUserByID func(context.Context, uuid.UUID) (coremodels.UserInterface, error),

) JwtAuth {
	return JwtAuth{
		jwt:            jwt,
		getUserByEmail: getUserByEmail,
		getUserByID:    getUserByID,
	}
}

func (s JwtAuth) Login(w http.ResponseWriter, r *http.Request) {
	type Credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	// Parse the request body into a Credentials struct
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.getUserByEmail(r.Context(), creds.Email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		log.Ctx(r.Context()).Error().Err(err).Msg("internal error")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if user.GetID() == uuid.Nil || !cryptlib.ValidateHash(creds.Password, user.GetPassword()) {
		log.Ctx(r.Context()).Error().Err(err).Msg("invalid credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := s.jwt.GenerateToken(user.GetID().String(), time.Now().Add(time.Hour), time.Now())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return the token as the response
	response := map[string]string{"token": token}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) //nolint
}

func (s JwtAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header value
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Ctx(r.Context()).Error().Err(errors.New("invalid header")).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract the token from the Authorization header
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Verify the token
		claims, err := s.jwt.VerifyToken(token)
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userID, err := uuid.Parse(claims["sub"].(string))
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := s.getUserByID(r.Context(), userID)
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := createUserContext(r.Context(), user)
		r = r.WithContext(ctx)

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

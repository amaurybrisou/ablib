package ablibhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/amaurybrisou/ablib/cryptlib"
	"github.com/amaurybrisou/ablib/jwtlib"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type JwtAuth struct {
	jwt                    *jwtlib.JWT
	db                     AuthRepository
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
}

func NewJwtAuth(jwt *jwtlib.JWT, db AuthRepository) *JwtAuth {
	return &JwtAuth{
		jwt:                    jwt,
		db:                     db,
		accessTokenExpiration:  time.Minute * 5,
		refreshTokenExpiration: time.Minute * 15,
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

	user, err := s.db.GetUserByEmail(r.Context(), creds.Email)
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

	expiresAt := time.Now().Add(s.accessTokenExpiration)
	token, err := s.jwt.GenerateToken(user.GetID().String(), expiresAt, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.jwt.GenerateToken(user.GetID().String(), expiresAt.Add(s.refreshTokenExpiration), time.Now())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
		http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	err = s.db.AddRefreshToken(r.Context(), user.GetID().String(), refreshToken)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to save refresh token")
		http.Error(w, "failed to save refresh token", http.StatusInternalServerError)
		return
	}

	jwtCookie := http.Cookie{
		Name:     "jwt_refresh_token",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		MaxAge:   int(time.Hour),
	}

	err = cryptlib.SetSignedCookie(w, jwtCookie, []byte(refreshToken))
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
		http.Error(w, "failed to signe refresh token cookie", http.StatusInternalServerError)
		return
	}
	// Return the token as the response
	response := map[string]string{
		"token":      token,
		"expires_at": fmt.Sprintf("%d", expiresAt.Unix()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response) //nolint
}

func (s JwtAuth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Get the Authorization header value
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Ctx(r.Context()).Error().Err(errors.New("invalid header")).Msg("Unauthorized")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract the accessToken from the Authorization header
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Verify the token
	claims, err := s.jwt.VerifyToken(accessToken)
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

	refreshToken, err := s.db.GetRefreshTokenByUserID(r.Context(), userID.String())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
		http.Error(w, "Unauthorized", http.StatusNotAcceptable)
		return
	}

	_, err = s.jwt.VerifyToken(refreshToken)
	if err != nil {
		err = s.db.RemoveRefreshToken(r.Context(), userID.String())
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Any("user_id", userID).Msg("removing refresh token")
			http.Error(w, "Unauthorized", http.StatusInternalServerError)
			return
		}
		log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
		http.Error(w, "Unauthorized", http.StatusNotAcceptable)
		return
	}

	expiresAt := time.Now().Add(s.accessTokenExpiration)
	accessToken, err = s.jwt.GenerateToken(userID.String(), expiresAt, time.Now())
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"token":      accessToken,
		"expires_at": fmt.Sprintf("%d", expiresAt.Unix()),
	}

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

		user, err := s.db.GetUserByID(r.Context(), userID.String())
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

func (s JwtAuth) NonAuthoritativeMiddleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header value
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Ctx(r.Context()).Warn().Err(errors.New("invalid header")).Msg("user not logged in")
			successNext.ServeHTTP(w, r)
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

		user, err := s.db.GetUserByID(r.Context(), userID.String())
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("Unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := createUserContext(r.Context(), user)
		r = r.WithContext(ctx)

		// Call the next handler
		successNext.ServeHTTP(w, r)
	})
}

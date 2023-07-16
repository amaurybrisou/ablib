package ablibhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/amaurybrisou/ablib/cryptlib"
	"github.com/amaurybrisou/ablib/jwtlib"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type CookieAuth struct {
	secret     []byte
	cookieName string
	jwt        *jwtlib.JWT
	jwtAuth    *JwtAuth
	maxAge     int
	db         AuthRepository
}

func NewCookieAuthHandler(secret, name string, maxAge int, db AuthRepository, jwt *jwtlib.JWT) CookieAuth {
	return CookieAuth{
		secret:     []byte(secret),
		cookieName: name,
		maxAge:     maxAge,
		db:         db,
		jwt:        jwt,
		jwtAuth:    NewJwtAuth(jwt, db),
	}
}

func (s CookieAuth) Login(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "internal error", http.StatusBadRequest)
		return
	}

	if user.GetID() == uuid.Nil || !cryptlib.ValidateHash(creds.Password, user.GetPassword()) {
		log.Ctx(r.Context()).Error().Err(err).Msg("invalid credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	cookie := http.Cookie{
		Name:     s.cookieName,
		Value:    user.GetID().String(),
		Path:     "/",
		MaxAge:   s.maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	err = cryptlib.SetSignedCookie(w, cookie, s.secret)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if s.jwt != nil {
		expiresAt := time.Now().Add(time.Second * 15)
		token, err := s.jwt.GenerateToken(user.GetID().String(), expiresAt, time.Now())
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("failed to generate")
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}

		refreshToken, err := s.jwt.GenerateToken(user.GetID().String(), expiresAt.Add(time.Minute*55), time.Now())
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
			Value:    refreshToken,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			MaxAge:   int(time.Hour),
		}

		err = cryptlib.SetSignedCookie(w, jwtCookie, []byte(s.jwt.SecretKey))
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

	w.WriteHeader(http.StatusOK)
}

func (s CookieAuth) Logout(w http.ResponseWriter, r *http.Request) {
	cookies, err := r.Cookie(s.cookieName)
	if err != nil {
		http.Redirect(w, r, "/set", http.StatusSeeOther)
		log.Ctx(r.Context()).Error().Err(err).Msg("cookies not found")
	}
	cookies.MaxAge = -1
	http.SetCookie(w, cookies)
}

func (s CookieAuth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if s.jwt != nil {
		s.jwtAuth.RefreshToken(w, r)
		return
	}
}
func (s CookieAuth) Middleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDString, err := cryptlib.GetSignedCookie(r, s.cookieName, s.secret)
		if err != nil {
			if s.jwt != nil {
				s.jwtAuth.Middleware(successNext).ServeHTTP(w, r)
				return
			}
			log.Ctx(r.Context()).Error().
				Err(err).
				Any("cookie.value", userIDString).
				Msg("Unauthorized")
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "cookie not found", http.StatusBadRequest)
			case errors.Is(err, cryptlib.ErrInvalidValue):
				http.Error(w, "invalid cookie", http.StatusBadRequest)
			default:
				http.Error(w, "server error", http.StatusInternalServerError)
			}
		}

		userID, err := uuid.Parse(userIDString)
		if err != nil {
			log.Ctx(r.Context()).Error().
				Err(err).
				Any("cookie.value", userIDString).
				Msg("Unauthorized")
			http.Error(w, "parse cookie value", http.StatusInternalServerError)
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

		successNext.ServeHTTP(w, r)
	})
}

func (s CookieAuth) NonAuthoritativeMiddleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDString, err := cryptlib.GetSignedCookie(r, s.cookieName, s.secret)
		if err != nil {
			if s.jwt != nil {
				NewJwtAuth(s.jwt, s.db).
					NonAuthoritativeMiddleware(successNext).ServeHTTP(w, r)
				return
			}
			log.Ctx(r.Context()).Warn().
				Err(err).
				Any("cookie.value", userIDString).
				Msg("user not logged in")
			successNext.ServeHTTP(w, r)
			return
		}

		userID, err := uuid.Parse(userIDString)
		if err != nil {
			log.Ctx(r.Context()).Error().
				Err(err).
				Any("cookie.value", userIDString).
				Msg("Unauthorized")
			http.Error(w, "parse cookie value", http.StatusInternalServerError)
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

		successNext.ServeHTTP(w, r)
	})
}

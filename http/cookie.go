package ablibhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/amaurybrisou/ablib/cryptlib"
	"github.com/amaurybrisou/ablib/jwtlib"
	ablibmodels "github.com/amaurybrisou/ablib/models"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type CookieAuth struct {
	secret         []byte
	cookieName     string
	jwt            *jwtlib.JWT
	maxAge         int
	getUserByID    func(ctx context.Context, userID uuid.UUID) (ablibmodels.UserInterface, error)
	getUserByEmail func(ctx context.Context, email string) (ablibmodels.UserInterface, error)
}

func NewCookieAuthHandler(secret, name string, maxAge int,
	getUserByEmail func(ctx context.Context, email string) (ablibmodels.UserInterface, error),
	getUserByID func(context.Context, uuid.UUID) (ablibmodels.UserInterface, error),
	jwt *jwtlib.JWT,
) CookieAuth {
	return CookieAuth{
		secret:         []byte(secret),
		cookieName:     name,
		maxAge:         maxAge,
		getUserByEmail: getUserByEmail,
		getUserByID:    getUserByID,
		jwt:            jwt,
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

	user, err := s.getUserByEmail(r.Context(), creds.Email)
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
		return
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

func (s CookieAuth) Middleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDString, err := cryptlib.GetSignedCookie(r, s.cookieName, s.secret)
		if err != nil {
			if s.jwt != nil {
				JwtAuth{
					getUserByEmail: s.getUserByEmail,
					getUserByID:    s.getUserByID,
					jwt:            s.jwt,
				}.Middleware(successNext).ServeHTTP(w, r)
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

		user, err := s.getUserByID(r.Context(), userID)
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

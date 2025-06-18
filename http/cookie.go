package ablibhttp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/amaurybrisou/ablib/scrypto"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type CookieAuth struct {
	secret                   []byte
	cookieName, cookieDomain string
	maxAge                   int
	db                       AuthRepository
}

func NewCookieAuthHandler(secret, name, cookieDomain string, maxAge int, db AuthRepository) CookieAuth {
	return CookieAuth{
		secret:       []byte(secret),
		cookieName:   name,
		cookieDomain: cookieDomain,
		maxAge:       maxAge,
		db:           db,
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

	if user.GetID() == uuid.Nil || !scrypto.ValidateHash(creds.Password, user.GetPassword()) {
		log.Ctx(r.Context()).Error().Err(err).Msg("invalid credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	cookie := http.Cookie{
		Name:     s.cookieName,
		Domain:   s.cookieDomain,
		Value:    user.GetID().String(),
		Path:     "/",
		MaxAge:   s.maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	err = scrypto.SetSignedCookie(w, cookie, s.secret)
	if err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("Invalid request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s CookieAuth) Logout(w http.ResponseWriter, r *http.Request) {
	cookies, err := r.Cookie(s.cookieName)
	if err != nil {
		http.Redirect(w, r, "/set", http.StatusSeeOther)
		log.Ctx(r.Context()).Error().Err(err).Msg("cookies not found")
		return
	}
	cookies.MaxAge = -1
	http.SetCookie(w, cookies)
}

func (s CookieAuth) Middleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDString, err := scrypto.GetSignedCookie(r, s.cookieName, s.secret)
		if err != nil {

			log.Ctx(r.Context()).Error().
				Err(err).
				Any("cookie.value", userIDString).
				Msg("Unauthorized")
			switch {
			case errors.Is(err, http.ErrNoCookie):
				http.Error(w, "cookie not found", http.StatusBadRequest)
			case errors.Is(err, scrypto.ErrInvalidValue):
				http.Error(w, "invalid cookie", http.StatusBadRequest)
			case errors.Is(err, scrypto.ErrInvalidCookieName):
				http.Error(w, "invalid cookie", http.StatusBadRequest)
			default:
				http.Error(w, "server error", http.StatusInternalServerError)
			}
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

func (s CookieAuth) NonAuthoritativeMiddleware(successNext http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userIDString, err := scrypto.GetSignedCookie(r, s.cookieName, s.secret)
		if err != nil {

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

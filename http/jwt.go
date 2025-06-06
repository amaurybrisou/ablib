package ablibhttp

import (
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/amaurybrisou/ablib/scrypto"
	"github.com/gorilla/mux"
)

// ValidateJWTMiddleware is a middleware that validates JWT tokens in the request.
// It checks the token in the "Authorization" header and, if not found, it checks the "token" cookie.
// If the token is valid, it calls the next handler in the chain.
// If the token is invalid, it returns a 401 Unauthorized response.
func ValidateJWTMiddleware(pubKey any, options ...Option) mux.MiddlewareFunc {
	config := defaultConfig()
	for _, opt := range options {
		opt(config)
	}
	return func(next http.Handler) http.Handler {
		return validateJWT(pubKey, config, next)
	}
}

type MiddlewareConfig struct {
	AllowHeaderJWT bool
}

type Option func(*MiddlewareConfig)

func WithHeaderJWT(allow bool) Option {
	return func(c *MiddlewareConfig) {
		c.AllowHeaderJWT = allow
	}
}

func defaultConfig() *MiddlewareConfig {
	return &MiddlewareConfig{
		AllowHeaderJWT: true, //nolint
	}
}

func validateJWT(pubKey any, config *MiddlewareConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string

		// Try header token if allowed.
		if config.AllowHeaderJWT {
			tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		// Fallback to cookie if no header token was provided.
		if tokenStr == "" {
			if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
				tokenStr = cookie.Value
			}
		}

		// If no token is found, return an error.
		if tokenStr == "" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Parse the token and check its purpose.
		token, err := scrypto.ParseAuthToken(tokenStr, pubKey.(*rsa.PublicKey))
		if err != nil || token == nil || token.Purpose != scrypto.ClaimPurposeAuthentication.String() {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

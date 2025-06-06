package ablibhttp

import (
	"context"
	"net/http"
	"strings"

	"github.com/amaurybrisou/ablib/scrypto"
	"github.com/gorilla/mux"
)

type jwtContextKey string

// middlewareConfig holds the configuration for the JWT middleware
type middlewareConfig[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair] struct {
	allowHeaderJWT bool
	parseTokenFunc func(string) (*scrypto.JWT[PRIV, PUB], error)
	jwk            *scrypto.JWK[PRIV, PUB]
}

func defaultParseTokenFunc[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](jwk *scrypto.JWK[PRIV, PUB]) func(string) (*scrypto.JWT[PRIV, PUB], error) {
	return func(tokenStr string) (*scrypto.JWT[PRIV, PUB], error) {
		if tokenStr == "" {
			return nil, scrypto.ErrInvalidToken
		}
		return scrypto.ParseAuthToken(tokenStr, jwk)
	}
}

func defaultConfig[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](jwk *scrypto.JWK[PRIV, PUB], options ...Option[PRIV, PUB]) *middlewareConfig[PRIV, PUB] {
	config := &middlewareConfig[PRIV, PUB]{
		allowHeaderJWT: true,
		jwk:            jwk,
		parseTokenFunc: defaultParseTokenFunc(jwk),
	}

	// Apply any additional options
	for _, opt := range options {
		opt(config)
	}
	return config
}

func WithHeaderJWT[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](allow bool) Option[PRIV, PUB] {
	return func(config *middlewareConfig[PRIV, PUB]) {
		config.allowHeaderJWT = allow
	}
}

func WithParseTokenFunc[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](parseFunc func(string) (*scrypto.JWT[PRIV, PUB], error)) Option[PRIV, PUB] {
	return func(config *middlewareConfig[PRIV, PUB]) {
		if parseFunc != nil {
			config.parseTokenFunc = parseFunc
		}
	}
}

type Option[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair] func(*middlewareConfig[PRIV, PUB])

// ValidateJWTMiddleware is a middleware that validates JWT tokens in the request.
// It checks the token in the "Authorization" header and, if not found, it checks the "token" cookie.
// If the token is valid, it calls the next handler in the chain.
// If the token is invalid, it returns a 401 Unauthorized response.
func ValidateJWTMiddleware[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](jwk *scrypto.JWK[PRIV, PUB], options ...Option[PRIV, PUB]) mux.MiddlewareFunc {
	config := defaultConfig(jwk)
	for _, opt := range options {
		opt(config)
	}

	return func(next http.Handler) http.Handler {
		return validateJWT(config, next)
	}
}

func validateJWT[PRIV scrypto.PrivateKeyPair, PUB scrypto.PublicKeyPair](config *middlewareConfig[PRIV, PUB], next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string

		// Try header token if allowed
		if config.allowHeaderJWT {
			tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}

		// Fallback to cookie if no header token was provided
		if tokenStr == "" {
			if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
				tokenStr = cookie.Value
			}
		}

		// Parse and validate token using the pre-configured function
		token, err := config.parseTokenFunc(tokenStr)
		if err != nil || token == nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		} // Store token in context for downstream handlers
		ctx := context.WithValue(r.Context(), jwtContextKey("jwt"), token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

package ablibhttp

import (
	"context"
	"net"
	"net/http"
)

const XUserTokenHeader = "X-User-Token"

type RateLimiter interface {
	Allow(ctx context.Context, userID string) bool
}

// RateLimitMiddleware is an HTTP middleware that applies rate limiting to incoming requests.
func RateLimitMiddleware(rl RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			userID := getUserIDFromRequest(r)

			if !rl.Allow(ctx, userID) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			w.Header().Set(XUserTokenHeader, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// getUserIDFromRequest extracts the user ID from the HTTP request.
func getUserIDFromRequest(r *http.Request) string {
	// First try to get from header
	if token := r.Header.Get(XUserTokenHeader); token != "" {
		return token
	}

	// Fall back to IP address
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if ip == "" {
		return "unknown"
	}

	return ip
}

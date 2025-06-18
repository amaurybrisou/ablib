package ablibhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coremodels "github.com/amaurybrisou/ablib/models"
	"github.com/google/uuid"
)

// Helper to create a context with user values.
func createTestContext(role coremodels.GatewayRole) context.Context {
	now := time.Now()
	// Create dummy pointer times.
	updatedAt := now
	deletedAt := now

	ctx := context.Background()
	ctx = context.WithValue(ctx, UserIDCtxKey, uuid.New())
	ctx = context.WithValue(ctx, ExternalIDCtxKey, "external-id")
	ctx = context.WithValue(ctx, UserEmail, "user@example.com")
	ctx = context.WithValue(ctx, UserFirstname, "First")
	ctx = context.WithValue(ctx, UserLastname, "Last")
	ctx = context.WithValue(ctx, UserRole, role)
	ctx = context.WithValue(ctx, UserCreatedAt, now)
	ctx = context.WithValue(ctx, UserUpdatedAt, &updatedAt)
	ctx = context.WithValue(ctx, UserDeletedAt, &deletedAt)
	return ctx
}

// createRequest builds a new GET request using the provided context.
func createRequest(ctx context.Context) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	return req.WithContext(ctx)
}

func TestIsAdminMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		role           coremodels.GatewayRole
		expectedStatus int
		nextCalled     bool
		expectedBody   string
	}{
		{
			name:           "admin",
			role:           coremodels.ADMIN,
			expectedStatus: http.StatusOK,
			nextCalled:     true,
			expectedBody:   "OK",
		},
		{
			name:           "non admin",
			role:           coremodels.GatewayRole("user"),
			expectedStatus: http.StatusForbidden,
			nextCalled:     false,
			expectedBody:   "Unauthorized\n",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := createTestContext(tt.role)
			req := createRequest(ctx)
			rr := httptest.NewRecorder()

			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK")) //nolint:errcheck,gosec
			})

			IsAdminMiddleware(next).ServeHTTP(rr, req)

			if called != tt.nextCalled {
				t.Errorf("expected next called %v, got %v", tt.nextCalled, called)
			}
			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
			if rr.Body.String() != tt.expectedBody {
				t.Errorf("expected body %q, got %q", tt.expectedBody, rr.Body.String())
			}
		})
	}
}

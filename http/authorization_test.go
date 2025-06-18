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

func TestIsAdminMiddleware_AllowsAdmin(t *testing.T) {
	t.Parallel()
	// Create a dummy admin user context.
	ctx := createTestContext(coremodels.ADMIN)

	// Create a request with our context.
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req = req.WithContext(ctx)

	// Create a response recorder.
	rr := httptest.NewRecorder()

	// Create a dummy next handler.
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK")) //nolint:errcheck,gosec
	})

	// Wrap the handler with the middleware.
	handler := IsAdminMiddleware(next)

	// Serve the request.
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("expected next handler to be called for admin user")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.String() != "OK" {
		t.Errorf("expected body %q, got %q", "OK", rr.Body.String())
	}
}

func TestIsAdminMiddleware_RejectsNonAdmin(t *testing.T) {
	t.Parallel()
	// Create a dummy non-admin user context.
	// Assuming a non-admin role is represented by something other than coremodels.ADMIN.
	nonAdminRole := coremodels.GatewayRole("user")
	ctx := createTestContext(nonAdminRole)

	// Create a request with our context.
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req = req.WithContext(ctx)

	// Create a response recorder.
	rr := httptest.NewRecorder()

	// Create a dummy next handler.
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK")) //nolint:errcheck, gosec
	})

	// Wrap the handler with the middleware.
	handler := IsAdminMiddleware(next)

	// Serve the request.
	handler.ServeHTTP(rr, req)

	if called {
		t.Error("expected next handler to NOT be called for non-admin user")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected status code %d, got %d", http.StatusForbidden, rr.Code)
	}
	expectedBody := "Unauthorized\n"
	if rr.Body.String() != expectedBody {
		t.Errorf("expected body %q, got %q", expectedBody, rr.Body.String())
	}
}

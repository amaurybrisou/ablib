package ablibhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	ablibmodels "github.com/amaurybrisou/ablib/models"
)

type stubAuthRepo struct{}

func (stubAuthRepo) GetUserByEmail(_ context.Context, _ string) (ablibmodels.UserInterface, error) {
	return ablibmodels.User{}, nil
}

func (stubAuthRepo) GetUserByID(_ context.Context, _ string) (ablibmodels.UserInterface, error) {
	return ablibmodels.User{}, nil
}

func (stubAuthRepo) AddRefreshToken(_ context.Context, _ string, _ string) error { return nil }
func (stubAuthRepo) RemoveRefreshToken(_ context.Context, _ string) error        { return nil }

func TestCookieAuthMiddleware_NoCookie(t *testing.T) {
	auth := NewCookieAuthHandler("secret", "session", "", 3600, stubAuthRepo{})
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	handler := auth.Middleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if called {
		t.Fatal("next handler should not be called")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestCookieAuthLogout_NoCookie(t *testing.T) {
	auth := NewCookieAuthHandler("secret", "session", "", 3600, stubAuthRepo{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	auth.Logout(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected status %d got %d", http.StatusSeeOther, rr.Code)
	}
	if sc := rr.Header().Get("Set-Cookie"); sc != "" {
		t.Fatalf("did not expect Set-Cookie header, got %s", sc)
	}
}

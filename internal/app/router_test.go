package app_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaitou-1412/auth-service/internal/app"
)

var testKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func TestNewRouter_ReturnsRouterAndCleanup(t *testing.T) {
	r, cleanup := app.NewRouter(nil, testKey, &testKey.PublicKey)
	defer cleanup()

	if r == nil {
		t.Fatal("expected non-nil router")
	}
}

func TestNewRouter_HealthEndpoint(t *testing.T) {
	r, cleanup := app.NewRouter(nil, testKey, &testKey.PublicKey)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /v1/health: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestNewRouter_SwaggerEndpoint(t *testing.T) {
	r, cleanup := app.NewRouter(nil, testKey, &testKey.PublicKey)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /swagger: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestNewRouter_UnauthenticatedRouteReturns401(t *testing.T) {
	r, cleanup := app.NewRouter(nil, testKey, &testKey.PublicKey)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/auth/sessions without auth: got status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestNewRouter_UnknownRouteReturns405Or404(t *testing.T) {
	r, cleanup := app.NewRouter(nil, testKey, &testKey.PublicKey)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/nonexistent: got status %d, want 404 or 405", rr.Code)
	}
}

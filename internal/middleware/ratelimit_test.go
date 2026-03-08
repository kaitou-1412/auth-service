package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/kaitou-1412/auth-service/internal/middleware"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimitByIP_AllowsWithinLimit(t *testing.T) {
	rl := middleware.NewIPRateLimiter(rate.Limit(10), 10)
	handler := middleware.RateLimitByIP(rl)(okHandler())

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}
}

func TestRateLimitByIP_BlocksOverLimit(t *testing.T) {
	rl := middleware.NewIPRateLimiter(rate.Limit(1), 2)
	handler := middleware.RateLimitByIP(rl)(okHandler())

	ip := "10.0.0.1:9999"

	// Exhaust burst
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got status %d, want %d", i+1, rr.Code, http.StatusOK)
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["error"] != "rate limit exceeded" {
		t.Errorf("got error %q, want %q", resp["error"], "rate limit exceeded")
	}
	if rr.Header().Get("Retry-After") != "60" {
		t.Errorf("got Retry-After %q, want %q", rr.Header().Get("Retry-After"), "60")
	}
}

func TestStartCleanup_RemovesStaleEntries(t *testing.T) {
	rl := middleware.NewIPRateLimiter(rate.Limit(1), 1)
	handler := middleware.RateLimitByIP(rl)(okHandler())

	// Create an entry
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "3.3.3.3:3333"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rr.Code, http.StatusOK)
	}

	// Start cleanup with very short intervals
	stop := rl.StartCleanup(10*time.Millisecond, 20*time.Millisecond)
	defer stop()

	// Wait for cleanup to run and evict the entry
	time.Sleep(100 * time.Millisecond)

	// The limiter for this IP should have been cleaned up,
	// so a new request should get a fresh limiter and pass
	// (even though we exhausted the burst earlier)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "3.3.3.3:3333"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("after cleanup: got status %d, want %d (expected fresh limiter)", rr.Code, http.StatusOK)
	}
}

func TestStartCleanup_StopFunction(t *testing.T) {
	rl := middleware.NewIPRateLimiter(rate.Limit(1), 1)
	stop := rl.StartCleanup(10*time.Millisecond, 20*time.Millisecond)

	// Should not panic when called
	stop()
}

func TestRateLimitByIP_IndependentPerIP(t *testing.T) {
	rl := middleware.NewIPRateLimiter(rate.Limit(1), 1)
	handler := middleware.RateLimitByIP(rl)(okHandler())

	// Exhaust IP 1
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.1.1.1:1111"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("IP1 first request: got status %d, want %d", rr.Code, http.StatusOK)
	}

	// IP 1 should be blocked
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.1.1.1:1111"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("IP1 second request: got status %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// IP 2 should still pass
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "2.2.2.2:2222"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("IP2 first request: got status %d, want %d", rr.Code, http.StatusOK)
	}
}

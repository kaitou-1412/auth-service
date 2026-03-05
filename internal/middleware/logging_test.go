package middleware_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/kaitou-1412/auth-service/internal/middleware"
)

// logCapture is a slog.Handler that records all log records for inspection.
type logCapture struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *logCapture) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *logCapture) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *logCapture) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *logCapture) WithGroup(_ string) slog.Handler      { return h }

func (h *logCapture) levels() []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()
	levels := make([]slog.Level, len(h.records))
	for i, r := range h.records {
		levels[i] = r.Level
	}
	return levels
}

func setupLogCapture(t *testing.T) *logCapture {
	t.Helper()
	capture := &logCapture{}
	original := slog.Default()
	slog.SetDefault(slog.New(capture))
	t.Cleanup(func() { slog.SetDefault(original) })
	return capture
}

func handlerWithStatus(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	})
}

func TestLoggingMiddleware_SkipsNoisyPaths(t *testing.T) {
	paths := []string{"/v1/health", "/swagger", "/api/openapi.yaml"}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			capture := setupLogCapture(t)

			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()

			middleware.LoggingMiddleware(handlerWithStatus(http.StatusOK)).ServeHTTP(rr, req)

			if len(capture.levels()) != 0 {
				t.Errorf("expected no log records for %s, got %d", path, len(capture.levels()))
			}
		})
	}
}

func TestLoggingMiddleware_LogLevels(t *testing.T) {
	tests := []struct {
		name           string
		handlerStatus  int
		wantFinalLevel slog.Level
	}{
		{"2xx_logs_info", http.StatusOK, slog.LevelInfo},
		{"4xx_logs_warn", http.StatusBadRequest, slog.LevelWarn},
		{"5xx_logs_error", http.StatusInternalServerError, slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := setupLogCapture(t)

			req := httptest.NewRequest(http.MethodGet, "/v1/auth/signup", nil)
			rr := httptest.NewRecorder()

			middleware.LoggingMiddleware(handlerWithStatus(tt.handlerStatus)).ServeHTTP(rr, req)

			levels := capture.levels()
			if len(levels) != 2 {
				t.Fatalf("expected 2 log records (received + completed), got %d", len(levels))
			}
			if levels[0] != slog.LevelInfo {
				t.Errorf("first record: got level %v, want Info", levels[0])
			}
			if levels[1] != tt.wantFinalLevel {
				t.Errorf("second record: got level %v, want %v", levels[1], tt.wantFinalLevel)
			}
		})
	}
}

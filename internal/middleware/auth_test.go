package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kaitou-1412/auth-service/internal/middleware"
)

var testKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := token.SignedString(testKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return s
}

func validClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":        "user-id-123",
		"session_id": "session-id-456",
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
		"iat":        time.Now().Unix(),
	}
}

func TestAuthMiddleware(t *testing.T) {
	// handler that captures context values
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := middleware.UserIDFromContext(r.Context())
		sessionID := middleware.SessionIDFromContext(r.Context())
		json.NewEncoder(w).Encode(map[string]string{
			"user_id":    userID,
			"session_id": sessionID,
		})
	})

	mw := middleware.AuthMiddleware(&testKey.PublicKey)
	handler := mw(nextHandler)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		wantErrMsg string
	}{
		{
			name:       "missing_header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "missing authorization header",
		},
		{
			name:       "invalid_format",
			authHeader: "Basic abc123",
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "invalid authorization header",
		},
		{
			name:       "invalid_token",
			authHeader: "Bearer invalid-token",
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "invalid or expired token",
		},
		{
			name: "expired_token",
			authHeader: "Bearer " + signToken(t, jwt.MapClaims{
				"sub":        "user-id",
				"session_id": "session-id",
				"exp":        time.Now().Add(-1 * time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "invalid or expired token",
		},
		{
			name: "missing_sub",
			authHeader: "Bearer " + signToken(t, jwt.MapClaims{
				"session_id": "session-id",
				"exp":        time.Now().Add(15 * time.Minute).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "invalid token claims",
		},
		{
			name: "missing_session_id",
			authHeader: "Bearer " + signToken(t, jwt.MapClaims{
				"sub": "user-id",
				"exp": time.Now().Add(15 * time.Minute).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: "invalid token claims",
		},
		{
			name:       "valid_token",
			authHeader: "Bearer " + signToken(t, validClaims()),
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rr.Code, tt.wantStatus)
			}

			if tt.wantErrMsg != "" {
				var resp map[string]string
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["error"] != tt.wantErrMsg {
					t.Errorf("got error %q, want %q", resp["error"], tt.wantErrMsg)
				}
			}

			if tt.wantStatus == http.StatusOK {
				var resp map[string]string
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				if resp["user_id"] != "user-id-123" {
					t.Errorf("got user_id %q, want %q", resp["user_id"], "user-id-123")
				}
				if resp["session_id"] != "session-id-456" {
					t.Errorf("got session_id %q, want %q", resp["session_id"], "session-id-456")
				}
			}
		})
	}
}

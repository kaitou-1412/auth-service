package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/handler"
	"github.com/kaitou-1412/auth-service/internal/middleware"
	"github.com/kaitou-1412/auth-service/internal/service"
)

type mockAuthService struct {
	signupFn func(ctx context.Context, params service.SignupParams) (db.User, error)
	loginFn  func(ctx context.Context, params service.LoginParams) (service.LoginResult, error)
	logoutFn func(ctx context.Context, sessionID string) error
}

func (m *mockAuthService) Signup(ctx context.Context, params service.SignupParams) (db.User, error) {
	return m.signupFn(ctx, params)
}

func (m *mockAuthService) Login(ctx context.Context, params service.LoginParams) (service.LoginResult, error) {
	return m.loginFn(ctx, params)
}

func (m *mockAuthService) Logout(ctx context.Context, sessionID string) error {
	return m.logoutFn(ctx, sessionID)
}

func newSignupRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/signup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuthHandler_Signup(t *testing.T) {
	validAppID := "00000000-0000-0000-0000-000000000001"
	var parsedAppID pgtype.UUID
	_ = parsedAppID.Scan(validAppID)

	isActive := true
	emailVerified := false
	successUser := db.User{
		AppID:         parsedAppID,
		Email:         "test@example.com",
		IsActive:      &isActive,
		EmailVerified: &emailVerified,
	}

	tests := []struct {
		name       string
		body       string
		signupFn   func(ctx context.Context, params service.SignupParams) (db.User, error)
		wantStatus int
		wantErrMsg string
	}{
		{
			name:       "invalid_json",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "invalid request body",
		},
		{
			name:       "missing_app_id",
			body:       `{"email":"test@example.com","password":"pass123"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name:       "missing_email",
			body:       `{"app_id":"` + validAppID + `","password":"pass123"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name:       "missing_password",
			body:       `{"app_id":"` + validAppID + `","email":"test@example.com"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name: "email_taken",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			signupFn: func(_ context.Context, _ service.SignupParams) (db.User, error) {
				return db.User{}, service.ErrEmailTaken
			},
			wantStatus: http.StatusConflict,
			wantErrMsg: service.ErrEmailTaken.Error(),
		},
		{
			name: "invalid_app_id",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			signupFn: func(_ context.Context, _ service.SignupParams) (db.User, error) {
				return db.User{}, service.ErrInvalidAppID
			},
			wantStatus: http.StatusBadRequest,
			wantErrMsg: service.ErrInvalidAppID.Error(),
		},
		{
			name: "session_user_mismatch",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			signupFn: func(_ context.Context, _ service.SignupParams) (db.User, error) {
				return db.User{}, service.ErrSessionUserMismatch
			},
			wantStatus: http.StatusForbidden,
			wantErrMsg: service.ErrSessionUserMismatch.Error(),
		},
		{
			name: "internal_error",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			signupFn: func(_ context.Context, _ service.SignupParams) (db.User, error) {
				return db.User{}, service.ErrUserNotFound
			},
			wantStatus: http.StatusNotFound,
			wantErrMsg: service.ErrUserNotFound.Error(),
		},
		{
			name: "success",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			signupFn: func(_ context.Context, _ service.SignupParams) (db.User, error) {
				return successUser, nil
			},
			wantStatus: http.StatusCreated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{signupFn: tt.signupFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.Signup(rr, newSignupRequest(t, tt.body))

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

			if tt.wantStatus == http.StatusCreated {
				var resp map[string]any
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal success response: %v", err)
				}
				if resp["email"] != "test@example.com" {
					t.Errorf("got email %v, want test@example.com", resp["email"])
				}
				if _, ok := resp["password_hash"]; ok {
					t.Error("response must not contain password_hash")
				}
			}
		})
	}
}

func newLoginRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuthHandler_Login(t *testing.T) {
	validAppID := "00000000-0000-0000-0000-000000000001"

	successResult := service.LoginResult{
		AccessToken:  "jwt-token",
		RefreshToken: "refresh-token",
	}

	tests := []struct {
		name       string
		body       string
		loginFn    func(ctx context.Context, params service.LoginParams) (service.LoginResult, error)
		wantStatus int
		wantErrMsg string
	}{
		{
			name:       "invalid_json",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "invalid request body",
		},
		{
			name:       "missing_app_id",
			body:       `{"email":"test@example.com","password":"pass123"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name:       "missing_email",
			body:       `{"app_id":"` + validAppID + `","password":"pass123"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name:       "missing_password",
			body:       `{"app_id":"` + validAppID + `","email":"test@example.com"}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "app_id, email, and password are required",
		},
		{
			name: "invalid_credentials",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"wrong"}`,
			loginFn: func(_ context.Context, _ service.LoginParams) (service.LoginResult, error) {
				return service.LoginResult{}, service.ErrInvalidCredentials
			},
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: service.ErrInvalidCredentials.Error(),
		},
		{
			name: "invalid_app_id",
			body: `{"app_id":"bad","email":"test@example.com","password":"pass123"}`,
			loginFn: func(_ context.Context, _ service.LoginParams) (service.LoginResult, error) {
				return service.LoginResult{}, service.ErrInvalidAppID
			},
			wantStatus: http.StatusBadRequest,
			wantErrMsg: service.ErrInvalidAppID.Error(),
		},
		{
			name: "success",
			body: `{"app_id":"` + validAppID + `","email":"test@example.com","password":"pass123"}`,
			loginFn: func(_ context.Context, _ service.LoginParams) (service.LoginResult, error) {
				return successResult, nil
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{loginFn: tt.loginFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.Login(rr, newLoginRequest(t, tt.body))

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
					t.Fatalf("failed to unmarshal success response: %v", err)
				}
				if resp["access_token"] != "jwt-token" {
					t.Errorf("got access_token %q, want %q", resp["access_token"], "jwt-token")
				}
				if resp["refresh_token"] != "refresh-token" {
					t.Errorf("got refresh_token %q, want %q", resp["refresh_token"], "refresh-token")
				}
			}
		})
	}
}

func newLogoutRequest(t *testing.T, sessionID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextKeySessionID, sessionID)
	return req.WithContext(ctx)
}

func TestAuthHandler_Logout(t *testing.T) {
	validSessionID := "00000000-0000-0000-0000-000000000003"

	tests := []struct {
		name       string
		sessionID  string
		logoutFn   func(ctx context.Context, sessionID string) error
		wantStatus int
		wantErrMsg string
	}{
		{
			name:      "invalid_session_id",
			sessionID: "bad-id",
			logoutFn: func(_ context.Context, _ string) error {
				return service.ErrInvalidSessionID
			},
			wantStatus: http.StatusBadRequest,
			wantErrMsg: service.ErrInvalidSessionID.Error(),
		},
		{
			name:      "service_error",
			sessionID: validSessionID,
			logoutFn: func(_ context.Context, _ string) error {
				return errors.New("db error")
			},
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
		{
			name:      "success",
			sessionID: validSessionID,
			logoutFn: func(_ context.Context, _ string) error {
				return nil
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{logoutFn: tt.logoutFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.Logout(rr, newLogoutRequest(t, tt.sessionID))

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
					t.Fatalf("failed to unmarshal success response: %v", err)
				}
				if resp["message"] != "logged out successfully" {
					t.Errorf("got message %q, want %q", resp["message"], "logged out successfully")
				}
			}
		})
	}
}

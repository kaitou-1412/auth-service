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
	signupFn       func(ctx context.Context, params service.SignupParams) (db.User, error)
	loginFn        func(ctx context.Context, params service.LoginParams) (service.LoginResult, error)
	logoutFn       func(ctx context.Context, sessionID string) error
	logoutAllFn      func(ctx context.Context, userID string) error
	changePasswordFn func(ctx context.Context, params service.ChangePasswordParams) error
	refreshTokenFn   func(ctx context.Context, rawToken string) (service.RefreshTokenResult, error)
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

func (m *mockAuthService) LogoutAll(ctx context.Context, userID string) error {
	return m.logoutAllFn(ctx, userID)
}

func (m *mockAuthService) ChangePassword(ctx context.Context, params service.ChangePasswordParams) error {
	return m.changePasswordFn(ctx, params)
}

func (m *mockAuthService) RefreshToken(ctx context.Context, rawToken string) (service.RefreshTokenResult, error) {
	return m.refreshTokenFn(ctx, rawToken)
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

func newLogoutAllRequest(t *testing.T, userID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout-all", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, userID)
	return req.WithContext(ctx)
}

func TestAuthHandler_LogoutAll(t *testing.T) {
	validUserID := "00000000000000000000000000000001"

	tests := []struct {
		name       string
		userID     string
		logoutAllFn func(ctx context.Context, userID string) error
		wantStatus int
		wantErrMsg string
	}{
		{
			name:   "service_error",
			userID: validUserID,
			logoutAllFn: func(_ context.Context, _ string) error {
				return errors.New("db error")
			},
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
		{
			name:   "success",
			userID: validUserID,
			logoutAllFn: func(_ context.Context, _ string) error {
				return nil
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{logoutAllFn: tt.logoutAllFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.LogoutAll(rr, newLogoutAllRequest(t, tt.userID))

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
				if resp["message"] != "logged out from all devices" {
					t.Errorf("got message %q, want %q", resp["message"], "logged out from all devices")
				}
			}
		})
	}
}

func newChangePasswordRequest(t *testing.T, body string, userID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, userID)
	return req.WithContext(ctx)
}

func TestAuthHandler_ChangePassword(t *testing.T) {
	validUserID := "00000000000000000000000000000001"

	tests := []struct {
		name             string
		body             string
		userID           string
		changePasswordFn func(ctx context.Context, params service.ChangePasswordParams) error
		wantStatus       int
		wantErrMsg       string
	}{
		{
			name:       "invalid_json",
			body:       `{invalid}`,
			userID:     validUserID,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "invalid request body",
		},
		{
			name:       "missing_current_password",
			body:       `{"new_password":"NewPass1!"}`,
			userID:     validUserID,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "current_password and new_password are required",
		},
		{
			name:       "missing_new_password",
			body:       `{"current_password":"OldPass1!"}`,
			userID:     validUserID,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "current_password and new_password are required",
		},
		{
			name:   "wrong_current_password",
			body:   `{"current_password":"WrongPass1!","new_password":"NewPass1!"}`,
			userID: validUserID,
			changePasswordFn: func(_ context.Context, _ service.ChangePasswordParams) error {
				return service.ErrInvalidCredentials
			},
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: service.ErrInvalidCredentials.Error(),
		},
		{
			name:   "invalid_new_password",
			body:   `{"current_password":"OldPass1!","new_password":"weak"}`,
			userID: validUserID,
			changePasswordFn: func(_ context.Context, _ service.ChangePasswordParams) error {
				return service.ErrPasswordLength
			},
			wantStatus: http.StatusBadRequest,
			wantErrMsg: service.ErrPasswordLength.Error(),
		},
		{
			name:   "user_not_found",
			body:   `{"current_password":"OldPass1!","new_password":"NewPass1!"}`,
			userID: validUserID,
			changePasswordFn: func(_ context.Context, _ service.ChangePasswordParams) error {
				return service.ErrUserNotFound
			},
			wantStatus: http.StatusNotFound,
			wantErrMsg: service.ErrUserNotFound.Error(),
		},
		{
			name:   "internal_error",
			body:   `{"current_password":"OldPass1!","new_password":"NewPass1!"}`,
			userID: validUserID,
			changePasswordFn: func(_ context.Context, _ service.ChangePasswordParams) error {
				return errors.New("db error")
			},
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
		{
			name:   "success",
			body:   `{"current_password":"OldPass1!","new_password":"NewPass1!"}`,
			userID: validUserID,
			changePasswordFn: func(_ context.Context, _ service.ChangePasswordParams) error {
				return nil
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{changePasswordFn: tt.changePasswordFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.ChangePassword(rr, newChangePasswordRequest(t, tt.body, tt.userID))

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
				if resp["message"] != "password changed successfully" {
					t.Errorf("got message %q, want %q", resp["message"], "password changed successfully")
				}
			}
		})
	}
}

func newRefreshTokenRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	successResult := service.RefreshTokenResult{
		AccessToken:  "new-jwt-token",
		RefreshToken: "new-refresh-token",
		ExpiresIn:    900,
		TokenType:    "Bearer",
	}

	tests := []struct {
		name           string
		body           string
		refreshTokenFn func(ctx context.Context, rawToken string) (service.RefreshTokenResult, error)
		wantStatus     int
		wantErrMsg     string
	}{
		{
			name:       "invalid_json",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "invalid request body",
		},
		{
			name:       "missing_refresh_token",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantErrMsg: "refresh_token is required",
		},
		{
			name: "token_not_found",
			body: `{"refresh_token":"invalid-token"}`,
			refreshTokenFn: func(_ context.Context, _ string) (service.RefreshTokenResult, error) {
				return service.RefreshTokenResult{}, service.ErrTokenNotFound
			},
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: service.ErrTokenNotFound.Error(),
		},
		{
			name: "session_revoked",
			body: `{"refresh_token":"some-token"}`,
			refreshTokenFn: func(_ context.Context, _ string) (service.RefreshTokenResult, error) {
				return service.RefreshTokenResult{}, service.ErrSessionRevoked
			},
			wantStatus: http.StatusUnauthorized,
			wantErrMsg: service.ErrSessionRevoked.Error(),
		},
		{
			name: "internal_error",
			body: `{"refresh_token":"some-token"}`,
			refreshTokenFn: func(_ context.Context, _ string) (service.RefreshTokenResult, error) {
				return service.RefreshTokenResult{}, errors.New("db error")
			},
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
		{
			name: "success",
			body: `{"refresh_token":"valid-token"}`,
			refreshTokenFn: func(_ context.Context, _ string) (service.RefreshTokenResult, error) {
				return successResult, nil
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &mockAuthService{refreshTokenFn: tt.refreshTokenFn}
			h := handler.NewAuthHandler(svc)

			rr := httptest.NewRecorder()
			h.RefreshToken(rr, newRefreshTokenRequest(t, tt.body))

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
				var resp map[string]any
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to unmarshal success response: %v", err)
				}
				if resp["access_token"] != "new-jwt-token" {
					t.Errorf("got access_token %v, want new-jwt-token", resp["access_token"])
				}
				if resp["refresh_token"] != "new-refresh-token" {
					t.Errorf("got refresh_token %v, want new-refresh-token", resp["refresh_token"])
				}
				if resp["expires_in"] != float64(900) {
					t.Errorf("got expires_in %v, want 900", resp["expires_in"])
				}
				if resp["token_type"] != "Bearer" {
					t.Errorf("got token_type %v, want Bearer", resp["token_type"])
				}
			}
		})
	}
}

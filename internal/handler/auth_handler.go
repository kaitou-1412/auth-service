package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/middleware"
	"github.com/kaitou-1412/auth-service/internal/service"
)

type AuthService interface {
	Signup(ctx context.Context, params service.SignupParams) (db.User, error)
	Login(ctx context.Context, params service.LoginParams) (service.LoginResult, error)
	Logout(ctx context.Context, sessionID string) error
	LogoutAll(ctx context.Context, userID string) error
	ChangePassword(ctx context.Context, params service.ChangePasswordParams) error
	RefreshToken(ctx context.Context, rawToken string) (service.RefreshTokenResult, error)
}

type AuthHandler struct {
	svc AuthService
}

func NewAuthHandler(svc AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func httpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrEmailTaken):
		RespondWithError(w, http.StatusConflict, err.Error())
	case errors.Is(err, service.ErrInvalidCredentials):
		RespondWithError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, service.ErrSessionNotFound),
		errors.Is(err, service.ErrSessionRevoked),
		errors.Is(err, service.ErrSessionExpired),
		errors.Is(err, service.ErrTokenNotFound),
		errors.Is(err, service.ErrTokenRevoked):
		RespondWithError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, service.ErrUserNotFound):
		RespondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrAppNotFound):
		RespondWithError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, service.ErrInvalidAppID),
		errors.Is(err, service.ErrInvalidUserID),
		errors.Is(err, service.ErrInvalidSessionID),
		errors.Is(err, service.ErrInvalidRoleID),
		errors.Is(err, service.ErrInvalidEmail),
		errors.Is(err, service.ErrPasswordLength),
		errors.Is(err, service.ErrPasswordComplexity),
		errors.Is(err, service.ErrPasswordLeadingTrailingSpaces):
		RespondWithError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, service.ErrSessionUserMismatch):
		RespondWithError(w, http.StatusForbidden, err.Error())
	default:
		RespondWithError(w, http.StatusInternalServerError, "internal server error")
	}
}

// signupRequest is the request body for POST /v1/auth/signup
type signupRequest struct {
	AppID    string `json:"app_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// signupResponse is the response body for POST /v1/auth/signup
type signupResponse struct {
	ID            pgtype.UUID      `json:"id"`
	AppID         pgtype.UUID      `json:"app_id"`
	Email         string           `json:"email"`
	IsActive      *bool            `json:"is_active"`
	EmailVerified *bool            `json:"email_verified"`
	CreatedAt     pgtype.Timestamp `json:"created_at"`
	UpdatedAt     pgtype.Timestamp `json:"updated_at"`
}

// loginRequest is the request body for POST /v1/auth/login
type loginRequest struct {
	AppID    string `json:"app_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse is the response body for POST /v1/auth/login
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	slog.Info("login request received")

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AppID == "" || req.Email == "" || req.Password == "" {
		RespondWithError(w, http.StatusBadRequest, "app_id, email, and password are required")
		return
	}

	var deviceInfo *string
	if ua := r.Header.Get("User-Agent"); ua != "" {
		deviceInfo = &ua
	}
	ip := r.RemoteAddr
	result, err := h.svc.Login(r.Context(), service.LoginParams{
		AppID:      req.AppID,
		Email:      req.Email,
		Password:   req.Password,
		DeviceInfo: deviceInfo,
		IPAddress:  &ip,
	})
	if err != nil {
		slog.Warn("login failed", "email", req.Email, "error", err)
		httpError(w, err)
		return
	}

	slog.Info("login successful", "email", req.Email)
	RespondWithJSON(w, http.StatusOK, loginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
	})
}

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	slog.Info("signup request received")

	var req signupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AppID == "" || req.Email == "" || req.Password == "" {
		RespondWithError(w, http.StatusBadRequest, "app_id, email, and password are required")
		return
	}

	user, err := h.svc.Signup(r.Context(), service.SignupParams{
		AppID:    req.AppID,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		slog.Warn("signup failed", "email", req.Email, "error", err)
		httpError(w, err)
		return
	}

	slog.Info("signup successful", "email", req.Email)
	RespondWithJSON(w, http.StatusCreated, signupResponse{
		ID:            user.ID,
		AppID:         user.AppID,
		Email:         user.Email,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromContext(r.Context())
	slog.Info("change password request received", "user_id", userID)

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		RespondWithError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	if err := h.svc.ChangePassword(r.Context(), service.ChangePasswordParams{
		UserID:          userID,
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}); err != nil {
		slog.Warn("change password failed", "user_id", userID, "error", err)
		httpError(w, err)
		return
	}

	slog.Info("change password successful", "user_id", userID)
	RespondWithJSON(w, http.StatusOK, map[string]string{"message": "password changed successfully"})
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	slog.Info("refresh token request received")

	var req refreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		RespondWithError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	result, err := h.svc.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		slog.Warn("refresh token failed", "error", err)
		httpError(w, err)
		return
	}

	slog.Info("refresh token successful")
	RespondWithJSON(w, http.StatusOK, refreshTokenResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
		TokenType:    result.TokenType,
	})
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := middleware.UserIDFromContext(r.Context())
	slog.Info("logout-all request received", "user_id", userID)

	if err := h.svc.LogoutAll(r.Context(), userID); err != nil {
		slog.Warn("logout-all failed", "user_id", userID, "error", err)
		httpError(w, err)
		return
	}

	slog.Info("logout-all successful", "user_id", userID)
	RespondWithJSON(w, http.StatusOK, map[string]string{"message": "logged out from all devices"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionID := middleware.SessionIDFromContext(r.Context())
	slog.Info("logout request received", "session_id", sessionID)

	if err := h.svc.Logout(r.Context(), sessionID); err != nil {
		slog.Warn("logout failed", "session_id", sessionID, "error", err)
		httpError(w, err)
		return
	}

	slog.Info("logout successful", "session_id", sessionID)
	RespondWithJSON(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

package service

import "errors"

var (
	ErrEmailTaken          = errors.New("email already registered for this app")
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionRevoked      = errors.New("session has been revoked")
	ErrSessionExpired      = errors.New("session has expired")
	ErrTokenNotFound       = errors.New("refresh token not found or expired")
	ErrTokenRevoked        = errors.New("refresh token has been revoked")
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidAppID        = errors.New("invalid app_id")
	ErrInvalidUserID       = errors.New("invalid user_id")
	ErrInvalidSessionID    = errors.New("invalid session_id")
	ErrInvalidRoleID       = errors.New("invalid role_id")
	ErrSessionUserMismatch = errors.New("session does not belong to this user")
)

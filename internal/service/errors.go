package service

import "errors"

var (
	ErrEmailTaken                  = errors.New("email already registered for this app")
	ErrInvalidCredentials          = errors.New("invalid email or password")
	ErrSessionNotFound             = errors.New("session not found")
	ErrSessionRevoked              = errors.New("session has been revoked")
	ErrSessionExpired              = errors.New("session has expired")
	ErrTokenNotFound               = errors.New("refresh token not found or expired")
	ErrTokenRevoked                = errors.New("refresh token has been revoked")
	ErrUserNotFound                = errors.New("user not found")
	ErrInvalidAppID                = errors.New("invalid app_id")
	ErrInvalidUserID               = errors.New("invalid user_id")
	ErrInvalidSessionID            = errors.New("invalid session_id")
	ErrInvalidRoleID               = errors.New("invalid role_id")
	ErrRoleNotFound                = errors.New("role not found")
	ErrRoleAlreadyAssigned         = errors.New("role already assigned to this user")
	ErrRoleNotAssigned             = errors.New("role not assigned to this user")
	ErrSessionUserMismatch         = errors.New("session does not belong to this user")
	ErrAppNotFound                 = errors.New("app not found")
	ErrInvalidEmail                = errors.New("invalid email address")
	ErrPasswordLength              = errors.New("password must be 8-128 characters")
	ErrPasswordComplexity          = errors.New("password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
	ErrPasswordLeadingTrailingSpaces = errors.New("password must not have leading or trailing spaces")
)

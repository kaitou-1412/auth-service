package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/service"
	"golang.org/x/crypto/bcrypt"
)

var testPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

// mockQuerier embeds db.Querier so only the methods under test need to be implemented.
// Any unexpected method call will panic, making test boundaries explicit.
type mockQuerier struct {
	db.Querier
	getApp                        func(ctx context.Context, id pgtype.UUID) (db.App, error)
	getUserByAppAndEmail          func(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error)
	createUser                    func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	createSession                 func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	createRefreshToken            func(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
	revokeRefreshTokensForSession func(ctx context.Context, sessionID pgtype.UUID) error
	revokeSession                 func(ctx context.Context, id pgtype.UUID) (db.Session, error)
	revokeAllSessionsForUser      func(ctx context.Context, userID pgtype.UUID) error
	revokeAllRefreshTokensForUser func(ctx context.Context, userID pgtype.UUID) error
	getUserPasswordHash           func(ctx context.Context, id pgtype.UUID) (string, error)
	updateUserPasswordHash        func(ctx context.Context, arg db.UpdateUserPasswordHashParams) (db.User, error)
	findRefreshToken              func(ctx context.Context, tokenHash string) (db.RefreshToken, error)
	verifySession                 func(ctx context.Context, id pgtype.UUID) (db.Session, error)
	revokeRefreshToken            func(ctx context.Context, id pgtype.UUID) (db.RefreshToken, error)
	getSessionsForUser            func(ctx context.Context, userID pgtype.UUID) ([]db.Session, error)
	verifySessionBelongsToUser    func(ctx context.Context, arg db.VerifySessionBelongsToUserParams) (db.Session, error)
	insertUserRole                func(ctx context.Context, arg db.InsertUserRoleParams) (db.UserRole, error)
	getUser                       func(ctx context.Context, id pgtype.UUID) (db.User, error)
	getRole                       func(ctx context.Context, id pgtype.UUID) (db.Role, error)
	getUserRole                   func(ctx context.Context, arg db.GetUserRoleParams) (db.UserRole, error)
	deleteUserRole                func(ctx context.Context, arg db.DeleteUserRoleParams) error
	getRolesForUser               func(ctx context.Context, userID pgtype.UUID) ([]db.Role, error)
}

func (m *mockQuerier) GetApp(ctx context.Context, id pgtype.UUID) (db.App, error) {
	return m.getApp(ctx, id)
}

func (m *mockQuerier) GetUserByAppAndEmail(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error) {
	return m.getUserByAppAndEmail(ctx, arg)
}

func (m *mockQuerier) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	return m.createUser(ctx, arg)
}

func (m *mockQuerier) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	return m.createSession(ctx, arg)
}

func (m *mockQuerier) CreateRefreshToken(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error) {
	return m.createRefreshToken(ctx, arg)
}

func (m *mockQuerier) RevokeRefreshTokensForSession(ctx context.Context, sessionID pgtype.UUID) error {
	return m.revokeRefreshTokensForSession(ctx, sessionID)
}

func (m *mockQuerier) RevokeSession(ctx context.Context, id pgtype.UUID) (db.Session, error) {
	return m.revokeSession(ctx, id)
}

func (m *mockQuerier) FindRefreshToken(ctx context.Context, tokenHash string) (db.RefreshToken, error) {
	return m.findRefreshToken(ctx, tokenHash)
}

func (m *mockQuerier) VerifySession(ctx context.Context, id pgtype.UUID) (db.Session, error) {
	return m.verifySession(ctx, id)
}

func (m *mockQuerier) RevokeRefreshToken(ctx context.Context, id pgtype.UUID) (db.RefreshToken, error) {
	return m.revokeRefreshToken(ctx, id)
}

func (m *mockQuerier) RevokeAllSessionsForUser(ctx context.Context, userID pgtype.UUID) error {
	return m.revokeAllSessionsForUser(ctx, userID)
}

func (m *mockQuerier) RevokeAllRefreshTokensForUser(ctx context.Context, userID pgtype.UUID) error {
	return m.revokeAllRefreshTokensForUser(ctx, userID)
}

func (m *mockQuerier) GetUserPasswordHash(ctx context.Context, id pgtype.UUID) (string, error) {
	return m.getUserPasswordHash(ctx, id)
}

func (m *mockQuerier) UpdateUserPasswordHash(ctx context.Context, arg db.UpdateUserPasswordHashParams) (db.User, error) {
	return m.updateUserPasswordHash(ctx, arg)
}

func (m *mockQuerier) GetSessionsForUser(ctx context.Context, userID pgtype.UUID) ([]db.Session, error) {
	return m.getSessionsForUser(ctx, userID)
}

func (m *mockQuerier) VerifySessionBelongsToUser(ctx context.Context, arg db.VerifySessionBelongsToUserParams) (db.Session, error) {
	return m.verifySessionBelongsToUser(ctx, arg)
}

func (m *mockQuerier) InsertUserRole(ctx context.Context, arg db.InsertUserRoleParams) (db.UserRole, error) {
	return m.insertUserRole(ctx, arg)
}

func (m *mockQuerier) GetUser(ctx context.Context, id pgtype.UUID) (db.User, error) {
	return m.getUser(ctx, id)
}

func (m *mockQuerier) GetRole(ctx context.Context, id pgtype.UUID) (db.Role, error) {
	return m.getRole(ctx, id)
}

func (m *mockQuerier) GetUserRole(ctx context.Context, arg db.GetUserRoleParams) (db.UserRole, error) {
	return m.getUserRole(ctx, arg)
}

func (m *mockQuerier) DeleteUserRole(ctx context.Context, arg db.DeleteUserRoleParams) error {
	return m.deleteUserRole(ctx, arg)
}

func (m *mockQuerier) GetRolesForUser(ctx context.Context, userID pgtype.UUID) ([]db.Role, error) {
	return m.getRolesForUser(ctx, userID)
}

func appFound(_ context.Context, _ pgtype.UUID) (db.App, error) {
	return db.App{}, nil
}

func TestAuthService_Signup(t *testing.T) {
	validAppID := "00000000-0000-0000-0000-000000000001"
	email := "test@example.com"
	password := "Password1!"

	var parsedAppID pgtype.UUID
	_ = parsedAppID.Scan(validAppID)

	returnedUser := db.User{
		AppID: parsedAppID,
		Email: email,
	}

	tests := []struct {
		name                string
		params              service.SignupParams
		getApp              func(ctx context.Context, id pgtype.UUID) (db.App, error)
		getUserByAppAndEmail func(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error)
		createUser          func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
		wantErr             error
		wantUser            bool
	}{
		{
			name: "invalid_app_id",
			params: service.SignupParams{
				AppID:    "not-a-uuid",
				Email:    email,
				Password: password,
			},
			wantErr: service.ErrInvalidAppID,
		},
		{
			name: "app_not_found",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: func(_ context.Context, _ pgtype.UUID) (db.App, error) {
				return db.App{}, pgx.ErrNoRows
			},
			wantErr: service.ErrAppNotFound,
		},
		{
			name: "invalid_email",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    "not-an-email",
				Password: password,
			},
			getApp:  appFound,
			wantErr: service.ErrInvalidEmail,
		},
		{
			name: "password_too_short",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: "Ab1!",
			},
			getApp:  appFound,
			wantErr: service.ErrPasswordLength,
		},
		{
			name: "password_no_uppercase",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: "password1!",
			},
			getApp:  appFound,
			wantErr: service.ErrPasswordComplexity,
		},
		{
			name: "password_no_special",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: "Password1",
			},
			getApp:  appFound,
			wantErr: service.ErrPasswordComplexity,
		},
		{
			name: "password_leading_space",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: " Password1!",
			},
			getApp:  appFound,
			wantErr: service.ErrPasswordLeadingTrailingSpaces,
		},
		{
			name: "email_already_taken",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return returnedUser, nil // no error = email exists
			},
			wantErr: service.ErrEmailTaken,
		},
		{
			name: "db_error_on_email_check",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return db.User{}, errors.New("connection refused")
			},
			wantErr: errors.New("connection refused"),
		},
		{
			name: "db_error_on_create",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			createUser: func(_ context.Context, _ db.CreateUserParams) (db.User, error) {
				return db.User{}, errors.New("insert failed")
			},
			wantErr: errors.New("insert failed"),
		},
		{
			name: "success",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			createUser: func(_ context.Context, arg db.CreateUserParams) (db.User, error) {
				if arg.Email != email {
					t.Errorf("CreateUser: got email %q, want %q", arg.Email, email)
				}
				if arg.PasswordHash == "" {
					t.Error("CreateUser: expected non-empty password hash")
				}
				return returnedUser, nil
			},
			wantUser: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getApp:              tt.getApp,
				getUserByAppAndEmail: tt.getUserByAppAndEmail,
				createUser:           tt.createUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			user, err := svc.Signup(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if tt.wantErr == service.ErrInvalidAppID || tt.wantErr == service.ErrEmailTaken ||
					tt.wantErr == service.ErrAppNotFound || tt.wantErr == service.ErrInvalidEmail ||
					tt.wantErr == service.ErrPasswordLength || tt.wantErr == service.ErrPasswordComplexity ||
					tt.wantErr == service.ErrPasswordLeadingTrailingSpaces {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantUser && user.Email != email {
				t.Errorf("got email %q, want %q", user.Email, email)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	validAppID := "00000000-0000-0000-0000-000000000001"
	email := "test@example.com"
	password := "Password1!"

	var parsedAppID pgtype.UUID
	_ = parsedAppID.Scan(validAppID)

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	isActive := true
	isInactive := false

	activeUser := db.User{
		ID:           pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		AppID:        parsedAppID,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     &isActive,
	}

	inactiveUser := db.User{
		ID:           pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
		AppID:        parsedAppID,
		Email:        email,
		PasswordHash: string(hash),
		IsActive:     &isInactive,
	}

	defaultSession := db.Session{
		ID:     pgtype.UUID{Bytes: [16]byte{3}, Valid: true},
		UserID: activeUser.ID,
	}

	noRoles := func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
		return []db.Role{}, nil
	}

	tests := []struct {
		name                 string
		params               service.LoginParams
		getApp               func(ctx context.Context, id pgtype.UUID) (db.App, error)
		getUserByAppAndEmail func(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error)
		createSession        func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
		createRefreshToken   func(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
		getRolesForUser      func(ctx context.Context, userID pgtype.UUID) ([]db.Role, error)
		wantErr              error
		wantResult           bool
	}{
		{
			name: "invalid_app_id",
			params: service.LoginParams{
				AppID:    "not-a-uuid",
				Email:    email,
				Password: password,
			},
			wantErr: service.ErrInvalidAppID,
		},
		{
			name: "app_not_found",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: func(_ context.Context, _ pgtype.UUID) (db.App, error) {
				return db.App{}, pgx.ErrNoRows
			},
			wantErr: service.ErrAppNotFound,
		},
		{
			name: "invalid_email",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    "not-an-email",
				Password: password,
			},
			getApp:  appFound,
			wantErr: service.ErrInvalidEmail,
		},
		{
			name: "user_not_found",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantErr: service.ErrInvalidCredentials,
		},
		{
			name: "db_error_on_user_fetch",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return db.User{}, errors.New("connection refused")
			},
			wantErr: errors.New("connection refused"),
		},
		{
			name: "user_inactive",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return inactiveUser, nil
			},
			wantErr: service.ErrInvalidCredentials,
		},
		{
			name: "wrong_password",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: "WrongPass1!",
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			wantErr: service.ErrInvalidCredentials,
		},
		{
			name: "create_session_fails",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			createSession: func(_ context.Context, _ db.CreateSessionParams) (db.Session, error) {
				return db.Session{}, errors.New("insert failed")
			},
			wantErr: errors.New("insert failed"),
		},
		{
			name: "create_refresh_token_fails",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			createSession: func(_ context.Context, _ db.CreateSessionParams) (db.Session, error) {
				return defaultSession, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, errors.New("insert failed")
			},
			wantErr: errors.New("insert failed"),
		},
		{
			name: "get_roles_fails",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			createSession: func(_ context.Context, _ db.CreateSessionParams) (db.Session, error) {
				return defaultSession, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return nil, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "success",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getApp: appFound,
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			createSession: func(_ context.Context, _ db.CreateSessionParams) (db.Session, error) {
				return defaultSession, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			getRolesForUser: noRoles,
			wantResult:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getApp:               tt.getApp,
				getUserByAppAndEmail: tt.getUserByAppAndEmail,
				createSession:        tt.createSession,
				createRefreshToken:   tt.createRefreshToken,
				getRolesForUser:      tt.getRolesForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.Login(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidAppID) || errors.Is(tt.wantErr, service.ErrInvalidCredentials) ||
					errors.Is(tt.wantErr, service.ErrAppNotFound) || errors.Is(tt.wantErr, service.ErrInvalidEmail) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantResult {
				if result.AccessToken == "" {
					t.Error("expected non-empty access_token")
				}
				if result.RefreshToken == "" {
					t.Error("expected non-empty refresh_token")
				}
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	validSessionID := "00000000-0000-0000-0000-000000000003"

	tests := []struct {
		name                          string
		sessionID                     string
		revokeRefreshTokensForSession func(ctx context.Context, sessionID pgtype.UUID) error
		revokeSession                 func(ctx context.Context, id pgtype.UUID) (db.Session, error)
		wantErr                       error
	}{
		{
			name:      "invalid_session_id",
			sessionID: "not-a-uuid",
			wantErr:   service.ErrInvalidSessionID,
		},
		{
			name:      "revoke_refresh_tokens_fails",
			sessionID: validSessionID,
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:      "revoke_session_fails",
			sessionID: validSessionID,
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeSession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:      "success",
			sessionID: validSessionID,
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeSession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				revokeRefreshTokensForSession: tt.revokeRefreshTokensForSession,
				revokeSession:                 tt.revokeSession,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			err := svc.Logout(context.Background(), tt.sessionID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidSessionID) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthService_RefreshToken(t *testing.T) {
	sessionID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	userID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	tokenID := pgtype.UUID{Bytes: [16]byte{10}, Valid: true}

	validToken := db.RefreshToken{
		ID:        tokenID,
		SessionID: sessionID,
		UserID:    userID,
	}

	validSession := db.Session{
		ID:     sessionID,
		UserID: userID,
	}

	tests := []struct {
		name               string
		rawToken           string
		findRefreshToken   func(ctx context.Context, tokenHash string) (db.RefreshToken, error)
		verifySession      func(ctx context.Context, id pgtype.UUID) (db.Session, error)
		revokeRefreshToken func(ctx context.Context, id pgtype.UUID) (db.RefreshToken, error)
		createRefreshToken func(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
		getRolesForUser    func(ctx context.Context, userID pgtype.UUID) ([]db.Role, error)
		wantErr            error
		wantResult         bool
	}{
		{
			name:     "token_not_found",
			rawToken: "invalid-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return db.RefreshToken{}, pgx.ErrNoRows
			},
			wantErr: service.ErrTokenNotFound,
		},
		{
			name:     "db_error_on_find",
			rawToken: "some-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return db.RefreshToken{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:     "session_invalid",
			rawToken: "some-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return validToken, nil
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, pgx.ErrNoRows
			},
			wantErr: service.ErrSessionRevoked,
		},
		{
			name:     "revoke_old_token_fails",
			rawToken: "some-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return validToken, nil
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return validSession, nil
			},
			revokeRefreshToken: func(_ context.Context, _ pgtype.UUID) (db.RefreshToken, error) {
				return db.RefreshToken{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:     "create_new_token_fails",
			rawToken: "some-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return validToken, nil
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return validSession, nil
			},
			revokeRefreshToken: func(_ context.Context, _ pgtype.UUID) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, errors.New("insert failed")
			},
			wantErr: errors.New("insert failed"),
		},
		{
			name:     "get_roles_fails",
			rawToken: "some-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return validToken, nil
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return validSession, nil
			},
			revokeRefreshToken: func(_ context.Context, _ pgtype.UUID) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return nil, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:     "success",
			rawToken: "valid-raw-token",
			findRefreshToken: func(_ context.Context, _ string) (db.RefreshToken, error) {
				return validToken, nil
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return validSession, nil
			},
			revokeRefreshToken: func(_ context.Context, _ pgtype.UUID) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return []db.Role{}, nil
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				findRefreshToken:   tt.findRefreshToken,
				verifySession:      tt.verifySession,
				revokeRefreshToken: tt.revokeRefreshToken,
				createRefreshToken: tt.createRefreshToken,
				getRolesForUser:    tt.getRolesForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.RefreshToken(context.Background(), tt.rawToken)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrTokenNotFound) || errors.Is(tt.wantErr, service.ErrSessionRevoked) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantResult {
				if result.AccessToken == "" {
					t.Error("expected non-empty access_token")
				}
				if result.RefreshToken == "" {
					t.Error("expected non-empty refresh_token")
				}
				if result.ExpiresIn != 900 {
					t.Errorf("got expires_in %d, want 900", result.ExpiresIn)
				}
				if result.TokenType != "Bearer" {
					t.Errorf("got token_type %q, want Bearer", result.TokenType)
				}
			}
		})
	}
}

func TestAuthService_LogoutAll(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"

	tests := []struct {
		name                          string
		userID                        string
		revokeAllSessionsForUser      func(ctx context.Context, userID pgtype.UUID) error
		revokeAllRefreshTokensForUser func(ctx context.Context, userID pgtype.UUID) error
		wantErr                       error
	}{
		{
			name:    "invalid_user_id",
			userID:  "not-a-uuid",
			wantErr: service.ErrInvalidUserID,
		},
		{
			name:   "revoke_sessions_fails",
			userID: validUserID,
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:   "revoke_refresh_tokens_fails",
			userID: validUserID,
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeAllRefreshTokensForUser: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:   "success",
			userID: validUserID,
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeAllRefreshTokensForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				revokeAllSessionsForUser:      tt.revokeAllSessionsForUser,
				revokeAllRefreshTokensForUser: tt.revokeAllRefreshTokensForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			err := svc.LogoutAll(context.Background(), tt.userID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthService_ChangePassword(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"
	currentPassword := "OldPass1!"
	newPassword := "NewPass1!"

	currentHash, _ := bcrypt.GenerateFromPassword([]byte(currentPassword), bcrypt.MinCost)

	tests := []struct {
		name                          string
		params                        service.ChangePasswordParams
		getUserPasswordHash           func(ctx context.Context, id pgtype.UUID) (string, error)
		updateUserPasswordHash        func(ctx context.Context, arg db.UpdateUserPasswordHashParams) (db.User, error)
		revokeAllSessionsForUser      func(ctx context.Context, userID pgtype.UUID) error
		revokeAllRefreshTokensForUser func(ctx context.Context, userID pgtype.UUID) error
		wantErr                       error
	}{
		{
			name: "invalid_user_id",
			params: service.ChangePasswordParams{
				UserID:          "not-a-uuid",
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			wantErr: service.ErrInvalidUserID,
		},
		{
			name: "user_not_found",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return "", pgx.ErrNoRows
			},
			wantErr: service.ErrUserNotFound,
		},
		{
			name: "db_error_on_get_hash",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return "", errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "wrong_current_password",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: "WrongPass1!",
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			wantErr: service.ErrInvalidCredentials,
		},
		{
			name: "invalid_new_password_too_short",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     "Ab1!",
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			wantErr: service.ErrPasswordLength,
		},
		{
			name: "invalid_new_password_no_special",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     "NewPassword1",
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			wantErr: service.ErrPasswordComplexity,
		},
		{
			name: "db_error_on_update",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			updateUserPasswordHash: func(_ context.Context, _ db.UpdateUserPasswordHashParams) (db.User, error) {
				return db.User{}, errors.New("update failed")
			},
			wantErr: errors.New("update failed"),
		},
		{
			name: "revoke_sessions_fails",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			updateUserPasswordHash: func(_ context.Context, _ db.UpdateUserPasswordHashParams) (db.User, error) {
				return db.User{}, nil
			},
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "revoke_tokens_fails",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			updateUserPasswordHash: func(_ context.Context, _ db.UpdateUserPasswordHashParams) (db.User, error) {
				return db.User{}, nil
			},
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeAllRefreshTokensForUser: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name: "success",
			params: service.ChangePasswordParams{
				UserID:          validUserID,
				CurrentPassword: currentPassword,
				NewPassword:     newPassword,
			},
			getUserPasswordHash: func(_ context.Context, _ pgtype.UUID) (string, error) {
				return string(currentHash), nil
			},
			updateUserPasswordHash: func(_ context.Context, arg db.UpdateUserPasswordHashParams) (db.User, error) {
				if arg.PasswordHash == "" {
					t.Error("expected non-empty new password hash")
				}
				return db.User{}, nil
			},
			revokeAllSessionsForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeAllRefreshTokensForUser: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getUserPasswordHash:           tt.getUserPasswordHash,
				updateUserPasswordHash:        tt.updateUserPasswordHash,
				revokeAllSessionsForUser:      tt.revokeAllSessionsForUser,
				revokeAllRefreshTokensForUser: tt.revokeAllRefreshTokensForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			err := svc.ChangePassword(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) ||
					errors.Is(tt.wantErr, service.ErrUserNotFound) ||
					errors.Is(tt.wantErr, service.ErrInvalidCredentials) ||
					errors.Is(tt.wantErr, service.ErrPasswordLength) ||
					errors.Is(tt.wantErr, service.ErrPasswordComplexity) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthService_GetSessions(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"
	currentSessionID := "03000000000000000000000000000000"

	sessionID1 := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	sessionID2 := pgtype.UUID{Bytes: [16]byte{4}, Valid: true}
	userID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	revoked := false

	sessions := []db.Session{
		{
			ID:      sessionID1,
			UserID:  userID,
			Revoked: &revoked,
		},
		{
			ID:      sessionID2,
			UserID:  userID,
			Revoked: &revoked,
		},
	}

	tests := []struct {
		name               string
		userID             string
		getSessionsForUser func(ctx context.Context, userID pgtype.UUID) ([]db.Session, error)
		wantErr            error
		wantCount          int
		wantCurrent        int
	}{
		{
			name:    "invalid_user_id",
			userID:  "not-a-uuid",
			wantErr: service.ErrInvalidUserID,
		},
		{
			name:   "db_error",
			userID: validUserID,
			getSessionsForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Session, error) {
				return nil, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:   "empty_sessions",
			userID: validUserID,
			getSessionsForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Session, error) {
				return []db.Session{}, nil
			},
			wantCount: 0,
		},
		{
			name:   "success_with_current_marked",
			userID: validUserID,
			getSessionsForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Session, error) {
				return sessions, nil
			},
			wantCount:   2,
			wantCurrent: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getSessionsForUser: tt.getSessionsForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.GetSessions(context.Background(), tt.userID, currentSessionID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantCount {
				t.Errorf("got %d sessions, want %d", len(result), tt.wantCount)
			}
			if tt.wantCount > 0 {
				if !result[tt.wantCurrent].Current {
					t.Errorf("expected session at index %d to be current", tt.wantCurrent)
				}
				if result[1].Current {
					t.Error("expected session at index 1 to not be current")
				}
			}
		})
	}
}

func TestAuthService_RevokeSession(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"
	validSessionID := "00000000-0000-0000-0000-000000000003"

	tests := []struct {
		name                          string
		userID                        string
		sessionID                     string
		verifySessionBelongsToUser    func(ctx context.Context, arg db.VerifySessionBelongsToUserParams) (db.Session, error)
		verifySession                 func(ctx context.Context, id pgtype.UUID) (db.Session, error)
		revokeRefreshTokensForSession func(ctx context.Context, sessionID pgtype.UUID) error
		revokeSession                 func(ctx context.Context, id pgtype.UUID) (db.Session, error)
		wantErr                       error
	}{
		{
			name:      "invalid_user_id",
			userID:    "not-a-uuid",
			sessionID: validSessionID,
			wantErr:   service.ErrInvalidUserID,
		},
		{
			name:      "invalid_session_id",
			userID:    validUserID,
			sessionID: "not-a-uuid",
			wantErr:   service.ErrInvalidSessionID,
		},
		{
			name:      "session_not_found",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, pgx.ErrNoRows
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, pgx.ErrNoRows
			},
			wantErr: service.ErrSessionNotFound,
		},
		{
			name:      "session_user_mismatch",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, pgx.ErrNoRows
			},
			verifySession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, nil
			},
			wantErr: service.ErrSessionUserMismatch,
		},
		{
			name:      "db_error_on_verify",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:      "revoke_refresh_tokens_fails",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, nil
			},
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:      "revoke_session_fails",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, nil
			},
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeSession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:      "success",
			userID:    validUserID,
			sessionID: validSessionID,
			verifySessionBelongsToUser: func(_ context.Context, _ db.VerifySessionBelongsToUserParams) (db.Session, error) {
				return db.Session{}, nil
			},
			revokeRefreshTokensForSession: func(_ context.Context, _ pgtype.UUID) error {
				return nil
			},
			revokeSession: func(_ context.Context, _ pgtype.UUID) (db.Session, error) {
				return db.Session{}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				verifySessionBelongsToUser:    tt.verifySessionBelongsToUser,
				verifySession:                 tt.verifySession,
				revokeRefreshTokensForSession: tt.revokeRefreshTokensForSession,
				revokeSession:                 tt.revokeSession,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			err := svc.RevokeSession(context.Background(), tt.userID, tt.sessionID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) ||
					errors.Is(tt.wantErr, service.ErrInvalidSessionID) ||
					errors.Is(tt.wantErr, service.ErrSessionNotFound) ||
					errors.Is(tt.wantErr, service.ErrSessionUserMismatch) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func userFound(_ context.Context, _ pgtype.UUID) (db.User, error) {
	return db.User{}, nil
}

func roleFound(_ context.Context, _ pgtype.UUID) (db.Role, error) {
	return db.Role{}, nil
}

func TestAuthService_AssignRole(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"
	validRoleID := "00000000-0000-0000-0000-000000000010"

	tests := []struct {
		name           string
		params         service.AssignRoleParams
		getUser        func(ctx context.Context, id pgtype.UUID) (db.User, error)
		getRole        func(ctx context.Context, id pgtype.UUID) (db.Role, error)
		insertUserRole func(ctx context.Context, arg db.InsertUserRoleParams) (db.UserRole, error)
		wantErr        error
		wantResult     bool
	}{
		{
			name:    "invalid_user_id",
			params:  service.AssignRoleParams{UserID: "not-a-uuid", RoleID: validRoleID},
			wantErr: service.ErrInvalidUserID,
		},
		{
			name:   "user_not_found",
			params: service.AssignRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: func(_ context.Context, _ pgtype.UUID) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantErr: service.ErrUserNotFound,
		},
		{
			name:    "invalid_role_id",
			params:  service.AssignRoleParams{UserID: validUserID, RoleID: "not-a-uuid"},
			getUser: userFound,
			wantErr: service.ErrInvalidRoleID,
		},
		{
			name:   "role_not_found",
			params: service.AssignRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: func(_ context.Context, _ pgtype.UUID) (db.Role, error) {
				return db.Role{}, pgx.ErrNoRows
			},
			wantErr: service.ErrRoleNotFound,
		},
		{
			name:   "role_already_assigned",
			params: service.AssignRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			insertUserRole: func(_ context.Context, _ db.InsertUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, &pgconn.PgError{Code: "23505"}
			},
			wantErr: service.ErrRoleAlreadyAssigned,
		},
		{
			name:   "db_error_on_insert",
			params: service.AssignRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			insertUserRole: func(_ context.Context, _ db.InsertUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:   "success",
			params: service.AssignRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			insertUserRole: func(_ context.Context, _ db.InsertUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, nil
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getUser:        tt.getUser,
				getRole:        tt.getRole,
				insertUserRole: tt.insertUserRole,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.AssignRole(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) ||
					errors.Is(tt.wantErr, service.ErrInvalidRoleID) ||
					errors.Is(tt.wantErr, service.ErrUserNotFound) ||
					errors.Is(tt.wantErr, service.ErrRoleNotFound) ||
					errors.Is(tt.wantErr, service.ErrRoleAlreadyAssigned) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantResult {
				if result.UserID != validUserID {
					t.Errorf("got user_id %q, want %q", result.UserID, validUserID)
				}
				if result.RoleID != validRoleID {
					t.Errorf("got role_id %q, want %q", result.RoleID, validRoleID)
				}
			}
		})
	}
}

func TestAuthService_RemoveRole(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"
	validRoleID := "00000000-0000-0000-0000-000000000010"

	tests := []struct {
		name           string
		params         service.RemoveRoleParams
		getUser        func(ctx context.Context, id pgtype.UUID) (db.User, error)
		getRole        func(ctx context.Context, id pgtype.UUID) (db.Role, error)
		getUserRole    func(ctx context.Context, arg db.GetUserRoleParams) (db.UserRole, error)
		deleteUserRole func(ctx context.Context, arg db.DeleteUserRoleParams) error
		wantErr        error
		wantResult     bool
	}{
		{
			name:    "invalid_user_id",
			params:  service.RemoveRoleParams{UserID: "not-a-uuid", RoleID: validRoleID},
			wantErr: service.ErrInvalidUserID,
		},
		{
			name:   "user_not_found",
			params: service.RemoveRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: func(_ context.Context, _ pgtype.UUID) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantErr: service.ErrUserNotFound,
		},
		{
			name:    "invalid_role_id",
			params:  service.RemoveRoleParams{UserID: validUserID, RoleID: "not-a-uuid"},
			getUser: userFound,
			wantErr: service.ErrInvalidRoleID,
		},
		{
			name:   "role_not_found",
			params: service.RemoveRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: func(_ context.Context, _ pgtype.UUID) (db.Role, error) {
				return db.Role{}, pgx.ErrNoRows
			},
			wantErr: service.ErrRoleNotFound,
		},
		{
			name:   "role_not_assigned",
			params: service.RemoveRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			getUserRole: func(_ context.Context, _ db.GetUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, pgx.ErrNoRows
			},
			wantErr: service.ErrRoleNotAssigned,
		},
		{
			name:   "db_error_on_delete",
			params: service.RemoveRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			getUserRole: func(_ context.Context, _ db.GetUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, nil
			},
			deleteUserRole: func(_ context.Context, _ db.DeleteUserRoleParams) error {
				return errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:   "success",
			params: service.RemoveRoleParams{UserID: validUserID, RoleID: validRoleID},
			getUser: userFound,
			getRole: roleFound,
			getUserRole: func(_ context.Context, _ db.GetUserRoleParams) (db.UserRole, error) {
				return db.UserRole{}, nil
			},
			deleteUserRole: func(_ context.Context, _ db.DeleteUserRoleParams) error {
				return nil
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getUser:        tt.getUser,
				getRole:        tt.getRole,
				getUserRole:    tt.getUserRole,
				deleteUserRole: tt.deleteUserRole,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.RemoveRole(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) ||
					errors.Is(tt.wantErr, service.ErrInvalidRoleID) ||
					errors.Is(tt.wantErr, service.ErrUserNotFound) ||
					errors.Is(tt.wantErr, service.ErrRoleNotFound) ||
					errors.Is(tt.wantErr, service.ErrRoleNotAssigned) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantResult {
				if result.UserID != validUserID {
					t.Errorf("got user_id %q, want %q", result.UserID, validUserID)
				}
				if result.RoleID != validRoleID {
					t.Errorf("got role_id %q, want %q", result.RoleID, validRoleID)
				}
			}
		})
	}
}

func TestAuthService_GetUserRoles(t *testing.T) {
	validUserID := "00000000-0000-0000-0000-000000000001"

	roleID1 := pgtype.UUID{Bytes: [16]byte{0x10}, Valid: true}
	roleID2 := pgtype.UUID{Bytes: [16]byte{0x20}, Valid: true}

	tests := []struct {
		name            string
		userID          string
		getUser         func(ctx context.Context, id pgtype.UUID) (db.User, error)
		getRolesForUser func(ctx context.Context, userID pgtype.UUID) ([]db.Role, error)
		wantErr         error
		wantCount       int
	}{
		{
			name:    "invalid_user_id",
			userID:  "not-a-uuid",
			wantErr: service.ErrInvalidUserID,
		},
		{
			name:   "user_not_found",
			userID: validUserID,
			getUser: func(_ context.Context, _ pgtype.UUID) (db.User, error) {
				return db.User{}, pgx.ErrNoRows
			},
			wantErr: service.ErrUserNotFound,
		},
		{
			name:   "db_error_on_get_user",
			userID: validUserID,
			getUser: func(_ context.Context, _ pgtype.UUID) (db.User, error) {
				return db.User{}, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:    "db_error_on_get_roles",
			userID:  validUserID,
			getUser: userFound,
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return nil, errors.New("db error")
			},
			wantErr: errors.New("db error"),
		},
		{
			name:    "empty_roles",
			userID:  validUserID,
			getUser: userFound,
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return []db.Role{}, nil
			},
			wantCount: 0,
		},
		{
			name:    "success",
			userID:  validUserID,
			getUser: userFound,
			getRolesForUser: func(_ context.Context, _ pgtype.UUID) ([]db.Role, error) {
				return []db.Role{
					{ID: roleID1, Name: "admin"},
					{ID: roleID2, Name: "editor"},
				}, nil
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getUser:         tt.getUser,
				getRolesForUser: tt.getRolesForUser,
			}
			svc := service.NewAuthService(q, testPrivateKey)

			result, err := svc.GetUserRoles(context.Background(), tt.userID)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidUserID) ||
					errors.Is(tt.wantErr, service.ErrUserNotFound) {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("got error %v, want %v", err, tt.wantErr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tt.wantCount {
				t.Errorf("got %d roles, want %d", len(result), tt.wantCount)
			}
			if tt.wantCount == 2 {
				if result[0].RoleName != "admin" {
					t.Errorf("got role_name %q, want %q", result[0].RoleName, "admin")
				}
				if result[1].RoleName != "editor" {
					t.Errorf("got role_name %q, want %q", result[1].RoleName, "editor")
				}
			}
		})
	}
}

package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/service"
	"golang.org/x/crypto/bcrypt"
)

// mockQuerier embeds db.Querier so only the methods under test need to be implemented.
// Any unexpected method call will panic, making test boundaries explicit.
type mockQuerier struct {
	db.Querier
	getUserByAppAndEmail       func(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error)
	createUser                 func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	createSession              func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	createRefreshToken         func(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
	revokeRefreshTokensForSession func(ctx context.Context, sessionID pgtype.UUID) error
	revokeSession              func(ctx context.Context, id pgtype.UUID) (db.Session, error)
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

func TestAuthService_Signup(t *testing.T) {
	validAppID := "00000000-0000-0000-0000-000000000001"
	email := "test@example.com"
	password := "password123"

	var parsedAppID pgtype.UUID
	_ = parsedAppID.Scan(validAppID)

	returnedUser := db.User{
		AppID: parsedAppID,
		Email: email,
	}

	tests := []struct {
		name                string
		params              service.SignupParams
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
			name: "email_already_taken",
			params: service.SignupParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
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
				getUserByAppAndEmail: tt.getUserByAppAndEmail,
				createUser:           tt.createUser,
			}
			svc := service.NewAuthService(q, "test-secret")

			user, err := svc.Signup(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if tt.wantErr == service.ErrInvalidAppID || tt.wantErr == service.ErrEmailTaken {
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
	password := "password123"

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

	tests := []struct {
		name                 string
		params               service.LoginParams
		getUserByAppAndEmail func(ctx context.Context, arg db.GetUserByAppAndEmailParams) (db.User, error)
		createSession        func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
		createRefreshToken   func(ctx context.Context, arg db.CreateRefreshTokenParams) (db.RefreshToken, error)
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
			name: "user_not_found",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
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
				Password: "wrongpassword",
			},
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
			name: "success",
			params: service.LoginParams{
				AppID:    validAppID,
				Email:    email,
				Password: password,
			},
			getUserByAppAndEmail: func(_ context.Context, _ db.GetUserByAppAndEmailParams) (db.User, error) {
				return activeUser, nil
			},
			createSession: func(_ context.Context, _ db.CreateSessionParams) (db.Session, error) {
				return defaultSession, nil
			},
			createRefreshToken: func(_ context.Context, _ db.CreateRefreshTokenParams) (db.RefreshToken, error) {
				return db.RefreshToken{}, nil
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &mockQuerier{
				getUserByAppAndEmail: tt.getUserByAppAndEmail,
				createSession:        tt.createSession,
				createRefreshToken:   tt.createRefreshToken,
			}
			svc := service.NewAuthService(q, "test-secret")

			result, err := svc.Login(context.Background(), tt.params)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.wantErr)
				}
				if errors.Is(tt.wantErr, service.ErrInvalidAppID) || errors.Is(tt.wantErr, service.ErrInvalidCredentials) {
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
			svc := service.NewAuthService(q, "test-secret")

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

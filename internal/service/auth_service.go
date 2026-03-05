package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	queries   db.Querier
	jwtSecret []byte
}

func NewAuthService(queries db.Querier, jwtSecret string) *AuthService {
	return &AuthService{queries: queries, jwtSecret: []byte(jwtSecret)}
}

type SignupParams struct {
	AppID    string
	Email    string
	Password string
}

func (s *AuthService) Signup(ctx context.Context, params SignupParams) (db.User, error) {
	slog.Info("signup attempt", "email", params.Email, "app_id", params.AppID)

	var appID pgtype.UUID
	if err := appID.Scan(params.AppID); err != nil {
		return db.User{}, ErrInvalidAppID
	}

	_, err := s.queries.GetUserByAppAndEmail(ctx, db.GetUserByAppAndEmailParams{
		AppID: appID,
		Email: params.Email,
	})
	if err == nil {
		slog.Warn("signup rejected: email already exists", "email", params.Email, "app_id", params.AppID)
		return db.User{}, ErrEmailTaken
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		slog.Error("signup: failed to check email existence", "email", params.Email, "error", err)
		return db.User{}, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(params.Password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("signup: failed to hash password", "error", err)
		return db.User{}, err
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		AppID:        appID,
		Email:        params.Email,
		PasswordHash: string(hash),
	})
	if err != nil {
		slog.Error("signup: failed to create user", "email", params.Email, "error", err)
		return db.User{}, err
	}

	slog.Info("signup successful", "email", params.Email, "app_id", params.AppID, "user_id", user.ID)
	return user, nil
}

type LoginParams struct {
	AppID      string
	Email      string
	Password   string
	DeviceInfo *string
	IPAddress  *string
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

const (
	accessTokenDuration  = 15 * time.Minute
	sessionDuration      = 24 * time.Hour
	refreshTokenDuration = 30 * 24 * time.Hour
	refreshTokenBytes    = 32
)

func (s *AuthService) Login(ctx context.Context, params LoginParams) (LoginResult, error) {
	slog.Info("login attempt", "email", params.Email, "app_id", params.AppID)

	var appID pgtype.UUID
	if err := appID.Scan(params.AppID); err != nil {
		return LoginResult{}, ErrInvalidAppID
	}

	user, err := s.queries.GetUserByAppAndEmail(ctx, db.GetUserByAppAndEmailParams{
		AppID: appID,
		Email: params.Email,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("login failed: user not found", "email", params.Email)
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		slog.Error("login: failed to fetch user", "email", params.Email, "error", err)
		return LoginResult{}, err
	}

	if user.IsActive != nil && !*user.IsActive {
		slog.Warn("login failed: user inactive", "email", params.Email)
		return LoginResult{}, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(params.Password)); err != nil {
		slog.Warn("login failed: wrong password", "email", params.Email)
		return LoginResult{}, ErrInvalidCredentials
	}

	now := time.Now()

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		UserID:     user.ID,
		DeviceInfo: params.DeviceInfo,
		IpAddress:  params.IPAddress,
		ExpiresAt:  pgtype.Timestamp{Time: now.Add(sessionDuration), Valid: true},
	})
	if err != nil {
		slog.Error("login: failed to create session", "user_id", user.ID, "error", err)
		return LoginResult{}, err
	}

	rawToken, tokenHash, err := generateRefreshToken()
	if err != nil {
		slog.Error("login: failed to generate refresh token", "error", err)
		return LoginResult{}, err
	}

	_, err = s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		SessionID: session.ID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: pgtype.Timestamp{Time: now.Add(refreshTokenDuration), Valid: true},
	})
	if err != nil {
		slog.Error("login: failed to create refresh token", "user_id", user.ID, "error", err)
		return LoginResult{}, err
	}

	userIDBytes := uuidToBytes(user.ID)
	sessionIDBytes := uuidToBytes(session.ID)
	accessToken, err := s.generateAccessToken(hex.EncodeToString(userIDBytes), hex.EncodeToString(sessionIDBytes), now)
	if err != nil {
		slog.Error("login: failed to generate access token", "error", err)
		return LoginResult{}, err
	}

	slog.Info("login successful", "email", params.Email, "session_id", session.ID)
	return LoginResult{
		AccessToken:  accessToken,
		RefreshToken: rawToken,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	slog.Info("logout attempt", "session_id", sessionID)

	var sid pgtype.UUID
	if err := sid.Scan(sessionID); err != nil {
		return ErrInvalidSessionID
	}

	if err := s.queries.RevokeRefreshTokensForSession(ctx, sid); err != nil {
		slog.Error("logout: failed to revoke refresh tokens", "session_id", sessionID, "error", err)
		return err
	}

	if _, err := s.queries.RevokeSession(ctx, sid); err != nil {
		slog.Error("logout: failed to revoke session", "session_id", sessionID, "error", err)
		return err
	}

	slog.Info("logout successful", "session_id", sessionID)
	return nil
}

func (s *AuthService) generateAccessToken(userID, sessionID string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub":        userID,
		"session_id": sessionID,
		"iat":        now.Unix(),
		"exp":        now.Add(accessTokenDuration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func generateRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])
	return raw, hash, nil
}

func uuidToBytes(u pgtype.UUID) []byte {
	return u.Bytes[:]
}

package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	queries    db.Querier
	privateKey *rsa.PrivateKey
}

func NewAuthService(queries db.Querier, privateKey *rsa.PrivateKey) *AuthService {
	return &AuthService{queries: queries, privateKey: privateKey}
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

	if _, err := s.queries.GetApp(ctx, appID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrAppNotFound
		}
		slog.Error("signup: failed to check app existence", "app_id", params.AppID, "error", err)
		return db.User{}, err
	}

	if err := validateEmail(params.Email); err != nil {
		return db.User{}, err
	}

	if err := validatePassword(params.Password); err != nil {
		return db.User{}, err
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

	if _, err := s.queries.GetApp(ctx, appID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LoginResult{}, ErrAppNotFound
		}
		slog.Error("login: failed to check app existence", "app_id", params.AppID, "error", err)
		return LoginResult{}, err
	}

	if err := validateEmail(params.Email); err != nil {
		return LoginResult{}, err
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

	now := time.Now().UTC()

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		UserID:     user.ID,
		DeviceInfo: params.DeviceInfo,
		IpAddress:  params.IPAddress,
		ExpiresAt:  pgtype.Timestamptz{Time: now.Add(sessionDuration), Valid: true},
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
		ExpiresAt: pgtype.Timestamptz{Time: now.Add(refreshTokenDuration), Valid: true},
	})
	if err != nil {
		slog.Error("login: failed to create refresh token", "user_id", user.ID, "error", err)
		return LoginResult{}, err
	}

	roleNames, err := s.getRoleNames(ctx, user.ID)
	if err != nil {
		slog.Error("login: failed to fetch user roles", "user_id", user.ID, "error", err)
		return LoginResult{}, err
	}

	userIDBytes := uuidToBytes(user.ID)
	sessionIDBytes := uuidToBytes(session.ID)
	accessToken, err := s.generateAccessToken(hex.EncodeToString(userIDBytes), hex.EncodeToString(sessionIDBytes), roleNames, now)
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

type RefreshTokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	TokenType    string
}

func (s *AuthService) RefreshToken(ctx context.Context, rawToken string) (RefreshTokenResult, error) {
	slog.Info("token refresh attempt")

	tokenHash := hashToken(rawToken)

	oldToken, err := s.queries.FindRefreshToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("token refresh failed: token not found")
			return RefreshTokenResult{}, ErrTokenNotFound
		}
		slog.Error("token refresh: failed to find token", "error", err)
		return RefreshTokenResult{}, err
	}

	session, err := s.queries.VerifySession(ctx, oldToken.SessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Warn("token refresh failed: session invalid", "session_id", oldToken.SessionID)
			return RefreshTokenResult{}, ErrSessionRevoked
		}
		slog.Error("token refresh: failed to verify session", "error", err)
		return RefreshTokenResult{}, err
	}

	if _, err := s.queries.RevokeRefreshToken(ctx, oldToken.ID); err != nil {
		slog.Error("token refresh: failed to revoke old token", "error", err)
		return RefreshTokenResult{}, err
	}

	now := time.Now().UTC()

	newRaw, newHash, err := generateRefreshToken()
	if err != nil {
		slog.Error("token refresh: failed to generate new token", "error", err)
		return RefreshTokenResult{}, err
	}

	if _, err := s.queries.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		SessionID: session.ID,
		UserID:    session.UserID,
		TokenHash: newHash,
		ExpiresAt: pgtype.Timestamptz{Time: now.Add(refreshTokenDuration), Valid: true},
	}); err != nil {
		slog.Error("token refresh: failed to create new token", "error", err)
		return RefreshTokenResult{}, err
	}

	roleNames, err := s.getRoleNames(ctx, session.UserID)
	if err != nil {
		slog.Error("token refresh: failed to fetch user roles", "user_id", session.UserID, "error", err)
		return RefreshTokenResult{}, err
	}

	userIDBytes := uuidToBytes(session.UserID)
	sessionIDBytes := uuidToBytes(session.ID)
	accessToken, err := s.generateAccessToken(hex.EncodeToString(userIDBytes), hex.EncodeToString(sessionIDBytes), roleNames, now)
	if err != nil {
		slog.Error("token refresh: failed to generate access token", "error", err)
		return RefreshTokenResult{}, err
	}

	slog.Info("token refresh successful", "session_id", session.ID)
	return RefreshTokenResult{
		AccessToken:  accessToken,
		RefreshToken: newRaw,
		ExpiresIn:    int(accessTokenDuration.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	slog.Info("logout-all attempt", "user_id", userID)

	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return ErrInvalidUserID
	}

	if err := s.queries.RevokeAllSessionsForUser(ctx, uid); err != nil {
		slog.Error("logout-all: failed to revoke sessions", "user_id", userID, "error", err)
		return err
	}

	if err := s.queries.RevokeAllRefreshTokensForUser(ctx, uid); err != nil {
		slog.Error("logout-all: failed to revoke refresh tokens", "user_id", userID, "error", err)
		return err
	}

	slog.Info("logout-all successful", "user_id", userID)
	return nil
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

type ChangePasswordParams struct {
	UserID          string
	CurrentPassword string
	NewPassword     string
}

func (s *AuthService) ChangePassword(ctx context.Context, params ChangePasswordParams) error {
	slog.Info("change password attempt", "user_id", params.UserID)

	var uid pgtype.UUID
	if err := uid.Scan(params.UserID); err != nil {
		return ErrInvalidUserID
	}

	currentHash, err := s.queries.GetUserPasswordHash(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		slog.Error("change password: failed to get password hash", "user_id", params.UserID, "error", err)
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(params.CurrentPassword)); err != nil {
		slog.Warn("change password: wrong current password", "user_id", params.UserID)
		return ErrInvalidCredentials
	}

	if err := validatePassword(params.NewPassword); err != nil {
		return err
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(params.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("change password: failed to hash new password", "error", err)
		return err
	}

	if _, err := s.queries.UpdateUserPasswordHash(ctx, db.UpdateUserPasswordHashParams{
		ID:           uid,
		PasswordHash: string(newHash),
	}); err != nil {
		slog.Error("change password: failed to update password", "user_id", params.UserID, "error", err)
		return err
	}

	if err := s.queries.RevokeAllSessionsForUser(ctx, uid); err != nil {
		slog.Error("change password: failed to revoke sessions", "user_id", params.UserID, "error", err)
		return err
	}

	if err := s.queries.RevokeAllRefreshTokensForUser(ctx, uid); err != nil {
		slog.Error("change password: failed to revoke refresh tokens", "user_id", params.UserID, "error", err)
		return err
	}

	slog.Info("change password successful", "user_id", params.UserID)
	return nil
}

type SessionInfo struct {
	SessionID  string
	DeviceInfo *string
	IpAddress  *string
	CreatedAt  pgtype.Timestamptz
	ExpiresAt  pgtype.Timestamptz
	Revoked    *bool
	Current    bool
}

func (s *AuthService) GetSessions(ctx context.Context, userID, currentSessionID string) ([]SessionInfo, error) {
	slog.Info("get sessions attempt", "user_id", userID)

	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, ErrInvalidUserID
	}

	sessions, err := s.queries.GetSessionsForUser(ctx, uid)
	if err != nil {
		slog.Error("get sessions: failed to fetch sessions", "user_id", userID, "error", err)
		return nil, err
	}

	result := make([]SessionInfo, 0, len(sessions))
	for _, sess := range sessions {
		sidBytes := uuidToBytes(sess.ID)
		sidHex := hex.EncodeToString(sidBytes)
		result = append(result, SessionInfo{
			SessionID:  formatUUID(sidHex),
			DeviceInfo: sess.DeviceInfo,
			IpAddress:  sess.IpAddress,
			CreatedAt:  sess.CreatedAt,
			ExpiresAt:  sess.ExpiresAt,
			Revoked:    sess.Revoked,
			Current:    sidHex == currentSessionID,
		})
	}

	slog.Info("get sessions successful", "user_id", userID, "count", len(result))
	return result, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, userID, sessionID string) error {
	slog.Info("revoke session attempt", "user_id", userID, "session_id", sessionID)

	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return ErrInvalidUserID
	}

	var sid pgtype.UUID
	if err := sid.Scan(sessionID); err != nil {
		return ErrInvalidSessionID
	}

	_, err := s.queries.VerifySessionBelongsToUser(ctx, db.VerifySessionBelongsToUserParams{
		ID:     sid,
		UserID: uid,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Check if session exists at all to distinguish 404 vs 403
			_, getErr := s.queries.VerifySession(ctx, sid)
			if errors.Is(getErr, pgx.ErrNoRows) {
				return ErrSessionNotFound
			}
			return ErrSessionUserMismatch
		}
		slog.Error("revoke session: failed to verify session ownership", "session_id", sessionID, "error", err)
		return err
	}

	if err := s.queries.RevokeRefreshTokensForSession(ctx, sid); err != nil {
		slog.Error("revoke session: failed to revoke refresh tokens", "session_id", sessionID, "error", err)
		return err
	}

	if _, err := s.queries.RevokeSession(ctx, sid); err != nil {
		slog.Error("revoke session: failed to revoke session", "session_id", sessionID, "error", err)
		return err
	}

	slog.Info("revoke session successful", "session_id", sessionID)
	return nil
}

type AssignRoleParams struct {
	UserID string
	RoleID string
}

type AssignRoleResult struct {
	UserID string
	RoleID string
}

func (s *AuthService) AssignRole(ctx context.Context, params AssignRoleParams) (AssignRoleResult, error) {
	slog.Info("assign role attempt", "user_id", params.UserID, "role_id", params.RoleID)

	var uid pgtype.UUID
	if err := uid.Scan(params.UserID); err != nil {
		return AssignRoleResult{}, ErrInvalidUserID
	}

	if _, err := s.queries.GetUser(ctx, uid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AssignRoleResult{}, ErrUserNotFound
		}
		slog.Error("assign role: failed to check user existence", "user_id", params.UserID, "error", err)
		return AssignRoleResult{}, err
	}

	var rid pgtype.UUID
	if err := rid.Scan(params.RoleID); err != nil {
		return AssignRoleResult{}, ErrInvalidRoleID
	}

	if _, err := s.queries.GetRole(ctx, rid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AssignRoleResult{}, ErrRoleNotFound
		}
		slog.Error("assign role: failed to check role existence", "role_id", params.RoleID, "error", err)
		return AssignRoleResult{}, err
	}

	_, err := s.queries.InsertUserRole(ctx, db.InsertUserRoleParams{
		UserID: uid,
		RoleID: rid,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return AssignRoleResult{}, ErrRoleAlreadyAssigned
		}
		slog.Error("assign role: failed to insert user role", "user_id", params.UserID, "role_id", params.RoleID, "error", err)
		return AssignRoleResult{}, err
	}

	slog.Info("assign role successful", "user_id", params.UserID, "role_id", params.RoleID)
	return AssignRoleResult(params), nil
}

type RemoveRoleParams struct {
	UserID string
	RoleID string
}

type RemoveRoleResult struct {
	UserID string
	RoleID string
}

func (s *AuthService) RemoveRole(ctx context.Context, params RemoveRoleParams) (RemoveRoleResult, error) {
	slog.Info("remove role attempt", "user_id", params.UserID, "role_id", params.RoleID)

	var uid pgtype.UUID
	if err := uid.Scan(params.UserID); err != nil {
		return RemoveRoleResult{}, ErrInvalidUserID
	}

	if _, err := s.queries.GetUser(ctx, uid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RemoveRoleResult{}, ErrUserNotFound
		}
		slog.Error("remove role: failed to check user existence", "user_id", params.UserID, "error", err)
		return RemoveRoleResult{}, err
	}

	var rid pgtype.UUID
	if err := rid.Scan(params.RoleID); err != nil {
		return RemoveRoleResult{}, ErrInvalidRoleID
	}

	if _, err := s.queries.GetRole(ctx, rid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RemoveRoleResult{}, ErrRoleNotFound
		}
		slog.Error("remove role: failed to check role existence", "role_id", params.RoleID, "error", err)
		return RemoveRoleResult{}, err
	}

	if _, err := s.queries.GetUserRole(ctx, db.GetUserRoleParams{
		UserID: uid,
		RoleID: rid,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RemoveRoleResult{}, ErrRoleNotAssigned
		}
		slog.Error("remove role: failed to check role assignment", "user_id", params.UserID, "role_id", params.RoleID, "error", err)
		return RemoveRoleResult{}, err
	}

	if err := s.queries.DeleteUserRole(ctx, db.DeleteUserRoleParams{
		UserID: uid,
		RoleID: rid,
	}); err != nil {
		slog.Error("remove role: failed to delete user role", "user_id", params.UserID, "role_id", params.RoleID, "error", err)
		return RemoveRoleResult{}, err
	}

	slog.Info("remove role successful", "user_id", params.UserID, "role_id", params.RoleID)
	return RemoveRoleResult(params), nil
}

type RoleInfo struct {
	RoleID   string
	RoleName string
}

func (s *AuthService) GetUserRoles(ctx context.Context, userID string) ([]RoleInfo, error) {
	slog.Info("get user roles attempt", "user_id", userID)

	var uid pgtype.UUID
	if err := uid.Scan(userID); err != nil {
		return nil, ErrInvalidUserID
	}

	if _, err := s.queries.GetUser(ctx, uid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		slog.Error("get user roles: failed to check user existence", "user_id", userID, "error", err)
		return nil, err
	}

	roles, err := s.queries.GetRolesForUser(ctx, uid)
	if err != nil {
		slog.Error("get user roles: failed to fetch roles", "user_id", userID, "error", err)
		return nil, err
	}

	result := make([]RoleInfo, 0, len(roles))
	for _, r := range roles {
		ridBytes := uuidToBytes(r.ID)
		result = append(result, RoleInfo{
			RoleID:   formatUUID(hex.EncodeToString(ridBytes)),
			RoleName: r.Name,
		})
	}

	slog.Info("get user roles successful", "user_id", userID, "count", len(result))
	return result, nil
}

func formatUUID(hex string) string {
	if len(hex) != 32 {
		return hex
	}
	return hex[0:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:32]
}

func (s *AuthService) generateAccessToken(userID, sessionID string, roles []string, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub":        userID,
		"session_id": sessionID,
		"roles":      roles,
		"iat":        now.Unix(),
		"exp":        now.Add(accessTokenDuration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

func (s *AuthService) getRoleNames(ctx context.Context, userID pgtype.UUID) ([]string, error) {
	roles, err := s.queries.GetRolesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	return names, nil
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}
	return nil
}

func validatePassword(password string) error {
	if strings.TrimSpace(password) != password {
		return ErrPasswordLeadingTrailingSpaces
	}

	if len(password) < 8 || len(password) > 128 {
		return ErrPasswordLength
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrPasswordComplexity
	}

	return nil
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

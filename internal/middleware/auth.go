package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	ContextKeyUserID    contextKey = "user_id"
	ContextKeySessionID contextKey = "session_id"
)

func respondUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func AuthMiddleware(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondUnauthorized(w, "missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				respondUnauthorized(w, "invalid authorization header")
				return
			}

			token, err := jwt.Parse(parts[1], func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return publicKey, nil
			})
			if err != nil || !token.Valid {
				respondUnauthorized(w, "invalid or expired token")
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				respondUnauthorized(w, "invalid token claims")
				return
			}

			userID, _ := claims["sub"].(string)
			sessionID, _ := claims["session_id"].(string)
			if userID == "" || sessionID == "" {
				respondUnauthorized(w, "invalid token claims")
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyUserID, userID)
			ctx = context.WithValue(ctx, ContextKeySessionID, sessionID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyUserID).(string)
	return v
}

func SessionIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeySessionID).(string)
	return v
}

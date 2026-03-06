package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/kaitou-1412/auth-service/internal/app"
	"github.com/kaitou-1412/auth-service/internal/db"
	sqlcdb "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/keyutil"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	port := os.Getenv("PORT")
	if port == "" {
		slog.Error("PORT is not set in environment variables")
		os.Exit(1)
	}

	privateKeyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		privateKeyPath = "/keys/private.pem"
	}
	publicKeyPath := os.Getenv("JWT_PUBLIC_KEY_PATH")
	if publicKeyPath == "" {
		publicKeyPath = "/keys/public.pem"
	}

	privateKey, err := keyutil.LoadPrivateKey(privateKeyPath)
	if err != nil {
		slog.Error("failed to load private key", "error", err)
		os.Exit(1)
	}

	publicKey, err := keyutil.LoadPublicKey(publicKeyPath)
	if err != nil {
		slog.Error("failed to load public key", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()

	pool, err := db.NewPool(ctx)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	queries := sqlcdb.New(pool)
	r := app.NewRouter(queries, privateKey, publicKey)

	srv := &http.Server{
		Handler: r,
		Addr:    ":" + port,
	}

	slog.Info("starting server", "port", port)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

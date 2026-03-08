package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	r, cleanup := app.NewRouter(queries, privateKey, publicKey)
	defer cleanup()

	srv := &http.Server{
		Handler: r,
		Addr:    ":" + port,
	}

	// Start server in a goroutine
	go func() {
		slog.Info("starting server", "port", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("shutting down server", "signal", sig.String())

	// Give in-flight requests 10 seconds to complete
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}

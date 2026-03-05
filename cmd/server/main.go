package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"

	"github.com/kaitou-1412/auth-service/internal/app"
	"github.com/kaitou-1412/auth-service/internal/db"
	sqlcdb "github.com/kaitou-1412/auth-service/internal/db/sqlc"
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

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		slog.Error("JWT_SECRET is not set in environment variables")
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
	r := app.NewRouter(queries, jwtSecret)

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

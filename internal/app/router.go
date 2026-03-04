package app

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/kaitou-1412/auth-service/internal/handler"
)

func NewRouter() *chi.Mux {
	r := chi.NewRouter()

	// Add request logging middleware
	r.Use(handler.LoggingMiddleware)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	v1Router := chi.NewRouter()
	v1Router.Get("/health", handler.HandlerReadiness)
	v1Router.Get("/err", handler.HandlerErr)

	r.Mount("/v1", v1Router)

	return r
}

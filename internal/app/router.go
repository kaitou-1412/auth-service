package app

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/handler"
	"github.com/kaitou-1412/auth-service/internal/middleware"
	"github.com/kaitou-1412/auth-service/internal/service"
)

func NewRouter(queries *db.Queries, jwtSecret string) *chi.Mux {
	r := chi.NewRouter()

	// Add request logging middleware
	r.Use(middleware.LoggingMiddleware)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	swaggerHandler := handler.NewSwaggerHandler()
	r.Get("/swagger", swaggerHandler.UI)
	r.Get("/api/openapi.yaml", swaggerHandler.Spec)

	healthHandler := handler.NewHealthHandler()
	authSvc := service.NewAuthService(queries, jwtSecret)
	authHandler := handler.NewAuthHandler(authSvc)

	v1Router := chi.NewRouter()
	v1Router.Get("/health", healthHandler.Health)
	v1Router.Post("/auth/signup", authHandler.Signup)
	v1Router.Post("/auth/login", authHandler.Login)

	// Authenticated routes
	v1Router.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware([]byte(jwtSecret)))
		r.Post("/auth/logout", authHandler.Logout)
	})

	r.Mount("/v1", v1Router)

	return r
}

package app

import (
	"crypto/rsa"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	db "github.com/kaitou-1412/auth-service/internal/db/sqlc"
	"github.com/kaitou-1412/auth-service/internal/handler"
	"github.com/kaitou-1412/auth-service/internal/middleware"
	"github.com/kaitou-1412/auth-service/internal/service"
	"golang.org/x/time/rate"
)

// NewRouter creates the chi router and returns it along with a cleanup function
// that stops rate limiter goroutines. Call cleanup during graceful shutdown.
func NewRouter(queries *db.Queries, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (*chi.Mux, func()) {
	r := chi.NewRouter()

	// Rate limiters
	strictRL := middleware.NewIPRateLimiter(rate.Every(12*time.Second), 5)   // 5 req/min
	moderateRL := middleware.NewIPRateLimiter(rate.Every(3*time.Second), 10) // 20 req/min
	standardRL := middleware.NewIPRateLimiter(rate.Limit(1), 20)            // 60 req/min

	stopStrict := strictRL.StartCleanup(3*time.Minute, 10*time.Minute)
	stopModerate := moderateRL.StartCleanup(3*time.Minute, 10*time.Minute)
	stopStandard := standardRL.StartCleanup(3*time.Minute, 10*time.Minute)

	cleanup := func() {
		stopStrict()
		stopModerate()
		stopStandard()
	}

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
	authSvc := service.NewAuthService(queries, privateKey)
	authHandler := handler.NewAuthHandler(authSvc)

	v1Router := chi.NewRouter()

	// No rate limiting
	v1Router.Get("/health", healthHandler.Health)

	// Strict rate limiting: 5 req/min (brute-force targets)
	v1Router.Group(func(r chi.Router) {
		r.Use(middleware.RateLimitByIP(strictRL))
		r.Post("/auth/signup", authHandler.Signup)
		r.Post("/auth/login", authHandler.Login)
	})

	// Moderate rate limiting: 20 req/min
	v1Router.Group(func(r chi.Router) {
		r.Use(middleware.RateLimitByIP(moderateRL))
		r.Post("/auth/token/refresh", authHandler.RefreshToken)
	})

	// Authenticated routes
	v1Router.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(publicKey))

		// Strict rate limiting for password change (brute-force target)
		r.Group(func(r chi.Router) {
			r.Use(middleware.RateLimitByIP(strictRL))
			r.Post("/auth/password/change", authHandler.ChangePassword)
		})

		// Standard rate limiting: 60 req/min
		r.Group(func(r chi.Router) {
			r.Use(middleware.RateLimitByIP(standardRL))
			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/logout-all", authHandler.LogoutAll)
			r.Get("/auth/sessions", authHandler.GetSessions)
			r.Delete("/auth/sessions/{session_id}", authHandler.RevokeSession)
			r.Post("/auth/users/{user_id}/roles", authHandler.AssignRole)
			r.Delete("/auth/users/{user_id}/roles/{role_id}", authHandler.RemoveRole)
			r.Get("/auth/users/{user_id}/roles", authHandler.GetUserRoles)
		})
	})

	r.Mount("/v1", v1Router)

	return r, cleanup
}

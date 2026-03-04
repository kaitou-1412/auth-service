package handler

import (
	"log"
	"net/http"
	"time"
)

// LoggingMiddleware logs all incoming HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Log the request
		log.Printf("[%s] %s %s - RemoteAddr: %s, UserAgent: %s",
			r.Method,
			r.URL.Path,
			r.Proto,
			r.RemoteAddr,
			r.UserAgent(),
		)

		// Call the next handler
		next.ServeHTTP(w, r)

		// Log the duration
		duration := time.Since(start)
		log.Printf("[%s] %s completed in %v",
			r.Method,
			r.URL.Path,
			duration,
		)
	})
}

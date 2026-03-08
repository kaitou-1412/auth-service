package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPRateLimiter struct {
	rate     rate.Limit
	burst    int
	limiters sync.Map
}

func NewIPRateLimiter(r rate.Limit, burst int) *IPRateLimiter {
	return &IPRateLimiter{rate: r, burst: burst}
}

func (rl *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	if v, ok := rl.limiters.Load(ip); ok {
		entry := v.(*limiterEntry)
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters.Store(ip, &limiterEntry{limiter: limiter, lastSeen: time.Now()})
	return limiter
}

func (rl *IPRateLimiter) StartCleanup(interval, maxAge time.Duration) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				rl.limiters.Range(func(key, value any) bool {
					entry := value.(*limiterEntry)
					if now.Sub(entry.lastSeen) > maxAge {
						rl.limiters.Delete(key)
					}
					return true
				})
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	return func() { close(done) }
}

func RateLimitByIP(rl *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			if !rl.GetLimiter(ip).Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

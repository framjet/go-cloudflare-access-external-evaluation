package api

import (
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
	"net/http"
	"time"
)

var limiter *rate.Limiter

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SetupRateLimit sets up rate limiting for the API
func SetupRateLimit(perSecond int, router *mux.Router) {
	limiter = rate.NewLimiter(rate.Every(time.Second), perSecond)

	router.Use(rateLimitMiddleware)
}

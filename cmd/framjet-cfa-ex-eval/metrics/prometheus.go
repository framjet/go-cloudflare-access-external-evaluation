package metrics

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"time"
)

// Define metrics
var (
	// Counter for total requests
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests by path and method",
		},
		[]string{"path", "method", "status"},
	)

	// Histogram for request duration
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests",
			Buckets: prometheus.DefBuckets, // Default buckets: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
		},
		[]string{"path", "method"},
	)

	// ExpressionCacheSize Gauge for cache size
	ExpressionCacheSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "expression_cache_size",
			Help: "Current number of cached expressions",
		},
	)

	// CacheOperationsTotal Counter for cache operations
	CacheOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_operations_total",
			Help: "Total number of cache operations",
		},
		[]string{"operation", "status"}, // operation: hit/miss, status: success/error
	)

	// ExpressionEvalDuration Histogram for expression evaluation time
	ExpressionEvalDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "expression_eval_duration_seconds",
			Help:    "Time taken to evaluate expressions",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"status"}, // success/error
	)
)

// Middleware to record HTTP metrics
func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create response writer wrapper to capture status code
		wrapped := newResponseWriter(w)

		// Call the next handler
		next.ServeHTTP(wrapped, r)

		// Record metrics
		duration := time.Since(start).Seconds()

		httpRequestsTotal.WithLabelValues(
			r.URL.Path,
			r.Method,
			fmt.Sprintf("%d", wrapped.statusCode),
		).Inc()

		httpRequestDuration.WithLabelValues(
			r.URL.Path,
			r.Method,
		).Observe(duration)
	})
}

// ResponseWriter wrapper to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// SetupMetrics Setup function to add metrics endpoint
func SetupMetrics(router *mux.Router) {
	// Add metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	// Wrap all other handlers with prometheus middleware
	router.Use(prometheusMiddleware)
}

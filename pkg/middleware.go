package pkg

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"
)

const (
	MaxFileSize       = 100 * 1024 * 1024 // 100MB
	MaxRequestSize    = 110 * 1024 * 1024 // 110MB to account for multipart form data
	RateLimitRequests = 100               // requests per minute
	// Time to keep IP rate limiters in memory
	RateLimitWindow = 1 * time.Hour
)

var (
	AllowedFileExtensions = []string{
		".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".jpg", ".jpeg", ".png", ".gif", ".zip", ".csv",
	}
	DisallowedPaths = []string{
		"..", "//", "\\", "%2e", "%2f",
	}
)

// ipRateLimiter stores rate limiters per IP address
type ipRateLimiter struct {
	sync.RWMutex
	limiters  map[string]*rateLimiterEntry
	done      chan struct{}
	closeOnce sync.Once
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newIPRateLimiter creates a new rate limiter that tracks per-IP limits
func newIPRateLimiter() *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		done:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// cleanup removes old IP entries periodically
func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(RateLimitWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.Lock()
			for ip, entry := range rl.limiters {
				if time.Since(entry.lastSeen) > RateLimitWindow {
					delete(rl.limiters, ip)
				}
			}
			rl.Unlock()
		case <-rl.done:
			return
		}
	}
}

// Shutdown gracefully stops the rate limiter cleanup goroutine
func (rl *ipRateLimiter) Shutdown() {
	rl.closeOnce.Do(func() {
		close(rl.done)
	})
}

// getLimiter returns the rate limiter for the provided IP address
func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.Lock()
	defer rl.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		limiter := rate.NewLimiter(rate.Every(time.Minute/RateLimitRequests), RateLimitRequests)
		rl.limiters[ip] = &rateLimiterEntry{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	entry.lastSeen = time.Now()
	return entry.limiter
}

// SecurityHeaders adds security-related HTTP headers to the response
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Server", "WebDAV")

		next.ServeHTTP(w, r)
	})
}

// RequestSizeLimiter limits the size of incoming requests
func RequestSizeLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxRequestSize {
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestSize)
		next.ServeHTTP(w, r)
	})
}

var ipLimiter = newIPRateLimiter()

// ShutdownRateLimiter gracefully shuts down the rate limiter
func ShutdownRateLimiter() {
	ipLimiter.Shutdown()
}

// RateLimiter implements a per-IP rate limiting middleware
func RateLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// Use the first IP in X-Forwarded-For header
			ip = strings.Split(forwardedFor, ",")[0]
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			ip = realIP
		}

		limiter := ipLimiter.getLimiter(strings.TrimSpace(ip))
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ValidateFilePath checks if the file path is safe and allowed
func ValidateFilePath(path string) error {
	// Check for disallowed path patterns
	for _, pattern := range DisallowedPaths {
		if strings.Contains(path, pattern) {
			return fmt.Errorf("invalid path pattern detected")
		}
	}

	// Validate file extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext == "" {
		return fmt.Errorf("file must have an extension")
	}

	allowed := false
	for _, allowedExt := range AllowedFileExtensions {
		if ext == allowedExt {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("file extension not allowed")
	}

	return nil
}

// RequestLogger logs all incoming requests
func RequestLogger(next http.Handler) http.Handler {
	return middleware.Logger(next)
}

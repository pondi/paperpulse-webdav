package logging

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// HTTP header constants for request tracing
const (
	RequestIDHeader = "X-Request-ID"
	TraceIDHeader   = "X-Trace-ID"
)

// responseWriter wraps http.ResponseWriter to capture the status code
// and implement additional interfaces commonly expected by HTTP middleware.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

// WriteHeader captures the status code and passes it to the wrapped ResponseWriter
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the number of bytes written
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// Flush implements http.Flusher if supported by the underlying ResponseWriter
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker if supported by the underlying ResponseWriter
func (rw *responseWriter) Hijack() (interface{}, interface{}, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// ensureTraceID ensures that a trace ID exists in the request headers.
// If no trace ID is present, it generates a new one.
func ensureTraceID(r *http.Request) string {
	traceID := r.Header.Get(TraceIDHeader)
	if traceID == "" {
		traceID = uuid.New().String()
		r.Header.Set(TraceIDHeader, traceID)
	}
	return traceID
}

// RequestLoggerMiddleware creates middleware for logging HTTP requests.
// It logs request details, duration, and response status.
// It also ensures trace IDs are present and propagated.
func RequestLoggerMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Ensure trace ID exists and propagate it
			traceID := ensureTraceID(r)
			w.Header().Set(TraceIDHeader, traceID)

			// Create a response wrapper to capture status and bytes written
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK, // Default to 200 OK
			}

			// Process the request
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Prepare log fields
			fields := map[string]any{
				"method":        r.Method,
				"path":          r.URL.Path,
				"status":        rw.statusCode,
				"duration_ms":   duration.Milliseconds(),
				"bytes_written": rw.bytesWritten,
				"user_agent":    r.UserAgent(),
				"remote_addr":   r.RemoteAddr,
				"request_id":    r.Header.Get(RequestIDHeader),
				"trace_id":      traceID,
				"host":          r.Host,
				"protocol":      r.Proto,
			}

			// Add query parameters if present
			if r.URL.RawQuery != "" {
				fields["query"] = r.URL.RawQuery
			}

			// Add content length if present
			if r.ContentLength > 0 {
				fields["content_length"] = r.ContentLength
			}

			// Add referer if present
			if referer := r.Referer(); referer != "" {
				fields["referer"] = referer
			}

			// Log at appropriate level based on status code
			switch {
			case rw.statusCode >= 500:
				logger.Error("Server error", fields)
			case rw.statusCode >= 400:
				logger.Warn("Client error", fields)
			case rw.statusCode >= 300:
				logger.Info("Redirection", fields)
			default:
				logger.Info("Request completed", fields)
			}
		})
	}
}

// AuditLogger handles logging of security-related events
type AuditLogger struct {
	logger *Logger
}

// NewAuditLogger creates a new audit logger for security event tracking
func NewAuditLogger(logger *Logger) *AuditLogger {
	return &AuditLogger{logger: logger}
}

// LogAuthAttempt logs an authentication attempt with detailed context
func (a *AuditLogger) LogAuthAttempt(success bool, username string, r *http.Request) {
	traceID := ensureTraceID(r)
	fields := map[string]any{
		"success":     success,
		"username":    username,
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
		"request_id":  r.Header.Get(RequestIDHeader),
		"trace_id":    traceID,
		"host":        r.Host,
		"path":        r.URL.Path,
		"method":      r.Method,
	}

	if success {
		a.logger.Info("Authentication successful", fields)
	} else if username == "" {
		// Initial auth challenge (no credentials provided)
		a.logger.Info("Authentication challenge", fields)
	} else {
		// Failed authentication attempt with credentials
		a.logger.Warn("Authentication failed", fields)
	}
}

// LogUpload logs a file upload event with detailed context
func (a *AuditLogger) LogUpload(success bool, filename string, size int64, r *http.Request) {
	traceID := ensureTraceID(r)
	fields := map[string]any{
		"success":     success,
		"filename":    filename,
		"size_bytes":  size,
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
		"request_id":  r.Header.Get(RequestIDHeader),
		"trace_id":    traceID,
		"host":        r.Host,
		"path":        r.URL.Path,
		"method":      r.Method,
	}

	if success {
		a.logger.Info("File upload successful", fields)
	} else {
		a.logger.Warn("File upload failed", fields)
	}
}

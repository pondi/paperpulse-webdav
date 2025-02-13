package pkg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Common errors
var (
	ErrMissingEnvVar = errors.New("required environment variable not set")
)

// Server configuration constants
const (
	DefaultPort         = "80"
	DefaultAddr         = ":" + DefaultPort
	DefaultReadTimeout  = 30 * time.Second
	DefaultWriteTimeout = 30 * time.Second
	DefaultIdleTimeout  = 120 * time.Second
	ShutdownTimeout     = 30 * time.Second
)

// RequiredEnvVars lists the environment variables that must be set
var RequiredEnvVars = []string{
	"S3_BUCKET",
}

// getRequiredEnvVars returns the list of required environment variables based on auth mode
func getRequiredEnvVars() []string {
	vars := RequiredEnvVars
	if strings.ToLower(os.Getenv("API_AUTH")) == "true" {
		vars = append(vars, "AUTH_API_URL")
	} else {
		vars = append(vars, "LOCAL_AUTH_USERNAME", "LOCAL_AUTH_PASSWORD")
	}
	return vars
}

// Server represents the WebDAV server configuration
type Server struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	Handler      http.Handler
}

// NewServer creates a new WebDAV server with default configuration.
// It loads environment variables and initializes all required components.
func NewServer() (*Server, error) {
	// Validate required environment variables
	for _, envVar := range getRequiredEnvVars() {
		if os.Getenv(envVar) == "" {
			return nil, fmt.Errorf("%w: %s", ErrMissingEnvVar, envVar)
		}
	}

	// Initialize components
	s3Client, err := initS3Client()
	if err != nil {
		return nil, err
	}

	return newServerWithS3Client(s3Client)
}

// newServerWithS3Client creates a new server with the provided S3 client.
// This is primarily used for testing.
func newServerWithS3Client(s3Client S3Interface) (*Server, error) {
	if s3Client == nil {
		return nil, fmt.Errorf("s3 client cannot be nil")
	}

	// Create WebDAV handler with middleware chain
	handler := buildHandlerChain(NewAuthenticator(), s3Client)

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}
	addr := ":" + port

	return &Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
		IdleTimeout:  DefaultIdleTimeout,
	}, nil
}

// initS3Client initializes the S3 client with error handling
func initS3Client() (S3Interface, error) {
	s3Client, err := NewS3Client(context.Background(), os.Getenv("S3_BUCKET"))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize S3 client: %w", err)
	}
	return s3Client, nil
}

// buildHandlerChain creates the middleware chain for the WebDAV handler
func buildHandlerChain(authenticator AuthenticatorInterface, s3Client S3Interface) http.Handler {
	webdavHandler := NewWebDAVHandler(authenticator, s3Client)

	return SecurityHeaders(
		RequestLogger(
			RateLimiter(
				RequestSizeLimiter(
					webdavHandler,
				),
			),
		),
	)
}

// ListenAndServe starts the WebDAV server with graceful shutdown support
func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:         s.Addr,
		Handler:      s.Handler,
		ReadTimeout:  s.ReadTimeout,
		WriteTimeout: s.WriteTimeout,
		IdleTimeout:  s.IdleTimeout,
	}

	// Channel for server errors
	serverError := make(chan error, 1)

	// Channel for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("Starting WebDAV server on %s", server.Addr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			serverError <- fmt.Errorf("server error: %w", err)
		}
	}()

	// Wait for shutdown signal
	var err error
	select {
	case err = <-serverError:
		log.Printf("Server error: %v", err)
	case <-ctx.Done():
		log.Println("Context cancelled")
	case sig := <-stop:
		log.Printf("Received signal: %v", sig)
	}

	// Start graceful shutdown
	log.Println("Starting graceful shutdown...")
	return s.shutdown(server)
}

// shutdown handles graceful server shutdown
func (s *Server) shutdown(server *http.Server) error {
	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	// Shutdown rate limiter
	ShutdownRateLimiter()

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	log.Println("Server shutdown completed")
	return nil
}

// ServeHTTP implements the http.Handler interface for direct usage in other HTTP servers
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Handler.ServeHTTP(w, r)
}

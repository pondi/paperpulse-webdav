// Package pkg implements the core WebDAV server functionality.
package pkg

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pondi/pulsedav/pkg/logging"
)

// Common errors
var (
	// ErrMissingEnvVar indicates a required environment variable is not set
	ErrMissingEnvVar = errors.New("required environment variable not set")
)

// Server configuration constants
const (
	// DefaultPort is the default server port if none is specified
	DefaultPort = "80"

	// DefaultReadTimeout is the maximum duration for reading the entire request
	DefaultReadTimeout = 30 * time.Second

	// DefaultWriteTimeout is the maximum duration before timing out writes of the response
	DefaultWriteTimeout = 30 * time.Second

	// DefaultIdleTimeout is the maximum amount of time to wait for the next request
	DefaultIdleTimeout = 120 * time.Second

	// ShutdownTimeout is the maximum duration to wait for server shutdown
	ShutdownTimeout = 30 * time.Second
)

// ServerConfig holds the complete server configuration including S3 and auth settings
type ServerConfig struct {
	// Port specifies the server listening port (e.g., "80")
	Port string

	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the next request
	IdleTimeout time.Duration

	// S3Config holds the S3 storage configuration
	S3Config *S3Config

	// AuthConfig holds the authentication configuration
	AuthConfig *AuthConfig
}

// DefaultServerConfig returns a ServerConfig initialized with default values.
// Note: S3Config and AuthConfig must be set separately as they have no defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:         DefaultPort,
		ReadTimeout:  DefaultReadTimeout,
		WriteTimeout: DefaultWriteTimeout,
		IdleTimeout:  DefaultIdleTimeout,
	}
}

// Server represents a configured WebDAV server instance.
// It encapsulates all the components needed to handle WebDAV requests.
type Server struct {
	config       *ServerConfig        // Server configuration
	handler      http.Handler         // Main request handler chain
	logger       *logging.Logger      // Application logger
	auditLogger  *logging.AuditLogger // Audit event logger
	shutdownFunc func() error         // Custom shutdown logic
}

// InitServer initializes a new server instance with the given configuration.
// It sets up all required components:
// - S3 client for file storage
// - Logging system with console and S3 output
// - Authentication (API or local)
// - WebDAV request handler with middleware chain
// If config is nil, default configuration will be used.
func InitServer(config *ServerConfig) (*Server, error) {
	if config == nil {
		config = DefaultServerConfig()
	}

	// Initialize S3 client
	s3Client, err := createS3Client(context.Background(), config.S3Config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize S3 client: %w", err)
	}

	// Initialize logger
	logger, err := initLogger(s3Client)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Create audit logger
	auditLogger := logging.NewAuditLogger(logger)

	// Initialize authenticator based on config
	var authenticator AuthenticatorInterface
	if config.AuthConfig.APIEnabled {
		authenticator = createAPIAuthenticator(config.AuthConfig.APIURL)
	} else {
		authenticator = createLocalAuthenticator(config.AuthConfig.Username, config.AuthConfig.Password)
	}

	// Create WebDAV handler with middleware chain
	handler := buildHandlerChain(authenticator, s3Client, logger, auditLogger)

	return &Server{
		config:      config,
		handler:     handler,
		logger:      logger,
		auditLogger: auditLogger,
		shutdownFunc: func() error {
			if err := logger.Flush(); err != nil {
				log.Printf("Error flushing logs: %v", err)
			}
			if err := logger.Close(); err != nil {
				log.Printf("Error closing logger: %v", err)
			}
			return nil
		},
	}, nil
}

// initLogger initializes the logging system with both console and S3 output.
// The S3 sink stores logs under webdav/{env}/webdav-server/* for persistence.
func initLogger(s3Client S3Interface) (*logging.Logger, error) {
	// Get the environment from env var or default to development
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	// Create S3 sink for logs
	s3Sink := logging.NewS3Sink(
		s3Client.GetS3Client(),
		os.Getenv("S3_BUCKET"),
		"webdav",
		env,
		"webdav-server",
		nil, // Use default options
	)

	// Create console sink for human-readable logs
	consoleSink := logging.NewConsoleSink()

	// Create logger with both sinks
	logger := logging.NewLogger(
		1000,           // Buffer size
		30*time.Second, // Flush interval
		consoleSink,    // Console sink first for immediate output
		s3Sink,         // S3 sink second for persistence
	)

	return logger, nil
}

// buildHandlerChain creates the middleware chain for the WebDAV handler.
// The chain includes (from outer to inner):
// 1. Security headers (CORS, content security)
// 2. Request logging with correlation IDs
// 3. Rate limiting per IP
// 4. Request size limits
// 5. WebDAV handler (auth, file operations)
func buildHandlerChain(authenticator AuthenticatorInterface, s3Client S3Interface, logger *logging.Logger, auditLogger *logging.AuditLogger) http.Handler {
	webdavHandler := setupWebDAVHandler(authenticator, s3Client, auditLogger)

	return SecurityHeaders(
		logging.RequestLoggerMiddleware(logger)(
			RateLimiter(
				RequestSizeLimiter(
					webdavHandler,
				),
			),
		),
	)
}

// ListenAndServe starts the WebDAV server and blocks until shutdown.
// It handles graceful shutdown on:
// - Context cancellation
// - SIGINT or SIGTERM signals
// - Server errors
func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{
		Addr:         ":" + s.config.Port,
		Handler:      s.handler,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
		IdleTimeout:  s.config.IdleTimeout,
	}

	// Channel for server errors
	serverError := make(chan error, 1)

	// Channel for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		log.Printf("Starting WebDAV server on :%s", s.config.Port)
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

// shutdown performs a graceful server shutdown:
// 1. Stops accepting new requests
// 2. Waits for active requests to complete (up to ShutdownTimeout)
// 3. Flushes logs and performs cleanup
// 4. Closes the HTTP server
func (s *Server) shutdown(server *http.Server) error {
	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()

	// Shutdown rate limiter
	ShutdownRateLimiter()

	// Run custom shutdown function
	if err := s.shutdownFunc(); err != nil {
		log.Printf("Error during custom shutdown: %v", err)
	}

	// Shutdown HTTP server
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	return nil
}

// ServeHTTP implements http.Handler, allowing the server to be used
// as a handler in other HTTP servers if needed.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// Package pulsedav provides a WebDAV server with S3-compatible storage backend.
//
// The server implements a subset of the WebDAV protocol (RFC 4918) with a focus
// on file uploads to S3. Files are stored in the S3 bucket under the path
// "incoming/{userID}/{filename}".
//
// Server Configuration:
//   - Port: :80 (default, configurable via PORT env var)
//   - Read timeout: 30 seconds
//   - Write timeout: 30 seconds
//   - Idle timeout: 120 seconds
//   - Max file size: 100MB
//   - Rate limit: 100 requests per minute per IP
//
// Required Environment Variables:
//   - S3_BUCKET: S3 bucket name for file storage and logging
//     And one of:
//   - API_AUTH=true and AUTH_API_URL: External authentication API endpoint
//   - API_AUTH=false and LOCAL_AUTH_USERNAME, LOCAL_AUTH_PASSWORD: Local auth credentials
//
// Optional Environment Variables:
//   - PORT: Server port (default: 80)
//   - ENVIRONMENT: Environment name for logging (default: development)
//   - S3_ENDPOINT: Custom S3 endpoint URL (for non-AWS services)
//   - S3_REGION: S3 region (default: us-east-1)
//   - S3_ACCESS_KEY: S3 access key (uses instance role if not set)
//   - S3_SECRET_KEY: S3 secret key (uses instance role if not set)
//   - S3_SESSION_TOKEN: Session token for temporary credentials
//   - S3_FORCE_PATH_STYLE: Use path-style S3 URLs (default: false)
//
// Security Features:
//   - Basic Authentication (API or local)
//   - Request rate limiting per IP
//   - Maximum file size enforcement
//   - Allowed file extensions only (.txt, .pdf, .doc, .docx, .xls, .xlsx,
//     .jpg, .jpeg, .png, .gif, .zip, .csv)
//   - Path traversal protection
//   - Security headers (CORS, content security)
//   - Comprehensive request and audit logging
//   - Graceful shutdown handling
//
// Authentication Modes:
//
//  1. API Authentication (API_AUTH=true):
//     Validates credentials against an external API endpoint.
//     The API must accept Basic Auth and return a user ID.
//
//  2. Local Authentication (API_AUTH=false):
//     Uses configured username/password pair for Basic Auth.
//     The username is used as the user ID for S3 paths.
//
// Supported WebDAV Operations:
//   - PUT: Uploads file to S3 with size and type validation
//   - PROPFIND (depth: 0): Returns basic directory information
//   - OPTIONS: Returns WebDAV capabilities and CORS headers
//   - Other operations return 405 Method Not Allowed
//
// Logging:
//   - Console output for immediate visibility
//   - S3 logging for persistence (under webdav/{env}/webdav-server/*)
//   - Request logging with correlation IDs
//   - Authentication audit logging
//   - File upload audit logging
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/pondi/pulsedav/pkg"
)

// loadConfig loads and validates the application configuration
func loadConfig() (*pkg.ServerConfig, error) {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found or error loading it: %v", err)
	}

	cfg := &pkg.ServerConfig{
		Port:         getEnvOrDefault("PORT", "80"),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		S3Config: &pkg.S3Config{
			Bucket:         os.Getenv("S3_BUCKET"),
			Region:         os.Getenv("S3_REGION"),
			Endpoint:       os.Getenv("S3_ENDPOINT"),
			AccessKey:      os.Getenv("S3_ACCESS_KEY"),
			SecretKey:      os.Getenv("S3_SECRET_KEY"),
			SessionToken:   os.Getenv("S3_SESSION_TOKEN"),
			ForcePathStyle: os.Getenv("S3_FORCE_PATH_STYLE") == "true",
		},
		AuthConfig: &pkg.AuthConfig{
			APIEnabled: os.Getenv("API_AUTH") == "true",
			APIURL:     os.Getenv("AUTH_API_URL"),
			Username:   os.Getenv("LOCAL_AUTH_USERNAME"),
			Password:   os.Getenv("LOCAL_AUTH_PASSWORD"),
		},
	}

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// validateConfig validates the configuration
func validateConfig(cfg *pkg.ServerConfig) error {
	if cfg.S3Config.Bucket == "" {
		return fmt.Errorf("S3_BUCKET is required")
	}

	if cfg.AuthConfig.APIEnabled {
		if cfg.AuthConfig.APIURL == "" {
			return fmt.Errorf("AUTH_API_URL is required when API_AUTH is true")
		}
	} else {
		if cfg.AuthConfig.Username == "" || cfg.AuthConfig.Password == "" {
			return fmt.Errorf("LOCAL_AUTH_USERNAME and LOCAL_AUTH_PASSWORD are required when API_AUTH is false")
		}
	}

	return nil
}

// getEnvOrDefault returns the environment variable value or the default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize server with configuration
	server, err := pkg.InitServer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Create context for graceful shutdown
	ctx := context.Background()

	// Start the server
	log.Printf("Starting WebDAV server on :%s", cfg.Port)
	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

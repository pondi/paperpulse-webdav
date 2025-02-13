// Package pulsedav provides a WebDAV server with S3-compatible storage backend.
//
// The server supports basic WebDAV operations with a focus on file uploads to S3.
// File uploads (PUT requests) are stored in the S3 bucket under the path
// "incoming/{userID}/{filename}". Other WebDAV operations are not supported.
//
// Server Configuration:
//   - Default address: :80
//   - Read timeout: 30 seconds
//   - Write timeout: 30 seconds
//   - Idle timeout: 120 seconds
//   - Max file size: 100MB
//   - Rate limit: 100 requests per minute
//
// Usage:
//
//	import "github.com/pondi/pulsedav"
//
//	func main() {
//	    server, err := pulsedav.NewDefaultServer()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    ctx := context.Background()
//	    if err := server.ListenAndServe(ctx); err != nil {
//	        log.Fatal(err)
//	    }
//	}
//
// Required environment variables:
//   - AUTH_API_URL: Authentication API endpoint
//   - S3_BUCKET: S3 bucket name
//
// Optional environment variables:
//   - S3_ENDPOINT: Custom S3 endpoint URL (for non-AWS services)
//   - S3_REGION: S3 region (default: us-east-1)
//   - S3_ACCESS_KEY: S3 access key
//   - S3_SECRET_KEY: S3 secret key
//   - S3_SESSION_TOKEN: Session token (if using temporary credentials)
//   - S3_FORCE_PATH_STYLE: Use path-style S3 URLs (default: false)
//
// Security Features:
//   - Basic Authentication required
//   - File size limit: 100MB
//   - Rate limiting: 100 requests per minute
//   - Allowed file extensions: .txt, .pdf, .doc, .docx, .xls, .xlsx, .jpg, .jpeg, .png, .gif, .zip, .csv
//   - Path traversal protection
//   - Security headers
//   - Request logging
//
// Authentication:
// The server uses Basic Authentication and validates credentials against an external
// authentication API. The API must accept POST requests with username/password and
// return a user ID that will be used in the S3 path structure.
//
// WebDAV Operations:
//   - PUT: Uploads file to S3 storage
//   - Other operations: Not supported (returns 405 Method Not Allowed)
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/pondi/pulsedav/pkg"
)

// Config represents the application configuration
type Config struct {
	S3 S3Config
}

// S3Config holds S3-specific configuration
type S3Config struct {
	Bucket   string
	Region   string
	Endpoint string
}

func main() {
	// Load environment variables from .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found or error loading it: %v", err)
	}

	// Initialize configuration
	config := &Config{
		S3: S3Config{
			Bucket:   os.Getenv("S3_BUCKET"),
			Region:   os.Getenv("S3_REGION"),
			Endpoint: os.Getenv("S3_ENDPOINT"),
		},
	}

	// Validate configuration
	if config.S3.Bucket == "" {
		log.Fatal("S3_BUCKET environment variable is required")
	}

	// Initialize server
	server, err := NewDefaultServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Create context for graceful shutdown
	ctx := context.Background()

	// Start the server
	log.Printf("Starting WebDAV server on %s", server.Addr)
	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// NewDefaultServer creates a new WebDAV server with default configuration.
// It loads environment variables and initializes all required components.
func NewDefaultServer() (*pkg.Server, error) {
	// Validate required environment variables
	for _, envVar := range pkg.RequiredEnvVars {
		if os.Getenv(envVar) == "" {
			return nil, fmt.Errorf("%w: %s", pkg.ErrMissingEnvVar, envVar)
		}
	}

	return pkg.NewServer()
}

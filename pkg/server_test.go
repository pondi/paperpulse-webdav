package pkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// testS3Client is a mock implementation of S3Interface for server tests
type testS3Client struct {
	shouldError bool
}

func (m *testS3Client) UploadFile(ctx context.Context, userID string, filename string, content io.Reader) error {
	if m.shouldError {
		return errors.New("upload failed")
	}
	return nil
}

func TestNewServer(t *testing.T) {
	// Save original env vars
	originalBucket := os.Getenv("S3_BUCKET")
	originalAuthURL := os.Getenv("AUTH_API_URL")
	originalAPIAuth := os.Getenv("API_AUTH")
	defer func() {
		os.Setenv("S3_BUCKET", originalBucket)
		os.Setenv("AUTH_API_URL", originalAuthURL)
		os.Setenv("API_AUTH", originalAPIAuth)
	}()

	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "valid configuration",
			envVars: map[string]string{
				"S3_BUCKET":    "test-bucket",
				"AUTH_API_URL": "http://auth-api",
				"API_AUTH":     "true",
				"S3_REGION":    "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "missing S3 bucket",
			envVars: map[string]string{
				"AUTH_API_URL": "http://auth-api",
				"API_AUTH":     "true",
				"S3_REGION":    "us-east-1",
			},
			wantErr: true,
		},
		{
			name: "missing auth URL",
			envVars: map[string]string{
				"S3_BUCKET": "test-bucket",
				"API_AUTH":  "true",
				"S3_REGION": "us-east-1",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear and set environment variables
			os.Clearenv()
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			var server *Server
			var err error

			// Validate required environment variables first
			for _, envVar := range getRequiredEnvVars() {
				if os.Getenv(envVar) == "" {
					err = fmt.Errorf("%w: %s", ErrMissingEnvVar, envVar)
					break
				}
			}

			// Only create server if environment validation passes
			if err == nil {
				// Create a test S3 client
				mockS3 := &testS3Client{shouldError: false}
				server, err = newServerWithS3Client(mockS3)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("NewServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if server == nil {
					t.Error("NewServer() returned nil server")
					return
				}

				// Verify default configuration
				if server.Addr != DefaultAddr {
					t.Errorf("NewServer() Addr = %v, want %v", server.Addr, DefaultAddr)
				}
				if server.ReadTimeout != DefaultReadTimeout {
					t.Errorf("NewServer() ReadTimeout = %v, want %v", server.ReadTimeout, DefaultReadTimeout)
				}
				if server.WriteTimeout != DefaultWriteTimeout {
					t.Errorf("NewServer() WriteTimeout = %v, want %v", server.WriteTimeout, DefaultWriteTimeout)
				}
				if server.IdleTimeout != DefaultIdleTimeout {
					t.Errorf("NewServer() IdleTimeout = %v, want %v", server.IdleTimeout, DefaultIdleTimeout)
				}
				if server.Handler == nil {
					t.Error("NewServer() Handler is nil")
				}
			}
		})
	}
}

func TestServer_ListenAndServe(t *testing.T) {
	// Create a test server with a custom handler
	server := &Server{
		Addr:         ":0", // Use random port
		Handler:      http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		IdleTimeout:  1 * time.Second,
	}

	// Create a context with cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(ctx)
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("ListenAndServe() shutdown timeout")
	}
}

func TestServer_ServeHTTP(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &Server{
		Handler: handler,
	}

	// Create test request and response recorder
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	// Serve request
	server.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("ServeHTTP() status = %v, want %v", recorder.Code, http.StatusOK)
	}
}

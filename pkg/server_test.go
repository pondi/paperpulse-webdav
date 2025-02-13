package pkg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// mockS3API for testing server initialization
type mockServerS3API struct {
	shouldFailHeadBucket bool
}

func (m *mockServerS3API) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.shouldFailHeadBucket {
		return nil, errors.New("bucket does not exist")
	}
	return &s3.HeadBucketOutput{}, nil
}

func (m *mockServerS3API) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return &s3.PutObjectOutput{}, nil
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

			server, err := NewServer()
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

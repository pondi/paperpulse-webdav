package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testUserID   = "123"
	testUsername = "testuser"
	testPassword = "testpass"
)

// mockAuthenticator implements AuthenticatorInterface for testing
type mockAuthenticator struct {
	shouldAuth bool
	userID     string
	username   string
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, username, password string) (AuthResult, error) {
	if !m.shouldAuth {
		return AuthResult{}, errors.New("authentication failed")
	}
	return AuthResult{
		Authenticated: true,
		UserID:        m.userID,
		Username:      m.username,
	}, nil
}

// mockS3Client implements S3Interface for testing
type mockS3Client struct {
	shouldError     bool
	lastUploadInput struct {
		userID   string
		filename string
		content  []byte
	}
}

func (m *mockS3Client) UploadFile(ctx context.Context, userID string, filename string, content io.Reader) error {
	if m.shouldError {
		return errors.New("upload failed")
	}

	// Capture upload details for verification
	contentBytes, _ := io.ReadAll(content)
	m.lastUploadInput = struct {
		userID   string
		filename string
		content  []byte
	}{
		userID:   userID,
		filename: filename,
		content:  contentBytes,
	}

	return nil
}

func TestNewWebDAVHandler(t *testing.T) {
	tests := []struct {
		name          string
		authenticator AuthenticatorInterface
		s3Client      S3Interface
		wantPanic     bool
	}{
		{
			name:          "valid initialization",
			authenticator: &mockAuthenticator{},
			s3Client:      &mockS3Client{},
			wantPanic:     false,
		},
		{
			name:          "nil authenticator",
			authenticator: nil,
			s3Client:      &mockS3Client{},
			wantPanic:     true,
		},
		{
			name:          "nil s3 client",
			authenticator: &mockAuthenticator{},
			s3Client:      nil,
			wantPanic:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.wantPanic {
					t.Errorf("NewWebDAVHandler() panic = %v, wantPanic = %v", r, tt.wantPanic)
				}
			}()

			handler := NewWebDAVHandler(tt.authenticator, tt.s3Client)
			if !tt.wantPanic && handler == nil {
				t.Error("NewWebDAVHandler() returned nil handler")
			}
		})
	}
}

func TestWebDAVHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		auth           string
		mockAuth       *mockAuthenticator
		mockS3         *mockS3Client
		body           string
		wantCode       int
		wantUpload     bool
		wantUploadPath string
	}{
		{
			name:     "no authentication",
			method:   http.MethodPut,
			path:     "/test.txt",
			auth:     "",
			mockAuth: &mockAuthenticator{shouldAuth: false},
			mockS3:   &mockS3Client{},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "failed authentication",
			method:   http.MethodPut,
			path:     "/test.txt",
			auth:     basicAuth("user", "wrong"),
			mockAuth: &mockAuthenticator{shouldAuth: false},
			mockS3:   &mockS3Client{},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:   "successful upload",
			method: http.MethodPut,
			path:   "/test.txt",
			auth:   basicAuth(testUsername, testPassword),
			body:   "test content",
			mockAuth: &mockAuthenticator{
				shouldAuth: true,
				userID:     testUserID,
				username:   testUsername,
			},
			mockS3:         &mockS3Client{},
			wantCode:       http.StatusCreated,
			wantUpload:     true,
			wantUploadPath: "test.txt",
		},
		{
			name:   "failed upload",
			method: http.MethodPut,
			path:   "/test.txt",
			auth:   basicAuth(testUsername, testPassword),
			body:   "test content",
			mockAuth: &mockAuthenticator{
				shouldAuth: true,
				userID:     testUserID,
				username:   testUsername,
			},
			mockS3: &mockS3Client{
				shouldError: true,
			},
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "method not allowed",
			method:   http.MethodGet,
			path:     "/test.txt",
			auth:     basicAuth(testUsername, testPassword),
			mockAuth: &mockAuthenticator{shouldAuth: true},
			mockS3:   &mockS3Client{},
			wantCode: http.StatusMethodNotAllowed,
		},
		{
			name:   "empty filename",
			method: http.MethodPut,
			path:   "/",
			auth:   basicAuth(testUsername, testPassword),
			mockAuth: &mockAuthenticator{
				shouldAuth: true,
				userID:     testUserID,
				username:   testUsername,
			},
			mockS3:   &mockS3Client{},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewWebDAVHandler(tt.mockAuth, tt.mockS3)

			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Errorf("handler returned wrong status code: got %v want %v", rr.Code, tt.wantCode)
			}

			if tt.wantUpload {
				if !tt.mockS3.shouldError && tt.mockS3.lastUploadInput.filename != tt.wantUploadPath {
					t.Errorf("wrong upload path: got %v want %v", tt.mockS3.lastUploadInput.filename, tt.wantUploadPath)
				}
			}

			if tt.method == http.MethodPut && tt.wantCode == http.StatusCreated {
				if location := rr.Header().Get("Location"); location != tt.path {
					t.Errorf("wrong Location header: got %v want %v", location, tt.path)
				}
			}

			if tt.method != http.MethodPut && tt.wantCode == http.StatusMethodNotAllowed {
				if allow := rr.Header().Get("Allow"); allow != "PUT" {
					t.Errorf("wrong Allow header: got %v want PUT", allow)
				}
			}
		})
	}
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

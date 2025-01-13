package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		password       string
		mockResponse   interface{}
		mockStatusCode int
		wantErr        bool
		expectedErr    error
		wantAuthResult AuthResult
	}{
		{
			name:     "successful authentication",
			username: "testuser",
			password: "testpass",
			mockResponse: authSuccessResponse{
				UserID:   123,
				Username: "testuser",
			},
			mockStatusCode: http.StatusOK,
			wantErr:        false,
			wantAuthResult: AuthResult{
				Authenticated: true,
				UserID:        "123",
				Username:      "testuser",
			},
		},
		{
			name:     "invalid credentials",
			username: "wronguser",
			password: "wrongpass",
			mockResponse: authErrorResponse{
				Error: "Invalid credentials",
			},
			mockStatusCode: http.StatusUnauthorized,
			wantErr:        true,
			expectedErr:    ErrInvalidCredentials,
		},
		{
			name:        "empty credentials",
			username:    "",
			password:    "",
			wantErr:     true,
			expectedErr: ErrInvalidCredentials,
		},
		{
			name:     "validation error",
			username: "testuser",
			password: "short",
			mockResponse: authErrorResponse{
				Error: "Password too short",
				Messages: map[string][]string{
					"password": {"must be at least 8 characters"},
				},
			},
			mockStatusCode: http.StatusUnprocessableEntity,
			wantErr:        true,
		},
		{
			name:     "server error",
			username: "testuser",
			password: "testpass",
			mockResponse: authErrorResponse{
				Error: "Internal server error",
			},
			mockStatusCode: http.StatusInternalServerError,
			wantErr:        true,
			expectedErr:    ErrAuthFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and content type
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
				}

				// If empty credentials, don't proceed with mock response
				if tt.username == "" && tt.password == "" {
					return
				}

				// Set response status code and write mock response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					if err := json.NewEncoder(w).Encode(tt.mockResponse); err != nil {
						t.Fatalf("failed to encode mock response: %v", err)
					}
				}
			}))
			defer server.Close()

			// Create authenticator with test server URL
			auth := &Authenticator{
				client:  server.Client(),
				authURL: server.URL,
			}

			// Call Authenticate
			result, err := auth.Authenticate(context.Background(), tt.username, tt.password)

			// Check error
			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("Authenticate() error = %v, want %v", err, tt.expectedErr)
			}

			// Check authentication result
			if !tt.wantErr {
				if result.Authenticated != tt.wantAuthResult.Authenticated {
					t.Errorf("Authenticate() authenticated = %v, want %v", result.Authenticated, tt.wantAuthResult.Authenticated)
				}
				if result.UserID != tt.wantAuthResult.UserID {
					t.Errorf("Authenticate() userID = %v, want %v", result.UserID, tt.wantAuthResult.UserID)
				}
				if result.Username != tt.wantAuthResult.Username {
					t.Errorf("Authenticate() username = %v, want %v", result.Username, tt.wantAuthResult.Username)
				}
			}
		})
	}
}

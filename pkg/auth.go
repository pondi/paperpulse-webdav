package pkg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAuthFailed         = errors.New("authentication failed")
)

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Authenticated bool
	UserID        string
	Username      string
}

// authRequest represents the authentication request payload
type authRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// authSuccessResponse represents a successful authentication response
type authSuccessResponse struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
}

// authErrorResponse represents an authentication error response
type authErrorResponse struct {
	Error    string              `json:"error"`
	Messages map[string][]string `json:"messages,omitempty"`
}

// Authenticator handles user authentication against an external API
type Authenticator struct {
	client  *http.Client
	authURL string
}

// NewAuthenticator creates a new authenticator with the configured auth URL
func NewAuthenticator() *Authenticator {
	authURL := os.Getenv("AUTH_API_URL")
	if authURL == "" {
		authURL = "http://localhost:8000/api/authenticate" // Default value for development
	}

	return &Authenticator{
		client:  &http.Client{},
		authURL: authURL,
	}
}

// Authenticate validates user credentials against the authentication API.
// It returns an AuthResult containing the authentication status and user details.
// If authentication fails, it returns an appropriate error.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (AuthResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return AuthResult{}, ErrInvalidCredentials
	}

	reqBody := authRequest{
		Username: username,
		Password: password,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return AuthResult{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.authURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return AuthResult{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return AuthResult{}, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var successResp authSuccessResponse
		if err := json.NewDecoder(resp.Body).Decode(&successResp); err != nil {
			return AuthResult{}, fmt.Errorf("failed to decode success response: %w", err)
		}

		return AuthResult{
			Authenticated: true,
			UserID:        fmt.Sprintf("%d", successResp.UserID),
			Username:      successResp.Username,
		}, nil
	}

	var errorResp authErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
		return AuthResult{}, fmt.Errorf("failed to decode error response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return AuthResult{}, ErrInvalidCredentials
	case http.StatusUnprocessableEntity:
		return AuthResult{}, fmt.Errorf("validation error: %s", errorResp.Error)
	default:
		return AuthResult{}, fmt.Errorf("%w: %s", ErrAuthFailed, errorResp.Error)
	}
}

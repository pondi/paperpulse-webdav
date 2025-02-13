package pkg

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrRateLimitExceeded  = errors.New("rate limit exceeded")
	ErrBruteForceBlock    = errors.New("account temporarily locked due to too many failed attempts")
)

// Authentication constants
const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	AuthRateLimit     = 10 // requests per minute
)

// failedAttempt tracks failed login attempts
type failedAttempt struct {
	count     int
	firstFail time.Time
	lastFail  time.Time
	lockedAt  time.Time
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Authenticated bool
	UserID        string
	Username      string
	Error         error
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

// AuthConfig holds authentication configuration
type AuthConfig struct {
	APIEnabled bool
	APIURL     string
	Username   string
	Password   string
}

// Authenticator handles user authentication against an external API or local credentials
type Authenticator struct {
	client      *http.Client
	authURL     string
	useAPIAuth  bool
	localUser   string
	localPass   string
	localUserID string

	// Rate limiting and brute force protection
	mu             sync.RWMutex
	failedAttempts map[string]*failedAttempt
	rateLimiter    *rate.Limiter
	cleanupTicker  *time.Ticker
	done           chan struct{}
}

// APIAuthenticator implements authentication against an external API
type APIAuthenticator struct {
	apiURL     string
	httpClient *http.Client
}

// LocalAuthenticator implements local authentication with username/password
type LocalAuthenticator struct {
	username string
	password string
}

// createAuthenticator creates an authenticator instance with the configured auth settings
func createAuthenticator() *Authenticator {
	useAPIAuth := strings.ToLower(os.Getenv("API_AUTH")) == "true"

	auth := &Authenticator{
		client:         &http.Client{Timeout: 10 * time.Second},
		useAPIAuth:     useAPIAuth,
		failedAttempts: make(map[string]*failedAttempt),
		rateLimiter:    rate.NewLimiter(rate.Every(time.Minute/AuthRateLimit), AuthRateLimit),
		cleanupTicker:  time.NewTicker(5 * time.Minute),
		done:           make(chan struct{}),
	}

	if useAPIAuth {
		auth.authURL = os.Getenv("AUTH_API_URL")
		if auth.authURL == "" {
			auth.authURL = "http://localhost:8000/api/authenticate" // Default value for development
		}
	} else {
		auth.localUser = os.Getenv("LOCAL_AUTH_USERNAME")
		auth.localPass = os.Getenv("LOCAL_AUTH_PASSWORD")
		auth.localUserID = os.Getenv("LOCAL_AUTH_USER_ID")
		if auth.localUserID == "" {
			auth.localUserID = "1" // Default local user ID
		}
	}

	// Start cleanup goroutine
	go auth.cleanup()

	return auth
}

// cleanup periodically removes expired failed attempts
func (a *Authenticator) cleanup() {
	for {
		select {
		case <-a.cleanupTicker.C:
			a.mu.Lock()
			now := time.Now()
			for username, attempt := range a.failedAttempts {
				// Remove entries older than lockout duration
				if now.Sub(attempt.lastFail) > LockoutDuration {
					delete(a.failedAttempts, username)
				}
			}
			a.mu.Unlock()
		case <-a.done:
			a.cleanupTicker.Stop()
			return
		}
	}
}

// Shutdown gracefully stops the authenticator
func (a *Authenticator) Shutdown() {
	close(a.done)
}

// checkBruteForce checks if the account is locked due to too many failed attempts
func (a *Authenticator) checkBruteForce(username string) error {
	a.mu.RLock()
	attempt, exists := a.failedAttempts[username]
	a.mu.RUnlock()

	if !exists {
		return nil
	}

	now := time.Now()
	if attempt.count >= MaxFailedAttempts {
		if now.Sub(attempt.lockedAt) < LockoutDuration {
			return ErrBruteForceBlock
		}
		// Reset after lockout duration
		a.mu.Lock()
		delete(a.failedAttempts, username)
		a.mu.Unlock()
	}

	return nil
}

// recordFailedAttempt records a failed authentication attempt
func (a *Authenticator) recordFailedAttempt(username string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	attempt, exists := a.failedAttempts[username]
	if !exists {
		a.failedAttempts[username] = &failedAttempt{
			count:     1,
			firstFail: now,
			lastFail:  now,
		}
		return
	}

	attempt.count++
	attempt.lastFail = now
	if attempt.count >= MaxFailedAttempts {
		attempt.lockedAt = now
	}
}

// resetFailedAttempts resets the failed attempts counter for a username
func (a *Authenticator) resetFailedAttempts(username string) {
	a.mu.Lock()
	delete(a.failedAttempts, username)
	a.mu.Unlock()
}

// Authenticate validates user credentials against either the API or local credentials.
// It returns an AuthResult containing the authentication status and user details.
// If authentication fails, it returns an appropriate error.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (AuthResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return AuthResult{}, ErrInvalidCredentials
	}

	// Check rate limit
	if !a.rateLimiter.Allow() {
		return AuthResult{}, ErrRateLimitExceeded
	}

	// Check for brute force attempts
	if err := a.checkBruteForce(username); err != nil {
		return AuthResult{}, err
	}

	var result AuthResult
	var err error

	if !a.useAPIAuth {
		// Use constant-time comparison for local authentication
		usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.localUser)) == 1
		passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.localPass)) == 1

		if usernameMatch && passwordMatch {
			result = AuthResult{
				Authenticated: true,
				UserID:        a.localUserID,
				Username:      username,
			}
		} else {
			err = ErrInvalidCredentials
		}
	} else {
		result, err = a.authenticateWithAPI(ctx, username, password)
	}

	// Handle authentication result
	if err != nil {
		a.recordFailedAttempt(username)
		return AuthResult{}, err
	}

	// Reset failed attempts on successful authentication
	a.resetFailedAttempts(username)
	return result, nil
}

// authenticateWithAPI handles authentication with the external API
func (a *Authenticator) authenticateWithAPI(ctx context.Context, username, password string) (AuthResult, error) {
	// Use API authentication
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

// createAPIAuthenticator creates an API-based authenticator
func createAPIAuthenticator(apiURL string) *APIAuthenticator {
	return &APIAuthenticator{
		apiURL: apiURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// createLocalAuthenticator creates a local authenticator
func createLocalAuthenticator(username, password string) *LocalAuthenticator {
	return &LocalAuthenticator{
		username: username,
		password: password,
	}
}

// Authenticate implements AuthenticatorInterface for APIAuthenticator
func (a *APIAuthenticator) Authenticate(ctx context.Context, username, password string) (AuthResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.apiURL, nil)
	if err != nil {
		return AuthResult{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(username, password)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return AuthResult{}, fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AuthResult{
			Authenticated: false,
			Error:         fmt.Errorf("authentication failed with status: %d", resp.StatusCode),
		}, nil
	}

	var result struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return AuthResult{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return AuthResult{
		Authenticated: true,
		UserID:        result.UserID,
	}, nil
}

// Authenticate implements AuthenticatorInterface for LocalAuthenticator
func (a *LocalAuthenticator) Authenticate(_ context.Context, username, password string) (AuthResult, error) {
	if username == a.username && password == a.password {
		return AuthResult{
			Authenticated: true,
			UserID:        username,
		}, nil
	}

	return AuthResult{
		Authenticated: false,
		Error:         fmt.Errorf("invalid credentials"),
	}, nil
}

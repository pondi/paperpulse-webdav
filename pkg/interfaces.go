package pkg

import (
	"context"
	"io"
)

// Authenticator defines the interface for authentication operations
type AuthenticatorInterface interface {
	Authenticate(ctx context.Context, username, password string) (AuthResult, error)
}

// S3Interface defines the interface for S3 operations
type S3Interface interface {
	UploadFile(ctx context.Context, userID string, filename string, content io.Reader) error
}

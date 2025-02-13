package pkg

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Authenticator defines the interface for authentication operations
type AuthenticatorInterface interface {
	Authenticate(ctx context.Context, username, password string) (AuthResult, error)
}

// S3Interface defines the interface for S3 operations
type S3Interface interface {
	UploadFile(ctx context.Context, userID string, filename string, content io.Reader) error
	ListFiles(ctx context.Context, prefix string) ([]S3Item, error)
	GetS3Client() interface {
		HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
		PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	}
}

// S3Item represents a file or directory in S3
type S3Item struct {
	Name         string
	IsCollection string
	LastModified time.Time
	ContentType  string
	Size         int64
}

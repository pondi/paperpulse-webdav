package pkg

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Common errors
var (
	ErrEmptyBucket   = fmt.Errorf("bucket name cannot be empty")
	ErrEmptyUserID   = fmt.Errorf("userID cannot be empty")
	ErrEmptyFilename = fmt.Errorf("filename cannot be empty")
	ErrNilContent    = fmt.Errorf("content cannot be nil")
	ErrNilContext    = fmt.Errorf("context cannot be nil")
)

// S3Client implements S3Interface for AWS S3 operations
type S3Client struct {
	client *s3.Client
	bucket string
}

// s3Config holds the configuration for S3 client
type s3Config struct {
	endpoint     string
	region       string
	accessKey    string
	secretKey    string
	sessionToken string
	usePathStyle bool
}

// loadConfigFromEnv loads S3 configuration from environment variables
func loadConfigFromEnv() s3Config {
	return s3Config{
		endpoint:     os.Getenv("S3_ENDPOINT"),
		region:       os.Getenv("S3_REGION"),
		accessKey:    os.Getenv("S3_ACCESS_KEY"),
		secretKey:    os.Getenv("S3_SECRET_KEY"),
		sessionToken: os.Getenv("S3_SESSION_TOKEN"),
		usePathStyle: os.Getenv("S3_FORCE_PATH_STYLE") == "true",
	}
}

// loadS3Config creates AWS config from the provided configuration
func loadS3Config(ctx context.Context, cfg s3Config) (aws.Config, error) {
	var options []func(*config.LoadOptions) error

	// Custom endpoint configuration
	if cfg.endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               cfg.endpoint,
				SigningRegion:     cfg.region,
				HostnameImmutable: true,
			}, nil
		})
		options = append(options, config.WithEndpointResolverWithOptions(customResolver))
	}

	// If access key and secret are provided, use them
	if cfg.accessKey != "" {
		options = append(options, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.accessKey,
			cfg.secretKey,
			cfg.sessionToken,
		)))
	}

	// Set custom region if provided
	if cfg.region != "" {
		options = append(options, config.WithRegion(cfg.region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return awsCfg, nil
}

// NewS3Client creates a new S3 client with the provided bucket
func NewS3Client(ctx context.Context, bucket string) (*S3Client, error) {
	if bucket == "" {
		return nil, ErrEmptyBucket
	}

	cfg := loadConfigFromEnv()
	awsCfg, err := loadS3Config(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	// Create S3 client with custom configuration
	s3Options := []func(*s3.Options){}
	if cfg.usePathStyle {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Options...)

	// Verify bucket exists and is accessible
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify bucket access: %w", err)
	}

	return &S3Client{
		client: client,
		bucket: bucket,
	}, nil
}

// UploadFile uploads a file to S3 with the given userID and filename.
// The file will be stored in the "incoming/{userID}/{filename}" path.
func (c *S3Client) UploadFile(ctx context.Context, userID string, filename string, content io.Reader) error {
	if ctx == nil {
		return ErrNilContext
	}
	if userID == "" {
		return ErrEmptyUserID
	}
	if filename == "" {
		return ErrEmptyFilename
	}
	if content == nil {
		return ErrNilContent
	}

	filename = path.Clean(filename)
	filename = strings.TrimPrefix(filename, "/")
	key := fmt.Sprintf("incoming/%s/%s", userID, filename)

	_, err := c.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(key),
		Body:   content,
	})
	if err != nil {
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	return nil
}

// GetS3Client returns the underlying AWS S3 client
func (s *S3Client) GetS3Client() interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
} {
	return s.client
}

// Package pkg provides S3 storage functionality for the WebDAV server.
package pkg

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Common errors related to S3 operations
var (
	// ErrEmptyBucket indicates that no S3 bucket name was provided
	ErrEmptyBucket = fmt.Errorf("bucket name cannot be empty")

	// ErrEmptyUserID indicates that no user ID was provided for file upload
	ErrEmptyUserID = fmt.Errorf("userID cannot be empty")

	// ErrEmptyFilename indicates that no filename was provided for upload
	ErrEmptyFilename = fmt.Errorf("filename cannot be empty")

	// ErrNilContent indicates that no file content was provided
	ErrNilContent = fmt.Errorf("content cannot be nil")

	// ErrNilContext indicates that no context was provided for the operation
	ErrNilContext = fmt.Errorf("context cannot be nil")
)

// S3Config holds the configuration for connecting to an S3-compatible storage service.
// All fields are optional except Bucket. If credentials are not provided,
// the AWS SDK will attempt to use instance role or environment credentials.
type S3Config struct {
	// Bucket is the name of the S3 bucket to use (required)
	Bucket string

	// Region is the AWS region (default: us-east-1)
	Region string

	// Endpoint is the custom S3 endpoint URL (for non-AWS services)
	Endpoint string

	// AccessKey is the S3 access key ID (optional)
	AccessKey string

	// SecretKey is the S3 secret access key (optional)
	SecretKey string

	// SessionToken is the temporary session token (optional)
	SessionToken string

	// ForcePathStyle forces path-style S3 URLs instead of virtual-hosted-style
	ForcePathStyle bool
}

// S3Client implements the S3Interface for AWS S3 operations.
// It provides a high-level interface for file uploads and bucket operations.
type S3Client struct {
	client *s3.Client // AWS S3 client
	bucket string     // Target bucket name
}

// createS3Client creates and configures an S3 client with the provided configuration.
// It validates the configuration, sets up AWS credentials, and verifies bucket access.
// The client supports both AWS S3 and S3-compatible services through custom endpoints.
func createS3Client(ctx context.Context, config *S3Config) (*S3Client, error) {
	if config == nil {
		return nil, fmt.Errorf("S3 configuration cannot be nil")
	}
	if config.Bucket == "" {
		return nil, ErrEmptyBucket
	}

	var options []func(*awsconfig.LoadOptions) error

	// Custom endpoint configuration
	if config.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL:               config.Endpoint,
				SigningRegion:     config.Region,
				HostnameImmutable: true,
			}, nil
		})
		options = append(options, awsconfig.WithEndpointResolverWithOptions(customResolver))
	}

	// If access key and secret are provided, use them
	if config.AccessKey != "" {
		options = append(options, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			config.AccessKey,
			config.SecretKey,
			config.SessionToken,
		)))
	}

	// Set custom region if provided
	if config.Region != "" {
		options = append(options, awsconfig.WithRegion(config.Region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom configuration
	s3Options := []func(*s3.Options){}
	if config.ForcePathStyle {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Options...)

	// Verify bucket exists and is accessible
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(config.Bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify bucket access: %w", err)
	}

	return &S3Client{
		client: client,
		bucket: config.Bucket,
	}, nil
}

// UploadFile uploads a file to S3 with the given userID and filename.
// The file is stored in the "incoming/{userID}/{filename}" path.
// It performs the following validations:
// - Non-nil context
// - Non-empty userID and filename
// - Non-nil content
// The function is safe for concurrent use.
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

// GetS3Client returns the underlying AWS S3 client interface.
// This is primarily used by the logging system for S3 sink configuration.
// The interface is limited to the required operations to prevent misuse.
func (s *S3Client) GetS3Client() interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
} {
	return s.client
}

// ListFiles lists files and directories in the S3 bucket with the given prefix.
// It returns a slice of S3Items representing the contents.
func (c *S3Client) ListFiles(ctx context.Context, prefix string) ([]S3Item, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	// Ensure prefix ends with / for directory listing
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	input := &s3.ListObjectsV2Input{
		Bucket:    aws.String(c.bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	}

	result, err := c.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects: %w", err)
	}

	items := make([]S3Item, 0)

	// Add common prefixes (directories)
	for _, commonPrefix := range result.CommonPrefixes {
		if commonPrefix.Prefix == nil {
			continue
		}
		name := strings.TrimPrefix(*commonPrefix.Prefix, prefix)
		name = strings.TrimSuffix(name, "/")
		if name == "" {
			continue
		}

		items = append(items, S3Item{
			Name:         name,
			IsCollection: "<D:collection/>",
			LastModified: time.Now().UTC(), // Directories don't have last modified time in S3
			ContentType:  "httpd/unix-directory",
			Size:         0,
		})
	}

	// Add objects (files)
	for _, obj := range result.Contents {
		if obj.Key == nil {
			continue
		}
		name := strings.TrimPrefix(*obj.Key, prefix)
		if name == "" {
			continue
		}

		contentType := "application/octet-stream"
		if strings.HasSuffix(strings.ToLower(name), ".pdf") {
			contentType = "application/pdf"
		} else if strings.HasSuffix(strings.ToLower(name), ".txt") {
			contentType = "text/plain"
		}
		// Add more content type mappings as needed

		var size int64
		if obj.Size != nil {
			size = *obj.Size
		}

		items = append(items, S3Item{
			Name:         name,
			IsCollection: "",
			LastModified: *obj.LastModified,
			ContentType:  contentType,
			Size:         size,
		})
	}

	return items, nil
}

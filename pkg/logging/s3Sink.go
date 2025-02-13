package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Common errors for S3 sink
var (
	ErrS3Upload = fmt.Errorf("s3 upload error")
	ErrEncode   = fmt.Errorf("json encode error")
)

// S3Client defines the interface for S3 operations needed by S3Sink.
// This allows for easier testing and mocking.
type S3Client interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// S3Sink implements LogSink interface for writing logs to S3.
// It buffers logs and rotates files based on size.
// It is safe for concurrent use.
type S3Sink struct {
	client        S3Client
	bucket        string          // S3 bucket name
	prefix        string          // S3 key prefix for logs
	environment   string          // Environment name (e.g., prod, staging)
	component     string          // Component name for log identification
	currentFile   string          // Current log file name
	rotateSize    int64           // Maximum size before rotating files
	currentSize   int64           // Current accumulated size
	mutex         sync.Mutex      // Protects concurrent access
	logFileNumber int             // Sequential number for log files
	ctx           context.Context // Context for S3 operations
}

const (
	defaultRotateSize = 50 * 1024 * 1024 // 50MB
	logFileFormat     = "2006/01/02/15-04-05-000"
	contentType       = "application/x-ndjson"
	maxRetries        = 3
)

// NewS3SinkOptions contains configuration options for creating a new S3Sink
type NewS3SinkOptions struct {
	RotateSize int64           // Optional custom rotate size
	Context    context.Context // Optional context for S3 operations
}

// NewS3Sink creates a new S3 sink for logging.
// It will create a directory structure in S3 organized by date.
func NewS3Sink(client S3Client, bucket, prefix, environment, component string, _ *NewS3SinkOptions) *S3Sink {
	return &S3Sink{
		client:        client,
		bucket:        bucket,
		prefix:        prefix,
		environment:   environment,
		component:     component,
		rotateSize:    defaultRotateSize,
		logFileNumber: 1,
		ctx:           context.Background(),
	}
}

// Write implements LogSink interface
func (s *S3Sink) Write(entries []LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.currentFile == "" {
		s.currentFile = s.generateFilename()
	}

	for i := range entries {
		entries[i].Environment = s.environment
		entries[i].Component = s.component
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("%w: %v", ErrEncode, err)
		}
	}

	newSize := s.currentSize + int64(buffer.Len())
	if newSize > s.rotateSize {
		s.logFileNumber++
		s.currentFile = s.generateFilename()
		s.currentSize = 0
		newSize = int64(buffer.Len())
	}

	key := path.Join("logs", s.prefix, s.currentFile)
	if err := s.uploadWithRetries(key, buffer.Bytes()); err != nil {
		return fmt.Errorf("%w: %v", ErrS3Upload, err)
	}

	s.currentSize = newSize
	return nil
}

// uploadWithRetries attempts to upload to S3 with exponential backoff
func (s *S3Sink) uploadWithRetries(key string, data []byte) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := s.client.PutObject(s.ctx, &s3.PutObjectInput{
			Bucket:      aws.String(s.bucket),
			Key:         aws.String(key),
			Body:        bytes.NewReader(data),
			ContentType: aws.String(contentType),
		})
		if err == nil {
			return nil
		}
		lastErr = err
		// Exponential backoff: 100ms, 200ms, 400ms
		time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
	}
	return lastErr
}

// generateFilename creates a new log filename with timestamp and sequence number
func (s *S3Sink) generateFilename() string {
	timestamp := time.Now().UTC().Format(logFileFormat)
	return fmt.Sprintf("%s-%s-%d.log", timestamp, s.component, s.logFileNumber)
}

// Flush implements LogSink interface
func (s *S3Sink) Flush() error {
	// No additional flushing needed for S3 sink as each Write is atomic
	return nil
}

// Close implements LogSink interface
func (s *S3Sink) Close() error {
	// No additional cleanup needed for S3 sink
	return nil
}

// IsImmediate implements LogSink interface
func (s *S3Sink) IsImmediate() bool {
	return false // S3 sink uses buffering and rotation
}

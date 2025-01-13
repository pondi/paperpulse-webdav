package pkg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const testBucket = "test-bucket"

// mockS3API implements the minimum S3 API interface needed for testing
type mockS3API interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Compile-time check to ensure mockS3Implementation implements mockS3API
var _ mockS3API = (*mockS3Implementation)(nil)

// mockS3Implementation is a mock implementation of the S3 client for testing
type mockS3Implementation struct {
	shouldFailHeadBucket bool
	shouldFailPutObject  bool
	lastPutObjectInput   *s3.PutObjectInput // Capture last upload for verification
}

func (m *mockS3Implementation) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.shouldFailHeadBucket {
		return nil, errors.New("bucket does not exist")
	}
	return &s3.HeadBucketOutput{}, nil
}

func (m *mockS3Implementation) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	m.lastPutObjectInput = params
	if m.shouldFailPutObject {
		return nil, errors.New("failed to upload object")
	}
	return &s3.PutObjectOutput{}, nil
}

// createTestS3Client creates a new S3Client with a mock implementation for testing
func createTestS3Client(bucket string, failHeadBucket bool) (*S3Client, *mockS3Implementation, error) {
	if bucket == "" {
		return nil, nil, ErrEmptyBucket
	}

	mock := &mockS3Implementation{
		shouldFailHeadBucket: failHeadBucket,
	}

	// Verify bucket exists and is accessible
	_, err := mock.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: &bucket,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify bucket access: %w", err)
	}

	client := &S3Client{
		s3Client: mock,
		bucket:   bucket,
	}

	return client, mock, nil
}

func TestNewS3Client(t *testing.T) {
	tests := []struct {
		name            string
		bucket          string
		failHeadBucket  bool
		wantErr         bool
		expectedErr     error
		expectedErrText string
	}{
		{
			name:        "empty bucket",
			bucket:      "",
			wantErr:     true,
			expectedErr: ErrEmptyBucket,
		},
		{
			name:    "successful creation",
			bucket:  testBucket,
			wantErr: false,
		},
		{
			name:            "bucket does not exist",
			bucket:          "nonexistent-bucket",
			failHeadBucket:  true,
			wantErr:         true,
			expectedErrText: "failed to verify bucket access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _, err := createTestS3Client(tt.bucket, tt.failHeadBucket)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewS3Client() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("NewS3Client() error = %v, want %v", err, tt.expectedErr)
			}

			if tt.expectedErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.expectedErrText)) {
				t.Errorf("NewS3Client() error = %v, want error containing %v", err, tt.expectedErrText)
			}

			if !tt.wantErr && client == nil {
				t.Error("NewS3Client() returned nil client without error")
			}
		})
	}
}

func TestS3Client_UploadFile(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		filename       string
		content        string
		failUpload     bool
		wantErr        bool
		expectedErr    error
		checkUploadKey bool // Whether to verify the upload key
		wantUploadKey  string
	}{
		{
			name:           "successful upload",
			userID:         "123",
			filename:       "test.txt",
			content:        "test content",
			wantErr:        false,
			checkUploadKey: true,
			wantUploadKey:  "incoming/123/test.txt",
		},
		{
			name:           "upload with path",
			userID:         "123",
			filename:       "folder/test.txt",
			content:        "test content",
			wantErr:        false,
			checkUploadKey: true,
			wantUploadKey:  "incoming/123/folder/test.txt",
		},
		{
			name:           "upload with absolute path",
			userID:         "123",
			filename:       "/folder/test.txt",
			content:        "test content",
			wantErr:        false,
			checkUploadKey: true,
			wantUploadKey:  "incoming/123/folder/test.txt",
		},
		{
			name:        "empty user ID",
			userID:      "",
			filename:    "test.txt",
			content:     "test content",
			wantErr:     true,
			expectedErr: ErrEmptyUserID,
		},
		{
			name:        "empty filename",
			userID:      "123",
			filename:    "",
			content:     "test content",
			wantErr:     true,
			expectedErr: ErrEmptyFilename,
		},
		{
			name:       "upload failure",
			userID:     "123",
			filename:   "test.txt",
			content:    "test content",
			failUpload: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockS3Implementation{
				shouldFailPutObject: tt.failUpload,
			}

			client := &S3Client{
				s3Client: mock,
				bucket:   testBucket,
			}

			content := strings.NewReader(tt.content)
			err := client.UploadFile(context.Background(), tt.userID, tt.filename, content)

			if (err != nil) != tt.wantErr {
				t.Errorf("UploadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("UploadFile() error = %v, want %v", err, tt.expectedErr)
			}

			if tt.checkUploadKey && !tt.wantErr {
				if mock.lastPutObjectInput == nil {
					t.Error("UploadFile() did not make a PutObject call")
					return
				}
				if got := *mock.lastPutObjectInput.Key; got != tt.wantUploadKey {
					t.Errorf("UploadFile() key = %v, want %v", got, tt.wantUploadKey)
				}
			}
		})
	}
}

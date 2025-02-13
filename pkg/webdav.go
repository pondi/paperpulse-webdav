package pkg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// Common errors
var (
	ErrInvalidFilename = &WebDAVError{
		StatusCode: http.StatusBadRequest,
		Message:    "Invalid filename",
		ErrorCode:  "INVALID_FILENAME",
	}
	ErrFileTooLarge = &WebDAVError{
		StatusCode: http.StatusRequestEntityTooLarge,
		Message:    "File exceeds maximum allowed size",
		ErrorCode:  "FILE_TOO_LARGE",
	}
	ErrUploadFailed = &WebDAVError{
		StatusCode: http.StatusInternalServerError,
		Message:    "Failed to upload file",
		ErrorCode:  "UPLOAD_FAILED",
	}
	ErrInvalidRequest = &WebDAVError{
		StatusCode: http.StatusBadRequest,
		Message:    "invalid request",
		ErrorCode:  "INVALID_REQUEST",
	}
	ErrMethodNotAllowed = &WebDAVError{
		StatusCode: http.StatusMethodNotAllowed,
		Message:    "Method not allowed",
		ErrorCode:  "METHOD_NOT_ALLOWED",
	}
)

// WebDAVError represents a WebDAV error following RFC 4918
type WebDAVError struct {
	StatusCode int    // HTTP status code
	Message    string // Human-readable message
	ErrorCode  string // Machine-readable error code
}

func (e *WebDAVError) Error() string {
	return e.Message
}

// NewWebDAVError creates a new WebDAV error with the given status code and message
func NewWebDAVError(statusCode int, message, errorCode string) *WebDAVError {
	return &WebDAVError{
		StatusCode: statusCode,
		Message:    message,
		ErrorCode:  errorCode,
	}
}

// writeWebDAVError writes a WebDAV-compatible error response following RFC 4918
func writeWebDAVError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")

	var webdavErr *WebDAVError
	if !errors.As(err, &webdavErr) {
		// Convert generic error to WebDAV error
		webdavErr = &WebDAVError{
			StatusCode: http.StatusInternalServerError,
			Message:    "Internal Server Error",
			ErrorCode:  "INTERNAL_ERROR",
		}
	}

	// Log error with correlation ID if available
	correlationID := w.Header().Get("X-Correlation-ID")
	if correlationID != "" {
		log.Printf("[%s] WebDAV Error: %s (Code: %s)", correlationID, webdavErr.Message, webdavErr.ErrorCode)
	} else {
		log.Printf("WebDAV Error: %s (Code: %s)", webdavErr.Message, webdavErr.ErrorCode)
	}

	w.WriteHeader(webdavErr.StatusCode)

	// Format error response according to RFC 4918 Section 9.8.5
	response := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8" ?>
<D:error xmlns:D="DAV:">
	<D:error>
		<D:status>HTTP/1.1 %d %s</D:status>
		<D:error-code>%s</D:error-code>
		<D:message>%s</D:message>
	</D:error>
</D:error>`,
		webdavErr.StatusCode,
		http.StatusText(webdavErr.StatusCode),
		webdavErr.ErrorCode,
		webdavErr.Message)

	w.Write([]byte(response))
}

// WebDAVHandler handles WebDAV requests, supporting only PUT operations
// for file uploads to S3 storage.
type WebDAVHandler struct {
	auth     AuthenticatorInterface
	s3Client S3Interface
}

// NewWebDAVHandler creates a new WebDAV handler with the given authenticator and S3 client.
// The handler only supports PUT operations, all other operations return 405 Method Not Allowed.
func NewWebDAVHandler(authenticator AuthenticatorInterface, s3Client S3Interface) *WebDAVHandler {
	if authenticator == nil {
		panic("authenticator cannot be nil")
	}
	if s3Client == nil {
		panic("s3Client cannot be nil")
	}

	return &WebDAVHandler{
		auth:     authenticator,
		s3Client: s3Client,
	}
}

// ServeHTTP implements http.Handler interface.
// It handles authentication and routes WebDAV requests to appropriate handlers.
func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set WebDAV compliance headers
	w.Header().Set("DAV", "1")
	w.Header().Set("MS-Author-Via", "DAV")
	w.Header().Add("Allow", "OPTIONS, PUT, PROPFIND")

	switch r.Method {
	case http.MethodOptions:
		h.handleOptions(w, r)
	case "PROPFIND":
		// Require authentication for PROPFIND
		_, ok := h.authenticate(w, r)
		if !ok {
			return // Response already written by authenticate
		}
		h.handlePropfind(w, r)
	case http.MethodPut:
		// Authenticate request
		userID, ok := h.authenticate(w, r)
		if !ok {
			return // Response already written by authenticate
		}
		h.handlePut(w, r, userID)
	default:
		writeWebDAVError(w, ErrMethodNotAllowed)
	}
}

// handleOptions handles OPTIONS requests for WebDAV protocol discovery
func (h *WebDAVHandler) handleOptions(w http.ResponseWriter, _ *http.Request) {
	// Only allow specific headers for security
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, If-Match, If-None-Match, Lock-Token, Timeout, X-Expected-Entity-Length")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS, PROPFIND")
	w.Header().Set("Access-Control-Max-Age", "86400") // Cache preflight for 24 hours
	w.WriteHeader(http.StatusOK)
}

// authenticate handles Basic Authentication and returns the userID if successful.
// It writes the appropriate error response if authentication fails.
func (h *WebDAVHandler) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}

	authResult, err := h.auth.Authenticate(r.Context(), username, password)
	if err != nil || !authResult.Authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return "", false
	}

	return authResult.UserID, true
}

// validateRequestBody performs security checks on the request body
func validateRequestBody(r *http.Request) error {
	// Validate Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/octet-stream") {
		return fmt.Errorf("invalid content type: only application/octet-stream is allowed")
	}

	// Validate Content-Length
	if r.ContentLength <= 0 {
		return fmt.Errorf("invalid content length: must be greater than 0")
	}

	// Check for content encoding to prevent BREACH/CRIME attacks
	if r.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("content encoding not allowed")
	}

	// Validate transfer encoding
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] != "chunked" {
		return fmt.Errorf("only chunked transfer encoding is allowed")
	}

	return nil
}

// handlePut processes PUT requests by uploading the file to S3.
// The file is stored in the "incoming/{userID}/{filename}" path.
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, userID string) {
	// Ensure the request body is always closed
	defer r.Body.Close()

	// Extract and validate filename
	filename := strings.TrimPrefix(r.URL.Path, "/")
	if filename == "" {
		writeWebDAVError(w, ErrInvalidFilename)
		return
	}

	// Validate request body
	if err := validateRequestBody(r); err != nil {
		writeWebDAVError(w, fmt.Errorf("invalid request: %w", err))
		return
	}

	// Validate file path and extension
	if err := ValidateFilePath(filename); err != nil {
		writeWebDAVError(w, fmt.Errorf("invalid file: %w", err))
		return
	}

	// Read the entire file into memory with size limit
	limitedReader := io.LimitReader(r.Body, MaxFileSize)
	fileData, err := io.ReadAll(limitedReader)
	if err != nil {
		log.Printf("Failed to read file: %v", err)
		writeWebDAVError(w, fmt.Errorf("failed to read file"))
		return
	}

	// Check if we hit the size limit
	if len(fileData) >= MaxFileSize {
		writeWebDAVError(w, ErrFileTooLarge)
		return
	}

	// Upload the buffered file to S3
	if err := h.s3Client.UploadFile(r.Context(), userID, filename, bytes.NewReader(fileData)); err != nil {
		// Log the error but don't expose internal details
		log.Printf("Failed to upload file: %v", err)
		writeWebDAVError(w, ErrUploadFailed)
		return
	}

	// Set appropriate response headers only after successful upload
	w.Header().Set("Location", "/"+filename)
	w.WriteHeader(http.StatusCreated)
}

// handlePropfind processes PROPFIND requests according to RFC 4918
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request) {
	// Check Depth header (0 = current resource, 1 = children, infinity = recursive)
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "infinity"
	}
	if depth == "infinity" {
		writeWebDAVError(w, &WebDAVError{
			StatusCode: http.StatusForbidden,
			Message:    "Infinity depth not allowed",
			ErrorCode:  "INFINITY_NOT_SUPPORTED",
		})
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)

	// Generate minimal WebDAV response showing an empty directory
	// This is secure as it doesn't expose any actual file information
	response := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
	<D:response>
		<D:href>%s</D:href>
		<D:propstat>
			<D:prop>
				<D:resourcetype><D:collection/></D:resourcetype>
				<D:displayname>%s</D:displayname>
				<D:getcontenttype>httpd/unix-directory</D:getcontenttype>
				<D:getlastmodified>%s</D:getlastmodified>
				<D:creationdate>%s</D:creationdate>
				<D:quota-available-bytes>%d</D:quota-available-bytes>
				<D:quota-used-bytes>%d</D:quota-used-bytes>
			</D:prop>
			<D:status>HTTP/1.1 200 OK</D:status>
		</D:propstat>
	</D:response>
</D:multistatus>`,
		r.URL.Path,
		filepath.Base(r.URL.Path),
		time.Now().UTC().Format(http.TimeFormat),
		time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		MaxFileSize, // Use MaxFileSize as quota limit
		0,           // No files stored yet
	)

	w.Write([]byte(response))
}

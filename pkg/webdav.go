package pkg

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pondi/pulsedav/pkg/logging"
)

const (
	// maxFileSize is the maximum allowed file size (100MB)
	maxFileSize = 100 * 1024 * 1024
)

// WebDAVError represents a WebDAV error following RFC 4918
type WebDAVError struct {
	StatusCode int    // HTTP status code
	Message    string // Human-readable message
	ErrorCode  string // Machine-readable error code
}

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
		Message:    "Invalid request",
		ErrorCode:  "INVALID_REQUEST",
	}
	ErrMethodNotAllowed = &WebDAVError{
		StatusCode: http.StatusMethodNotAllowed,
		Message:    "Method not allowed",
		ErrorCode:  "METHOD_NOT_ALLOWED",
	}
)

func (e *WebDAVError) Error() string {
	return e.Message
}

// WebDAVResponse represents a WebDAV XML response
type WebDAVResponse struct {
	XMLName   xml.Name `xml:"D:multistatus"`
	XMLNS     string   `xml:"xmlns:D,attr"`
	Responses []struct {
		Href     string `xml:"D:href"`
		PropStat struct {
			Status string `xml:"D:status"`
			Prop   struct {
				ResourceType string    `xml:"D:resourcetype"`
				LastModified time.Time `xml:"D:getlastmodified"`
				ContentType  string    `xml:"D:getcontenttype"`
				ContentLen   int64     `xml:"D:getcontentlength"`
			} `xml:"D:prop"`
		} `xml:"D:propstat"`
	} `xml:"D:response"`
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
	auth        AuthenticatorInterface
	s3Client    S3Interface
	auditLogger *logging.AuditLogger
}

// setupWebDAVHandler creates and configures a WebDAV handler with the given dependencies
func setupWebDAVHandler(authenticator AuthenticatorInterface, s3Client S3Interface, auditLogger *logging.AuditLogger) *WebDAVHandler {
	if authenticator == nil {
		panic("authenticator cannot be nil")
	}
	if s3Client == nil {
		panic("s3Client cannot be nil")
	}
	if auditLogger == nil {
		panic("auditLogger cannot be nil")
	}

	return &WebDAVHandler{
		auth:        authenticator,
		s3Client:    s3Client,
		auditLogger: auditLogger,
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

// handlePropfind handles PROPFIND requests according to RFC 4918
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request) {
	depth := r.Header.Get("Depth")
	if depth != "0" && depth != "1" {
		writeWebDAVError(w, &WebDAVError{
			StatusCode: http.StatusNotImplemented,
			Message:    "Only Depth: 0 or 1 is supported",
			ErrorCode:  "DEPTH_NOT_SUPPORTED",
		})
		return
	}

	// Create multistatus response
	response := WebDAVResponse{
		XMLNS: "DAV:",
		Responses: []struct {
			Href     string `xml:"D:href"`
			PropStat struct {
				Status string `xml:"D:status"`
				Prop   struct {
					ResourceType string    `xml:"D:resourcetype"`
					LastModified time.Time `xml:"D:getlastmodified"`
					ContentType  string    `xml:"D:getcontenttype"`
					ContentLen   int64     `xml:"D:getcontentlength"`
				} `xml:"D:prop"`
			} `xml:"D:propstat"`
		}{
			{
				Href: r.URL.Path,
				PropStat: struct {
					Status string `xml:"D:status"`
					Prop   struct {
						ResourceType string    `xml:"D:resourcetype"`
						LastModified time.Time `xml:"D:getlastmodified"`
						ContentType  string    `xml:"D:getcontenttype"`
						ContentLen   int64     `xml:"D:getcontentlength"`
					} `xml:"D:prop"`
				}{
					Status: "HTTP/1.1 200 OK",
					Prop: struct {
						ResourceType string    `xml:"D:resourcetype"`
						LastModified time.Time `xml:"D:getlastmodified"`
						ContentType  string    `xml:"D:getcontenttype"`
						ContentLen   int64     `xml:"D:getcontentlength"`
					}{
						ResourceType: "<D:collection/>",
						LastModified: time.Now().UTC(),
						ContentType:  "httpd/unix-directory",
					},
				},
			},
		},
	}

	// If depth is 1, add our placeholder message
	if depth == "1" {
		response.Responses = append(response.Responses, struct {
			Href     string `xml:"D:href"`
			PropStat struct {
				Status string `xml:"D:status"`
				Prop   struct {
					ResourceType string    `xml:"D:resourcetype"`
					LastModified time.Time `xml:"D:getlastmodified"`
					ContentType  string    `xml:"D:getcontenttype"`
					ContentLen   int64     `xml:"D:getcontentlength"`
				} `xml:"D:prop"`
			} `xml:"D:propstat"`
		}{
			Href: path.Join(r.URL.Path, "Please upload your file"),
			PropStat: struct {
				Status string `xml:"D:status"`
				Prop   struct {
					ResourceType string    `xml:"D:resourcetype"`
					LastModified time.Time `xml:"D:getlastmodified"`
					ContentType  string    `xml:"D:getcontenttype"`
					ContentLen   int64     `xml:"D:getcontentlength"`
				} `xml:"D:prop"`
			}{
				Status: "HTTP/1.1 200 OK",
				Prop: struct {
					ResourceType string    `xml:"D:resourcetype"`
					LastModified time.Time `xml:"D:getlastmodified"`
					ContentType  string    `xml:"D:getcontenttype"`
					ContentLen   int64     `xml:"D:getcontentlength"`
				}{
					ResourceType: "",
					LastModified: time.Now().UTC(),
					ContentType:  "text/plain",
					ContentLen:   24, // Length of "Please upload your file"
				},
			},
		})
	}

	// Write response
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(response); err != nil {
		log.Printf("Error encoding PROPFIND response: %v", err)
	}
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
	if err := validateFilePath(filename); err != nil {
		writeWebDAVError(w, fmt.Errorf("invalid file: %w", err))
		return
	}

	// Read the entire file into memory with size limit
	limitedReader := io.LimitReader(r.Body, maxFileSize)
	fileData, err := io.ReadAll(limitedReader)
	if err != nil {
		writeWebDAVError(w, fmt.Errorf("failed to read file: %w", err))
		return
	}

	// Check if file size exceeds limit
	if len(fileData) >= maxFileSize {
		writeWebDAVError(w, ErrFileTooLarge)
		return
	}

	// Upload file to S3
	err = h.s3Client.UploadFile(r.Context(), userID, filename, bytes.NewReader(fileData))
	if err != nil {
		writeWebDAVError(w, fmt.Errorf("failed to upload file: %w", err))
		return
	}

	// Log successful upload
	h.auditLogger.LogUpload(true, filename, int64(len(fileData)), r)

	// Return success
	w.WriteHeader(http.StatusCreated)
}

// authenticate handles Basic Authentication and returns the userID if successful.
// It writes the appropriate error response if authentication fails.
func (h *WebDAVHandler) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		// Log initial auth challenge at INFO level
		h.auditLogger.LogAuthAttempt(false, "", r)
		return "", false
	}

	authResult, err := h.auth.Authenticate(r.Context(), username, password)
	if err != nil || !authResult.Authenticated {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		h.auditLogger.LogAuthAttempt(false, username, r)
		return "", false
	}

	h.auditLogger.LogAuthAttempt(true, username, r)
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

// validateFilePath validates the file path and extension
func validateFilePath(filename string) error {
	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(filename)
	if cleanPath != filename {
		return fmt.Errorf("invalid file path: path traversal detected")
	}

	// Check for valid file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if !isAllowedExtension(ext) {
		return fmt.Errorf("invalid file extension: %s", ext)
	}

	return nil
}

// isAllowedExtension checks if the file extension is allowed
func isAllowedExtension(ext string) bool {
	allowedExtensions := map[string]bool{
		".txt":  true,
		".pdf":  true,
		".doc":  true,
		".docx": true,
		".xls":  true,
		".xlsx": true,
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".zip":  true,
		".csv":  true,
	}
	return allowedExtensions[ext]
}

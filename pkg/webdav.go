package pkg

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/webdav"
)

// Common errors
var (
	ErrInvalidFilename = fmt.Errorf("invalid filename")
)

// WebDAVHandler handles WebDAV requests, supporting only PUT operations
// for file uploads to S3 storage.
type WebDAVHandler struct {
	auth     AuthenticatorInterface
	s3Client S3Interface
	webdav   *webdav.Handler
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
		webdav: &webdav.Handler{
			FileSystem: webdav.NewMemFS(),
			LockSystem: webdav.NewMemLS(),
		},
	}
}

// ServeHTTP implements http.Handler interface.
// It handles authentication and routes PUT requests to handlePut.
func (h *WebDAVHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow PUT operations
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate request
	userID, ok := h.authenticate(w, r)
	if !ok {
		return // Response already written by authenticate
	}

	h.handlePut(w, r, userID)
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

// handlePut processes PUT requests by uploading the file to S3.
// The file is stored in the "incoming/{userID}/{filename}" path.
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, userID string) {
	// Ensure the request body is always closed
	defer r.Body.Close()

	// Extract and validate filename
	filename := strings.TrimPrefix(r.URL.Path, "/")
	if filename == "" {
		http.Error(w, ErrInvalidFilename.Error(), http.StatusBadRequest)
		return
	}

	// Validate file path and extension
	if err := ValidateFilePath(filename); err != nil {
		http.Error(w, fmt.Sprintf("Invalid file: %v", err), http.StatusBadRequest)
		return
	}

	// Limit file size and handle upload
	limitedReader := io.LimitReader(r.Body, MaxFileSize)
	if err := h.s3Client.UploadFile(r.Context(), userID, filename, limitedReader); err != nil {
		// Log the error but don't expose internal details
		log.Printf("Failed to upload file: %v", err)
		http.Error(w, "Failed to upload file", http.StatusInternalServerError)
		return
	}

	// Set appropriate response headers
	w.Header().Set("Location", "/"+filename)
	w.WriteHeader(http.StatusCreated)
}

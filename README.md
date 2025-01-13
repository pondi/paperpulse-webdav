# PulseDAV

A WebDAV package that provides secure file upload functionality with S3-compatible storage backend.

## Features

- WebDAV server implementation supporting only PUT operations
- S3-compatible storage backend
- Basic authentication with external API integration
- Built-in security features:
  - File size limits
  - Rate limiting
  - File extension validation
  - Path traversal protection
  - Security headers
  - Request logging

## Installation

```bash
go get github.com/pondi/pulsedav
```

## Configuration

Set the following environment variables:

Required:
- `AUTH_API_URL`: Authentication API endpoint
- `S3_BUCKET`: S3 bucket name

Optional:
- `S3_ENDPOINT`: Custom S3 endpoint URL
- `S3_REGION`: S3 region (default: us-east-1)
- `S3_ACCESS_KEY`: S3 access key
- `S3_SECRET_KEY`: S3 secret key
- `S3_SESSION_TOKEN`: Session token
- `S3_FORCE_PATH_STYLE`: Use path-style S3 URLs (default: false)

## Usage

Import and use the package in your Go application:

```go
package main

import (
    "log"
    "net/http"
    "github.com/pondi/pulsedav"
)

func main() {
    server, err := pulsedav.NewDefaultServer()
    if err != nil {
        log.Fatal(err)
    }

    // Use as an HTTP handler
    http.Handle("/webdav/", server)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Authentication API Requirements

Your authentication endpoint should:

1. Accept POST requests with:
```json
{
    "username": "string",
    "password": "string"
}
```

2. Return on success (HTTP 200):
```json
{
    "user_id": 123,
    "username": "string"
}
```

## File Storage

Files are stored in S3 using the path: `incoming/{userID}/{filename}`

## License

MIT License - see LICENSE file for details 
# PulseDAV

A standalone WebDAV server with S3-compatible storage backend, focusing on secure file uploads.

## Features

- WebDAV server implementation supporting only PUT operations
- S3-compatible storage backend
- Dual authentication modes:
  - External API authentication
  - Local user authentication
- Built-in security features:
  - File size limits
  - Rate limiting
  - File extension validation
  - Path traversal protection
  - Security headers
  - Request logging

## Installation

```bash
git clone https://github.com/pondi/pulsedav
cd pulsedav
go mod download
```

## Configuration

Create a `.env` file in the project root or set the following environment variables:

Required:
- `S3_BUCKET`: S3 bucket name
- `API_AUTH`: Set to "true" to use API authentication, "false" for local authentication

When using API authentication (`API_AUTH=true`):
- `AUTH_API_URL`: Authentication API endpoint

When using local authentication (`API_AUTH=false`):
- `LOCAL_AUTH_USERNAME`: Username for local authentication
- `LOCAL_AUTH_PASSWORD`: Password for local authentication
- `LOCAL_AUTH_USER_ID`: User ID for local authentication (optional, defaults to "1")

Optional Configuration:
- `PORT`: Server port number (default: 80)

Optional S3 Configuration:
- `S3_ENDPOINT`: Custom S3 endpoint URL
- `S3_REGION`: S3 region (default: us-east-1)
- `S3_ACCESS_KEY`: S3 access key
- `S3_SECRET_KEY`: S3 secret key
- `S3_SESSION_TOKEN`: Session token
- `S3_FORCE_PATH_STYLE`: Use path-style S3 URLs (default: false)

Example `.env` file for API authentication:
```env
API_AUTH=true
AUTH_API_URL=http://your-auth-api
PORT=8080
S3_BUCKET=your-bucket
S3_REGION=your-region
S3_ENDPOINT=your-endpoint
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
```

Example `.env` file for local authentication:
```env
API_AUTH=false
LOCAL_AUTH_USERNAME=admin
LOCAL_AUTH_PASSWORD=secret
LOCAL_AUTH_USER_ID=1000
PORT=8080
S3_BUCKET=your-bucket
S3_REGION=your-region
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
```

## Usage

Run the server:

```bash
go run main.go
```

The server will start with the following default settings:
- Address: :80 (unless specified by PORT environment variable)
- Read timeout: 30 seconds
- Write timeout: 30 seconds
- Idle timeout: 120 seconds
- Max file size: 100MB
- Rate limit: 100 requests per minute

## Authentication API Requirements

When using API authentication (`API_AUTH=true`), your authentication endpoint should:

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

## Supported File Types

The following file extensions are allowed:
- Documents: .txt, .pdf, .doc, .docx
- Spreadsheets: .xls, .xlsx
- Images: .jpg, .jpeg, .png, .gif
- Archives: .zip
- Data: .csv

## License

MIT License - see LICENSE file for details 
## [2.0.1](https://github.com/pondi/pulsedav/compare/v2.0.0...v2.0.1) (2025-02-13)


### Bug Fixes

* Update dependencies and test configurations ([2d37f5f](https://github.com/pondi/pulsedav/commit/2d37f5f186bf7330c6e1e28afe22cd582e850c1b))

# [2.0.0](https://github.com/pondi/pulsedav/compare/v1.0.0...v2.0.0) (2025-02-13)


### Features

* transform from Go package to independent WebDAV runtime ([574aa90](https://github.com/pondi/pulsedav/commit/574aa902115c40854682c2b56c68c1effaac0bdb))


### BREAKING CHANGES

* Complete transformation from importable Go package to standalone WebDAV runtime

- Completely restructured from Go package to standalone WebDAV runtime
- Updated go.mod to use compatible dependency versions
- Refactored authentication to support both API and local authentication modes
- Improved security middleware with enhanced headers and path validation
- Added robust error handling for WebDAV operations
- Implemented rate limiting and brute force protection
- Enhanced PROPFIND and OPTIONS request handling
- Simplified main package structure and configuration management
* This fundamentally changes how the software is used:
- No longer importable as a Go package
- Now runs as an independent WebDAV server runtime
- Requires different configuration and deployment approach

# 1.0.0 (2025-01-13)


### Features

* Add Docker setup for Alpine WebDAV server with S3 upload functionality ([f003e46](https://github.com/pondi/pulsedav/commit/f003e463430b193f6643af47e89ad7e58fbc5c10))
* Implement WebDAV server with S3 backend and authentication ([9eb2abb](https://github.com/pondi/pulsedav/commit/9eb2abbc35efa5a9698d3c2f1be5d5e97cd342fc))

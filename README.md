# AI-Cart-Auth

A lightweight, secure OAuth 2.0 authentication service supporting multiple providers (Google, GitHub, LinkedIn, Facebook) with standardized user data output.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Build Status](https://github.com/rakibhoossain/ai-cart-auth/workflows/Build%20and%20Release/badge.svg)](https://github.com/rakibhoossain/ai-cart-auth/actions)

## Features

- 🔐 **Multi-Provider OAuth Support**: Google, GitHub, LinkedIn, and Facebook
- 📊 **Standardized User Data**: Consistent user object format across all providers
- 🔒 **Secure JWT Signing**: HMAC-SHA256 signed tokens
- 🚀 **Lightweight**: Single binary with no external dependencies
- 🐳 **Docker Ready**: Includes Dockerfile and docker-compose
- 🌍 **Cross-Platform**: Pre-built binaries for Linux, macOS, and Windows
- ⚡ **Fast**: Built with Go for optimal performance
- 🛡️ **Error Handling**: Graceful error redirects with detailed error codes

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [User Data Format](#user-data-format)
- [Deployment](#deployment)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

### Using Docker

```bash
# Clone the repository
git clone https://github.com/rakibhoossain/ai-cart-auth.git
cd ai-cart-auth

# Copy and configure environment variables
cp env.example .env
# Edit .env with your OAuth credentials

# Run with Docker Compose
docker-compose up -d
```

### Using Pre-built Binary

```bash
# Download the latest release for your platform
# Linux AMD64
wget https://github.com/rakibhoossain/ai-cart-auth/releases/latest/download/ai-cart-auth-linux-amd64
chmod +x ai-cart-auth-linux-amd64

# macOS ARM64 (Apple Silicon)
wget https://github.com/rakibhoossain/ai-cart-auth/releases/latest/download/ai-cart-auth-darwin-arm64
chmod +x ai-cart-auth-darwin-arm64

# Windows AMD64
# Download ai-cart-auth-windows-amd64.exe from releases page

# Configure environment
cp env.example .env
# Edit .env with your credentials

# Run the service (Linux/macOS)
./ai-cart-auth-linux-amd64
# or
./ai-cart-auth-darwin-arm64

# Windows
# ai-cart-auth-windows-amd64.exe
```

## Installation

### Prerequisites

- Go 1.25 or higher (for building from source)
- OAuth credentials from your chosen providers
- A domain or public URL for OAuth callbacks

### From Source

```bash
# Clone the repository
git clone https://github.com/rakibhoossain/ai-cart-auth.git
cd ai-cart-auth

# Install dependencies
go mod download

# Build
go build -o ai-cart-auth .

# Or use Make
make build
```

### Using Go Install

```bash
go install github.com/rakibhoossain/ai-cart-auth@latest
```

## Configuration

### Environment Variables

Create a `.env` file in the project root (use `env.example` as a template):

```bash
# Server Configuration
PORT=8080
APP_URL=https://auth.yourdomain.com

# Security (minimum 32 characters)
OAUTH_SIGNING_SECRET=your_super_secret_random_string_min_32_chars

# Google OAuth (optional)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

# GitHub OAuth (optional)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# LinkedIn OAuth (optional)
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret

# Facebook OAuth (optional)
FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret
```

### Obtaining OAuth Credentials

#### Google
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project or select existing
3. Create OAuth 2.0 credentials
4. Add authorized redirect URI: `https://your-domain.com/callback/google`

#### GitHub
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set callback URL: `https://your-domain.com/callback/github`

#### LinkedIn
1. Go to [LinkedIn Developers](https://www.linkedin.com/developers/apps)
2. Create a new app
3. Add redirect URL: `https://your-domain.com/callback/linkedin`

#### Facebook
1. Go to [Facebook Developers](https://developers.facebook.com/apps)
2. Create a new app
3. Add OAuth redirect URI: `https://your-domain.com/callback/facebook`

## Usage

### Starting the Server

```bash
# Using the binary
./ai-cart-auth

# Using Go
go run .

# Using Make
make run

# Using Docker
docker-compose up
```

The server will start on the configured PORT (default: 8080).

### Authentication Flow

1. **Initiate Login**: Redirect user to `/login/{provider}?redirect={your_callback_url}`
   ```
   https://auth.yourdomain.com/login/google?redirect=https://yourapp.com/auth/callback
   ```

2. **User Authenticates**: User is redirected to the OAuth provider

3. **Callback**: After authentication, user is redirected back to your callback URL with the JWT payload:
   ```
   https://yourapp.com/auth/callback?oauthPayload=eyJhbGc...
   ```

4. **Decode JWT**: Decode and verify the JWT to get user information

### Error Handling

On authentication failure, users are redirected to your callback URL with error parameters:

```
https://yourapp.com/auth/callback?error=token_exchange_failed&error_description=Failed+to+exchange+authorization+code
```

Common error codes:
- `invalid_request`: Missing required parameters
- `token_exchange_failed`: Failed to exchange authorization code
- `user_info_failed`: Failed to fetch user information
- `jwt_signing_failed`: Failed to create authentication token

## API Endpoints

### Health Check
```
GET /health
```

Returns server health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "time": "2025-01-15T10:30:00Z"
}
```

### Login
```
GET /login/{provider}?redirect={callback_url}
```

Initiates OAuth flow for the specified provider.

**Parameters:**
- `provider` (path): One of `google`, `github`, `linkedin`, `facebook`
- `redirect` (query): Your application's callback URL (must be a valid HTTPS URL)

**Example:**
```
GET /login/google?redirect=https://yourapp.com/auth/callback
```

### Callback
```
GET /callback/{provider}
```

OAuth provider callback endpoint (handled automatically).

## User Data Format

All providers return a standardized user object:

```json
{
  "provider": "google",
  "user": {
    "email": "user@example.com",
    "name": "John Doe",
    "first_name": "John",
    "last_name": "Doe",
    "photo": "https://example.com/photo.jpg",
    "provider": "google",
    "provider_id": "1234567890"
  },
  "token": "ya29.a0AfH6SMB...",
  "exp": 1642248000
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | User's email address |
| `name` | string | Full name |
| `first_name` | string | First name (given name) |
| `last_name` | string | Last name (family name) |
| `photo` | string | Profile picture URL |
| `provider` | string | OAuth provider name |
| `provider_id` | string | Unique user ID from the provider |
| `token` | string | OAuth access token |
| `exp` | number | JWT expiration timestamp (Unix) |

### Provider-Specific Notes

- **Google**: Provides all fields natively
- **GitHub**: Name is split into first/last name automatically
- **LinkedIn**: Uses OpenID Connect userinfo endpoint
- **Facebook**: Name is split into first/last name automatically

## Deployment

### Production Deployment

#### Using Docker

```bash
# Build the image
docker build -t ai-cart-auth:latest .

# Run the container
docker run -d \
  --name ai-cart-auth \
  -p 8080:8080 \
  --env-file .env \
  ai-cart-auth:latest
```

#### Using Docker Compose

```bash
docker-compose up -d
```

#### Using Systemd (Linux)

Create `/etc/systemd/system/ai-cart-auth.service`:

```ini
[Unit]
Description=ai-cart-auth OAuth Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/ai-cart-auth
EnvironmentFile=/opt/ai-cart-auth/.env
ExecStart=/opt/ai-cart-auth/ai-cart-auth
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable ai-cart-auth
sudo systemctl start ai-cart-auth
sudo systemctl status ai-cart-auth
```

### Reverse Proxy Setup

#### Nginx

```nginx
server {
    listen 80;
    server_name auth.yourdomain.com;

    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Caddy

```
auth.yourdomain.com {
    reverse_proxy localhost:8080
}
```

### Cloud Deployment

#### Heroku

```bash
# Create app
heroku create your-auth-app

# Set environment variables
heroku config:set APP_URL=https://your-auth-app.herokuapp.com
heroku config:set OAUTH_SIGNING_SECRET=your_secret
heroku config:set GOOGLE_CLIENT_ID=your_id
# ... set other variables

# Deploy
git push heroku main
```

#### Railway

1. Connect your GitHub repository
2. Add environment variables in the Railway dashboard
3. Deploy automatically on push

#### DigitalOcean App Platform

1. Create a new app from your repository
2. Set environment variables
3. Deploy

## Development

### Prerequisites

- Go 1.25+
- Make (optional)
- Docker (optional)

### Setup

```bash
# Clone repository
git clone https://github.com/rakibhoossain/ai-cart-auth.git
cd ai-cart-auth

# Install dependencies
make install

# Copy environment file
cp env.example .env
# Edit .env with your credentials

# Run in development mode
make dev
```

### Available Make Commands

```bash
make help          # Show all available commands
make build         # Build for current platform
make build-all     # Build for all platforms
make run           # Run the application
make dev           # Run with auto-reload
make test          # Run tests
make clean         # Clean build artifacts
make fmt           # Format code
make lint          # Run linter
make docker-build  # Build Docker image
make docker-run    # Run Docker container
```

### Project Structure

```
ai-cart-auth/
├── main.go              # Main application code
├── go.mod               # Go module definition
├── go.sum               # Go module checksums
├── .env                 # Environment variables (not in git)
├── env.example          # Environment template
├── Dockerfile           # Docker image definition
├── docker-compose.yml   # Docker Compose configuration
├── Makefile             # Build automation
├── build.sh             # Multi-platform build script
├── README.md            # This file
├── LICENSE              # MIT License
└── .github/
    └── workflows/
        └── release.yml  # GitHub Actions workflow
```

### Testing

```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -v -cover ./...

# Run specific test
go test -v -run TestFunctionName
```

### Building for Production

```bash
# Build optimized binary
go build -ldflags="-s -w" -o ai-cart-auth .

# Build for all platforms
./build.sh

# Or use Make
make build-all
```

## Security Considerations

### Best Practices

1. **Use HTTPS**: Always deploy behind HTTPS in production
2. **Strong Secret**: Use a cryptographically secure random string for `OAUTH_SIGNING_SECRET` (minimum 32 characters)
3. **Environment Variables**: Never commit `.env` file to version control
4. **Redirect URL Validation**: The service validates redirect URLs to prevent open redirects
5. **JWT Expiration**: Tokens expire after 1 minute by default
6. **Regular Updates**: Keep dependencies updated

### Generating Secure Secrets

```bash
# Generate a secure random secret
openssl rand -base64 32

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Or using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

### Optional: Whitelist Redirect Hosts

Add to your `.env`:

```bash
ALLOWED_REDIRECT_HOSTS=yourapp.com,app.yourapp.com,staging.yourapp.com
```

## Troubleshooting

### Common Issues

#### "No OAuth providers configured"

**Solution**: Ensure at least one provider's `CLIENT_ID` and `CLIENT_SECRET` are set in your `.env` file.

#### "OAUTH_SIGNING_SECRET must be at least 32 characters long"

**Solution**: Generate a longer secret using one of the methods in [Security Considerations](#security-considerations).

#### OAuth callback fails with "redirect_uri_mismatch"

**Solution**: Ensure the callback URL in your OAuth provider settings matches exactly:
```
https://your-domain.com/callback/{provider}
```

#### "Invalid redirect URL"

**Solution**: Ensure your redirect parameter is a valid HTTPS URL with a proper scheme and host.

### Debug Mode

Enable detailed logging:

```bash
# Set log level (if implemented)
export LOG_LEVEL=debug
./ai-cart-auth
```

### Health Check

```bash
# Check if service is running
curl http://localhost:8080/health

# Expected response
{"status":"healthy","version":"1.0.0","time":"2025-01-15T10:30:00Z"}
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Go best practices and conventions
- Add tests for new features
- Update documentation as needed
- Run `make fmt` before committing
- Ensure all tests pass with `make test`

## Changelog

### Version 1.0.0 (2025-01-15)

- ✨ Initial release
- 🔐 Multi-provider OAuth support (Google, GitHub, LinkedIn, Facebook)
- 📊 Standardized user data format
- 🔒 JWT token signing
- 🚀 Multi-platform binaries
- 🐳 Docker support
- 📝 Comprehensive documentation

## Roadmap

- [ ] Add more OAuth providers (Twitter, Microsoft, Apple)
- [ ] Implement token refresh mechanism
- [ ] Add rate limiting
- [ ] Add metrics and monitoring endpoints
- [ ] Add user session management
- [ ] Add webhook support for auth events
- [ ] Add admin dashboard

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Rakib Hossain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Support

- 📧 Email: rakibhoossain@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/rakibhoossain/ai-cart-auth/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/rakibhoossain/ai-cart-auth/discussions)

## Acknowledgments

- Built with [Go](https://golang.org/)
- OAuth2 library: [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2)
- Environment management: [godotenv](https://github.com/joho/godotenv)

## Related Projects

- [AI Cart](https://github.com/rakibhoossain/ai-cart) - The main AI Cart application
- [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy) - Alternative OAuth proxy

---

**Made with ❤️ for the AI Cart project**

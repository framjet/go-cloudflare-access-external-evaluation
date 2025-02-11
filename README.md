# Cloudflare Access External Evaluation

A Go server for external evaluation of Cloudflare Access Policy using "expr-lang" expressions on user token.

## Features

- External evaluation of Cloudflare Access tokens using [`expr-lang`](https://expr-lang.org/docs/language-definition) expressions
- LRU caching for compiled expressions
- Easy configuration via environment variables or CLI flags
- Prometheus metrics endpoint for monitoring
- Rate limiting for API endpoints
- Configurable expression cache size
- Auto-generated RSA keys in Docker container

## Quick Start

### Using Docker

```bash
# Basic usage (auto-generates RSA keys)
docker run -p 8000:8000 \
  -e JWK_URL=https://<team_name>.cloudflareaccess.com/cdn-cgi/access/certs \
  framjet/cloudflare-access-external-evaluation

# With custom RSA keys and additional configuration
docker run -p 8000:8000 \
  -e JWK_URL=https://<team_name>.cloudflareaccess.com/cdn-cgi/access/certs \
  -e PRIVATE_KEY=/keys/private.pem \
  -e PUBLIC_KEY=/keys/public.pem \
  -e CACHE_SIZE=200 \
  -e RATE_LIMIT=100 \
  -e TOKEN_EXPIRATION=120s \
  -v /path/to/your/keys:/keys \
  framjet/cloudflare-access-external-evaluation
```

Note: The Docker container will automatically generate new RSA keys on each start if they're not provided. This is suitable for most use cases as the keys are only used to verify that responses were sent from this server.

### Building from Source

1. Clone the repository
```bash
git clone https://github.com/framjet/go-cloudflare-access-external-evaluation.git
cd go-cloudflare-access-external-evaluation
```

2. Build the binary
```bash
go build -o framjet-cfa-ex-eval ./cmd/framjet-cfa-ex-eval
```

3. Run the server
```bash
./framjet-cfa-ex-eval \
  --jwk=https://<team_name>.cloudflareaccess.com/cdn-cgi/access/certs \
  --private-key=/path/to/private.pem \
  --public-key=/path/to/public.pem
```

## Configuration

### Environment Variables

- `JWK_URL` - URL to fetch JWK set for verifying incoming tokens
- `PRIVATE_KEY` - Path to private PEM key used for signing tokens (optional in Docker)
- `PUBLIC_KEY` - Path to public PEM key (optional in Docker)
- `HTTP_HOST` - HTTP server host (default: "0.0.0.0")
- `HTTP_PORT` - HTTP server port (default: 8000)
- `CACHE_SIZE` - Size of the compiled expression cache (default: 100)
- `RATE_LIMIT` - Rate limit for the API in requests per second (default: 50)
- `TOKEN_EXPIRATION` - Expiration time for signed tokens (default: 60s)

### CLI Flags

- `--jwk` - Same as JWK_URL
- `--private-key` - Same as PRIVATE_KEY
- `--public-key` - Same as PUBLIC_KEY
- `--host` - Same as HTTP_HOST
- `--port` - Same as HTTP_PORT
- `--cache-size` - Same as CACHE_SIZE
- `--rate-limit` - Same as RATE_LIMIT
- `--token-expiration` - Same as TOKEN_EXPIRATION
- `--log-level` - Set log level (debug, info, warn, error, fatal, panic)
- `--verbose` - Enable verbose logging
- `--quiet` - Disable all logging

## API Endpoints

### GET `/metrics`
Prometheus metrics endpoint providing operational metrics like request counts, latencies, and cache statistics.

### GET `/status`
Health check endpoint returning server status and uptime information.

### GET `/keys`
Returns the public key information used for token verification.

### POST `/{expr}`
Evaluates the base64-encoded expr-lang expression against the provided token.

Request body:
```json
{
  "token": "your.jwt.token"
}
```

## Example Usage

1. Generate RSA key pair:
```bash
# Generate private key
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private.pem -out public.pem
```

2. Start the server:
```bash
./framjet-cfa-ex-eval \
  --jwk=https://your-team.cloudflareaccess.com/cdn-cgi/access/certs \
  --private-key=private.pem \
  --public-key=public.pem
```

3. Make a request:
```bash
curl -X POST http://localhost:8000/ZW1haWwuZW5kc1dpdGgoIkBjb21wYW55LmNvbSIp \
  -H "Content-Type: application/json" \
  -d '{"token": "your.jwt.token"}'
```

## License

MIT License - see the [LICENSE](LICENSE) file for details.
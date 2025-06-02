# Minimal OAuth2 M2M FastAPI Server

This project is a minimal OAuth2 server for machine-to-machine (M2M) authentication using FastAPI and Authlib, issuing JWT access tokens with custom claims.

## Features

- OAuth2 `client_credentials` grant
- JWT access tokens with custom claims (`fhirUser`, `azp`, `scp`, `name`, `email`)
- In-memory client "database" with per-client algorithm (`HS256` or `RS256`)
- RS256 and HS256 signing supported
- Auto-generation of RSA keypair for RS256 if needed
- OpenID Connect discovery endpoint
- JWKS endpoint for RS256 public key
- `/userinfo` and `/introspect` endpoints

## Setup

1. **Install dependencies**  
   (If not using Docker, install Python dependencies manually)
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the server**
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000
   ```
   Or use the provided Dockerfile.

## Environment Variables

- `JWT_SECRET` - Secret for signing HS256 JWTs (default: demo value)
- `ISSUER_URL` - Issuer URL for tokens and discovery (default: `http://localhost:8000`)
- `RS256_PRIVATE_KEY_PATH` - Path to RS256 private key PEM file (default: `/workspaces/oauth_tmp/private_key.pem`)
- `RS256_PUBLIC_KEY_PATH` - Path to RS256 public key PEM file (default: `/workspaces/oauth_tmp/public_key.pem`)
    - Set either to `auto-gen` to auto-generate a keypair at `/tmp/auto_private_key.pem` and `/tmp/auto_public_key.pem`

## Endpoints

### `POST /token`

Obtain a JWT access token using the `client_credentials` grant.

**Example:**
```bash
curl -X POST http://localhost:8000/token \
  -d 'grant_type=client_credentials' \
  -d 'client_id=m2m-client' \
  -d 'client_secret=m2m-secret'
```

### `GET /.well-known/openid-configuration`

OpenID Connect discovery endpoint (pretty-printed JSON).

### `GET /.well-known/jwks.json`

JWKS endpoint for RS256 public key.

### `POST /introspect`

Token introspection endpoint.

### `GET /userinfo`

Userinfo endpoint (requires Bearer token).

## Notes

- This is a minimal, demo-only implementation. Do not use in production.
- No persistent storage; all data is in-memory.
- Only the `client_credentials` grant is supported.
- For RS256, public/private keys can be auto-generated if needed.

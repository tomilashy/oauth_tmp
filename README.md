# Minimal OAuth2 M2M FastAPI Server

This project is a minimal OAuth2 server for machine-to-machine (M2M) authentication using FastAPI and Authlib, issuing JWT access tokens with custom claims.

## Features

- OAuth2 `client_credentials` grant
- JWT access tokens with custom claims (`fhirUser`, `azp`, `scp`, `name`, `email`)
- In-memory client "database"
- OpenID Connect discovery endpoint

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

### `GET /.well-known`

List registered clients.

### `GET /.well-known/openid-configuration`

OpenID Connect discovery endpoint.

## Environment Variables

- `JWT_SECRET` - Secret for signing JWTs (default: demo value)
- `ISSUER_URL` - Issuer URL for tokens and discovery (default: `http://localhost:8000`)

## Notes

- This is a minimal, demo-only implementation. Do not use in production.
- No persistent storage; all data is in-memory.
- Only the `client_credentials` grant is supported.

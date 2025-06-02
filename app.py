from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import JSONResponse
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import grants, AuthorizationServer
from authlib.jose import jwt
import os
import time

app = FastAPI()

# In-memory client "database"
clients = {
    "m2m-client": {
        "client_secret": "m2m-secret",
        "scopes": "user/*.read user/*.write",
        "fhirUser": "Practitioner/123",
        "azp": "emr-backend",
        "name": "Machine Client",
        "email": "machine@example.com"
    }
}

JWT_SECRET = os.getenv("JWT_SECRET", "O6cbMeZS6w190es3kg1dTDqOsuK3psex_ggYJYEzFxU")
JWT_ALG = "HS256"
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000")


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    def authenticate_client(self):
        client_id = self.request.form.get("client_id")
        client_secret = self.request.form.get("client_secret")
        if client_id is None:
            return None
        client = clients.get(client_id)
        if client and client["client_secret"] == client_secret:
            self.request.client = client
            self.request.client_id = client_id
            return client
        return None

    def save_token(self, token_data, request):
        # Skipping DB storage in this minimal example
        pass

    def create_access_token(self, token, client, grant_user):
        now = int(time.time())
        claims = {
            "iss": ISSUER_URL,
            # Standard claims
            "sub": client["fhirUser"],  # subject is the fhirUser
            "aud": client["azp"],       # audience is the authorized party
            "iat": now,
            "exp": now + 3600,
            # Custom claims
            "azp": client["azp"],
            "scp": client["scopes"],
            "fhirUser": client["fhirUser"],  # custom claim for fhirUser
            "name": client.get("name"),
            "email": client.get("email"),
        }
        encoded = jwt.encode({"alg": JWT_ALG}, claims, JWT_SECRET)
        token["access_token"] = encoded.decode() if hasattr(encoded, 'decode') else encoded
        token["token_type"] = "bearer"
        token["expires_in"] = 3600
        return token


authorization = AuthorizationServer()
authorization.register_grant(ClientCredentialsGrant)


@app.post("/token")
async def token(request: Request):
    form = await request.form()
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    grant_type = form.get("grant_type")
    scope = form.get("scope")

    # Only support client_credentials
    if grant_type != "client_credentials":
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    client = clients.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    now = int(time.time())
    claims = {
        "iss": ISSUER_URL,
        "sub": client["fhirUser"],
        "aud": client["azp"],
        "iat": now,
        "exp": now + 3600,
        "azp": client["azp"],
        "scp": client["scopes"],
        "fhirUser": client["fhirUser"],
        "name": client.get("name"),
        "email": client.get("email"),
    }
    encoded = jwt.encode({"alg": JWT_ALG}, claims, JWT_SECRET)
    access_token = encoded.decode() if hasattr(encoded, 'decode') else encoded

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": client["scopes"]
    }



@app.get("/.well-known/openid-configuration")
def openid_configuration():
    return {
        "issuer": ISSUER_URL,
        "token_endpoint": f"{ISSUER_URL}/token",
        "jwks_uri": f"{ISSUER_URL}/.well-known/jwks.json",
        "grant_types_supported": ["client_credentials"],
        "response_types_supported": [],
        "scopes_supported": ["user/*.read", "user/*.write"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }


@app.get("/.well-known/jwks.json")
def jwks():
    # For HS256, JWKS is not strictly needed, but OIDC clients may expect it.
    # If you switch to RS256, return your public key here.
    return {"keys": []}


@app.post("/introspect")
async def introspect(request: Request):
    form = await request.form()
    token = form.get("token")
    if not token:
        return {"active": False}
    try:
        claims = jwt.decode(token, JWT_SECRET)
        # Optionally verify exp, iat, etc.
        now = int(time.time())
        if claims.get("exp", 0) < now:
            return {"active": False}
        return {
            "active": True,
            **claims
        }
    except Exception:
        return {"active": False}


@app.get("/userinfo")
async def userinfo(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    token = authorization.split(" ", 1)[1]
    try:
        claims = jwt.decode(token, JWT_SECRET)
        # Optionally verify exp, iat, etc.
        now = int(time.time())
        if claims.get("exp", 0) < now:
            return JSONResponse(status_code=401, content={"error": "token_expired"})
        # Return only user-related claims
        return {
            "sub": claims.get("sub"),
            "fhirUser": claims.get("fhirUser"),
            "azp": claims.get("azp"),
            "scp": claims.get("scp"),
            "name": claims.get("name"),
            "email": claims.get("email"),
        }
    except Exception:
        return JSONResponse(status_code=401, content={"error": "invalid_token"})

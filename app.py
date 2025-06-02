# app.py
from fastapi import FastAPI, Request, Depends
from authlib.integrations.starlette_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.jose import jwt
from starlette.responses import JSONResponse
from starlette.requests import Request
import time
import os

app = FastAPI()

# Dummy in-memory client store
clients = {
    "m2m-client": {
        "client_secret": "m2m-secret",
        "scopes": "user/*.read user/*.write",
        "fhirUser": "Practitioner/123",
        "azp": "emr-backend"
    }
}

# JWT signing key (use a real secret or asymmetric key in prod)
JWT_SECRET = JWT_SECRET = os.getenv("JWT_SECRET", "replace-this-in-prod")
JWT_ALG = "HS256"


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_post', 'client_secret_basic']

    def authenticate_client(self):
        client_id = self.request.form.get("client_id")
        client_secret = self.request.form.get("client_secret")
        client = clients.get(client_id)
        if client and client["client_secret"] == client_secret:
            self.request.client = client
            self.request.client_id = client_id
            return client
        return None

    def create_access_token(self, token, client, grant_user):
        # Add custom claims here in the JWT access token
        now = int(time.time())
        claims = {
            "iss": "https://your-auth-server.example.com",
            "sub": client["fhirUser"],
            "aud": client,
            "iat": now,
            "exp": now + 3600,
            "azp": client["azp"],
            "scp": client["scopes"],
            # add any other custom claims here
        }
        access_token = jwt.encode({"alg": JWT_ALG}, claims, JWT_SECRET)
        token["access_token"] = access_token.decode() if hasattr(access_token, 'decode') else access_token
        token["token_type"] = "bearer"
        token["expires_in"] = 3600
        return token


# Instantiate authorization server
authorization = AuthorizationServer()

authorization.register_grant(ClientCredentialsGrant)


@app.post("/token")
async def issue_token(request: Request):
    return await authorization.create_token_response(request)


@app.get("/protected")
async def protected(token: str = Depends()):
    # This endpoint would require token validation; simplified here
    return {"msg": "This is a protected resource"}


# Register the server with the FastAPI app
authorization.init_app(app)

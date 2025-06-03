from fastapi import FastAPI, Request, Form, Header
from fastapi.responses import JSONResponse, Response
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import grants, AuthorizationServer
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import time
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes

app = FastAPI()

# In-memory client "database"
clients = {
    "m2m-client": {
        "client_secret": "m2m-secret",
        "scopes": "user/*.read user/*.write",
        "fhirUser": "Practitioner/123",
        "azp": "emr-backend",
        "name": "Machine Client",
        "email": "machine@example.com",
        "alg": "RS256"
    },
    "m2m-hs256": {
        "client_secret": "m2m-hs256-secret",
        "scopes": "user/*.read user/*.write",
        "fhirUser": "Practitioner/456",
        "azp": "emr-backend",
        "name": "RS256 Client",
        "email": "rs256@example.com",
        "alg": "HS256"
    }
}

JWT_SECRET = os.getenv("JWT_SECRET", "O6cbMeZS6w190es3kg1dTDqOsuK3psex_ggYJYEzFxU")
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000")

# Load RS256 private key (PEM format) and public key for JWKS
RS256_PRIVATE_KEY_PATH = os.getenv("RS256_PRIVATE_KEY_PATH", "/workspaces/oauth_tmp/private_key.pem")
RS256_PUBLIC_KEY_PATH = os.getenv("RS256_PUBLIC_KEY_PATH", "/workspaces/oauth_tmp/public_key.pem")

def auto_generate_rsa_keypair():
    logging.info("Auto-generating RSA keypair for RS256...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv_path = "/tmp/auto_private_key.pem"
    pub_path = "/tmp/auto_public_key.pem"
    # Write private key
    with open(priv_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    # Write public key
    public_key = private_key.public_key()
    with open(pub_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    logging.info(f"RS256 private key generated at: {priv_path}")
    logging.info(f"RS256 public key generated at: {pub_path}")
    # Update environment variables for the rest of the app
    os.environ["RS256_PRIVATE_KEY_PATH"] = priv_path
    os.environ["RS256_PUBLIC_KEY_PATH"] = pub_path
    return priv_path, pub_path

# Auto-generate keys if requested
if RS256_PRIVATE_KEY_PATH == "auto-gen" or RS256_PUBLIC_KEY_PATH == "auto-gen":
    RS256_PRIVATE_KEY_PATH, RS256_PUBLIC_KEY_PATH = auto_generate_rsa_keypair()

def load_private_key():
    try:
        with open(RS256_PRIVATE_KEY_PATH, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        logging.error(f"Failed to load RS256 private key: {e}")
        return None

def load_public_key():
    try:
        with open(RS256_PUBLIC_KEY_PATH, "rb") as key_file:
            return serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except Exception as e:
        logging.error(f"Failed to load RS256 public key: {e}")
        return None

RS256_PRIVATE_KEY = load_private_key()
RS256_PUBLIC_KEY = load_public_key()

def get_jwk_from_public_key(pubkey):
    from cryptography.hazmat.primitives.asymmetric import rsa
    import base64
    import hashlib

    if not isinstance(pubkey, rsa.RSAPublicKey):
        return None
    numbers = pubkey.public_numbers()
    def b64(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode('utf-8')

    # Generate or load a self-signed cert for x5c/x5t
    cert_path = "/tmp/auto_public_cert.pem"
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    else:
        from datetime import datetime, timedelta
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, u"Demo RS256 Key"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pubkey)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .sign(RS256_PRIVATE_KEY, hashes.SHA256(), default_backend())
        )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode("utf-8")]
    x5t = base64.urlsafe_b64encode(hashlib.sha1(cert_der).digest()).rstrip(b'=').decode("utf-8")
    kid = x5t

    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')),
        "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')),
        "kid": kid,
        "x5t": x5t,
        "x5c": x5c
    }


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
        alg = client.get("alg", "HS256")
        if alg == "HS256":
            signing_key = JWT_SECRET
        elif alg == "RS256":
            signing_key = RS256_PRIVATE_KEY
        else:
            raise Exception("Unsupported signing algorithm")
        claims = {
            "iss": ISSUER_URL,
            # Standard claims
            "sub": client["fhirUser"],
            "aud": client["azp"],
            "iat": now,
            "exp": now + 3600,
            # Custom claims
            "azp": client["azp"],
            "scp": client["scopes"],
            "fhirUser": client["fhirUser"],
            "name": client.get("name"),
            "email": client.get("email"),
        }
        encoded = jwt.encode({"alg": alg}, claims, signing_key)
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

    if grant_type != "client_credentials":
        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type"})

    client = clients.get(client_id)
    if not client:
        return JSONResponse(status_code=401, content={"error": "invalid_client"})

    alg = client.get("alg", "HS256")
    if alg == "HS256":
        if client["client_secret"] != client_secret:
            return JSONResponse(status_code=401, content={"error": "invalid_client"})
        signing_key = JWT_SECRET
    elif alg == "RS256":
        if RS256_PRIVATE_KEY is None:
            return JSONResponse(status_code=500, content={"error": "server_rs256_key_missing"})
        signing_key = RS256_PRIVATE_KEY
    else:
        return JSONResponse(status_code=400, content={"error": "unsupported_alg"})

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
    encoded = jwt.encode({"alg": alg}, claims, signing_key)
    access_token = encoded.decode() if hasattr(encoded, 'decode') else encoded

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "scope": client["scopes"]
    }



@app.get("/.well-known/openid-configuration")
def openid_configuration():
    config = {
        "issuer": ISSUER_URL,
        "token_endpoint": f"{ISSUER_URL}/token",
        "userinfo_endpoint": f"{ISSUER_URL}/userinfo",
        "introspection_endpoint": f"{ISSUER_URL}/introspect",
        "jwks_uri": f"{ISSUER_URL}/.well-known/jwks.json",
        "grant_types_supported": ["client_credentials"],
        "response_types_supported": [],
        "scopes_supported": ["user/*.read", "user/*.write"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "HS256"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "subject_types_supported": ["public"],
        "claims_supported": [
            "sub", "fhirUser", "azp", "scp", "name", "email", "iss", "aud", "exp", "iat"
        ],
    }
    return Response(
        content=json.dumps(config, indent=2),
        media_type="application/json"
    )


@app.get("/.well-known/jwks.json")
def jwks():
    # Return RS256 public key if available, otherwise empty keys
    if RS256_PUBLIC_KEY:
        return {"keys": [get_jwk_from_public_key(RS256_PUBLIC_KEY)]}
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

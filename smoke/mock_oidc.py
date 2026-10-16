"""A tiny OpenID Connect provider for tests (never for real use): discovery, authorize (signs in
whoever the test set with POST /next-user, no login page), token (checks client secret, redirect
URI and PKCE), JWKS. id_tokens are RS256, signed with a throwaway key via the openssl CLI.

    python3 mock_oidc.py PORT CLIENT_ID CLIENT_SECRET
"""
import base64, hashlib, json, os, secrets, subprocess, sys, tempfile, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CLIENT_ID, CLIENT_SECRET = int(sys.argv[1]), sys.argv[2], sys.argv[3]
BASE = f"http://127.0.0.1:{PORT}"
KEY = os.path.join(tempfile.mkdtemp(), "key.pem")
subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", KEY], check=True, capture_output=True)
MODULUS = subprocess.run(["openssl", "rsa", "-in", KEY, "-noout", "-modulus"], check=True, capture_output=True, text=True).stdout.split("=")[1].strip()

def b64(data): return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
JWK = {"kty": "RSA", "kid": "test-key-1", "use": "sig", "alg": "RS256", "n": b64(bytes.fromhex(MODULUS)), "e": b64((65537).to_bytes(3, "big"))}

NEXT_USER = {"sub": "user-1", "email": "someone@example.test", "email_verified": True}
CODES = {}

def sign(claims):
    header = b64(json.dumps({"alg": "RS256", "kid": JWK["kid"], "typ": "JWT"}).encode())
    payload = b64(json.dumps(claims).encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY], input=f"{header}.{payload}".encode(), capture_output=True, check=True).stdout
    return f"{header}.{payload}.{b64(sig)}"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def send(self, status, body=None, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        data = json.dumps(body).encode() if body is not None else b""
        if body is not None: self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path); q = dict(urllib.parse.parse_qsl(url.query))
        if url.path == "/.well-known/openid-configuration":
            return self.send(200, {"issuer": BASE, "authorization_endpoint": BASE + "/authorize", "token_endpoint": BASE + "/token", "jwks_uri": BASE + "/jwks"})
        if url.path == "/jwks":
            return self.send(200, {"keys": [JWK]})
        if url.path == "/authorize":
            if q.get("client_id") != CLIENT_ID or q.get("code_challenge_method") != "S256" or "openid" not in q.get("scope", ""):
                return self.send(400, {"error": "invalid_request"})
            code = secrets.token_urlsafe(16)
            CODES[code] = {"redirect_uri": q["redirect_uri"], "challenge": q["code_challenge"], "nonce": q.get("nonce"), "user": dict(NEXT_USER)}
            sep = "&" if "?" in q["redirect_uri"] else "?"
            return self.send(302, headers={"Location": q["redirect_uri"] + sep + urllib.parse.urlencode({"code": code, "state": q.get("state", "")})})
        self.send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0)); raw = self.rfile.read(length).decode()
        if self.path == "/next-user":
            NEXT_USER.clear(); NEXT_USER.update(json.loads(raw)); return self.send(200, NEXT_USER)
        if self.path == "/token":
            f = dict(urllib.parse.parse_qsl(raw)); grant = CODES.pop(f.get("code", ""), None)
            if f.get("client_id") != CLIENT_ID or f.get("client_secret") != CLIENT_SECRET:
                return self.send(401, {"error": "invalid_client"})
            if not grant or grant["redirect_uri"] != f.get("redirect_uri"):
                return self.send(400, {"error": "invalid_grant"})
            if b64(hashlib.sha256(f.get("code_verifier", "").encode()).digest()) != grant["challenge"]:
                return self.send(400, {"error": "invalid_grant", "error_description": "PKCE"})
            now = int(time.time()); user = grant["user"]
            claims = {"iss": user.pop("iss", BASE), "aud": user.pop("aud", CLIENT_ID), "iat": now, "exp": now + 300, "nonce": user.pop("nonce", grant["nonce"]), **user}
            return self.send(200, {"access_token": secrets.token_urlsafe(16), "token_type": "Bearer", "id_token": sign(claims)})
        self.send(404, {"error": "not found"})

ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

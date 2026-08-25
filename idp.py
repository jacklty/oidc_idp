#!/usr/bin/env python3
"""Minimal OIDC identity provider for the STS lab.

Serves the three things AWS reads from a web identity provider:

  GET  /.well-known/openid-configuration   -> issuer discovery document
  GET  /.well-known/jwks.json              -> public signing key (JWKS)
  POST /token                              -> mint a signed JWT (guarded by a Bearer secret)

Run locally first; later put this behind a Cloudflare tunnel and point an
IAM OIDC provider at the public hostname so real STS can fetch the JWKS here.
"""

import argparse
import json
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import jwt as jwtlib

KID = "idp-rsa-2048-1"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--key-dir", default=str(Path(__file__).parent / "keys"))
    ap.add_argument("--issuer", default=None,
                    help="public issuer, e.g. https://your-tunnel.trycloudflare.com; "
                         "defaults to http://localhost:PORT")
    ap.add_argument("--secret", default="devsecret",
                    help="Bearer token required by POST /token (never expose this)")
    ap.add_argument("--cache", default="public, max-age=300",
                    help="Cache-Control header for JWKS/discovery; set to no-store to "
                         "force STS to fetch on every call (observe the difference)")
    args = ap.parse_args()

    key_dir = Path(args.key_dir)
    private_key = key_dir / "private.pem"
    public_key = key_dir / "public.pem"
    if not private_key.exists():
        sys.exit(f"missing {private_key} -- run ./gen_keys.sh first")

    issuer = args.issuer or f"http://localhost:{args.port}"

    class IdPHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # args = (requestline, status code, size). Behind a Cloudflare tunnel
            # the TCP peer is cloudflared itself, so the real client IP is only
            # available via the CF-Connecting-IP header (X-Forwarded-For as
            # fallback); direct localhost clients fall back to the socket peer.
            ip = (self.headers.get("CF-Connecting-IP")
                  or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or self.client_address[0])
            print(f"[req] {time.strftime('%H:%M:%S')} {ip} {fmt % args}",
                  file=sys.stderr, flush=True)

        def _send(self, code, obj):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", args.cache)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.rstrip("/")
            if path == "/.well-known/openid-configuration":
                self._send(200, {
                    "issuer": issuer,
                    "jwks_uri": f"{issuer}/.well-known/jwks.json",
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "response_types_supported": ["id_token"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                })
            elif path == "/.well-known/jwks.json":
                jwk = jwtlib.pem_to_jwk(public_key, KID)
                print(f"[idp] {time.strftime('%H:%M:%S')} JWKS fetch (kid={jwk['kid']})",
                      file=sys.stderr, flush=True)
                self._send(200, {"keys": [jwk]})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            if self.path.rstrip("/") != "/token":
                self._send(404, {"error": "not_found"})
                return
            if self.headers.get("Authorization") != f"Bearer {args.secret}":
                self._send(401, {"error": "unauthorized"})
                return
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            claims = json.loads(body or b"{}")
            payload = {
                "iss": issuer,
                "aud": claims.pop("aud", "sts.amazonaws.com"),
                "sub": claims.pop("sub", "lab-user"),
                "iat": int(time.time()),
                "exp": int(time.time()) + int(claims.pop("exp_ttl", 3600)),
                "jti": uuid.uuid4().hex,
            }
            payload.update(claims)
            token = jwtlib.sign_jwt({"alg": "RS256", "typ": "JWT", "kid": KID}, payload, private_key)
            self._send(200, {"token": token, "payload": payload})

    print(f"[idp] issuer   = {issuer}", file=sys.stderr)
    print(f"[idp] jwks_uri = {issuer}/.well-known/jwks.json", file=sys.stderr)
    print(f"[idp] /token   requires: Authorization: Bearer {args.secret}", file=sys.stderr)
    ThreadingHTTPServer(("0.0.0.0", args.port), IdPHandler).serve_forever()


if __name__ == "__main__":
    main()

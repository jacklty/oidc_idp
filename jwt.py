#!/usr/bin/env python3
"""RS256 JWT helpers built on openssl. Stdlib only, no pip dependencies.

Everything AWS's STS does to a web identity token is expressed here:
build the signing input, sign it, verify the signature, and export the
public key as a JWK (the shape served from /.well-known/jwks.json).
"""

import base64
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

from typing import Dict, Tuple


def b64url(data: bytes) -> str:
    """Base64url without padding, as used in JWTs."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def to_segment(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def sign_input(header: dict, payload: dict) -> bytes:
    """The exact bytes openssl signs: b64url(header).b64url(payload)."""
    return f"{to_segment(header)}.{to_segment(payload)}".encode("ascii")


def sign_jwt(header: dict, payload: dict, private_key) -> str:
    """Sign with RS256 and return the compact JWT string."""
    data = sign_input(header, payload)
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(private_key)],
        input=data,
        capture_output=True,
        check=True,
    ).stdout
    return f"{data.decode('ascii')}.{b64url(sig)}"


def verify_jwt(token: str, public_key) -> bool:
    """Verify an RS256 signature. This is the check STS performs with the
    key from your JWKS before it trusts anything in the token."""
    header_seg, payload_seg, sig_seg = token.split(".")
    data = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = b64url_decode(sig_seg)
    with tempfile.TemporaryDirectory() as td:
        sigf = Path(td) / "sig.bin"
        dataf = Path(td) / "data.bin"
        sigf.write_bytes(sig)
        dataf.write_bytes(data)
        proc = subprocess.run(
            [
                "openssl", "dgst", "-sha256", "-verify", str(public_key),
                "-signature", str(sigf), str(dataf),
            ],
            capture_output=True,
        )
    return proc.returncode == 0


def decode_jwt(token: str) -> Tuple[dict, dict]:
    """Decode (header, payload) without verifying — for inspection only."""
    header_seg, payload_seg, _ = token.split(".")
    header = json.loads(b64url_decode(header_seg))
    payload = json.loads(b64url_decode(payload_seg))
    return header, payload


def pem_to_jwk(public_key) -> dict:
    """Convert an RSA public PEM to a JWK with a derived key identifier."""
    out = subprocess.run(
        ["openssl", "rsa", "-pubin", "-in", str(public_key), "-text", "-noout"],
        capture_output=True, text=True, check=True,
    ).stdout
    modulus_hex, exp = _parse_rsa_text(out)
    nbytes = bytes.fromhex(modulus_hex)
    if nbytes[0] == 0:  # openssl emits a leading 0x00 sign byte; strip for JWK
        nbytes = nbytes[1:]
    ebytes = exp.to_bytes((exp.bit_length() + 7) // 8, "big")
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": b64url(nbytes).rstrip("="),
        "e": b64url(ebytes).rstrip("="),
    }
    jwk["kid"] = jwk_thumbprint(jwk)
    return jwk


def jwk_thumbprint(jwk: dict) -> str:
    """Return the RFC 7638 thumbprint for an RSA public JWK."""
    members = {key: jwk[key] for key in ("e", "kty", "n")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def _parse_rsa_text(out: str) -> Tuple[str, int]:
    hexparts: list = []
    exp = 65537
    in_modulus = False
    for line in out.splitlines():
        s = line.strip()
        low = s.lower()
        if low == "modulus:":
            in_modulus = True
            continue
        if in_modulus:
            # openssl 3.x prints "Exponent:", older versions "publicExponent:"
            if low.startswith("publicexponent:") or low.startswith("exponent:"):
                in_modulus = False
                m = re.match(r"\s*[a-z]+:\s*(\d+)", s, flags=re.IGNORECASE)
                if m:
                    exp = int(m.group(1))
                continue
            hexparts.append(re.sub(r"[^0-9a-fA-F]", "", s))
    return "".join(hexparts), exp

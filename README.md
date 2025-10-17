
manual_hs256_demo.py — a minimal, self-contained script that:

builds a JWT (header + payload → Base64URL → HMAC-SHA256 signature),

verifies a token (signature check + exp claim),

demonstrates tampering (payload changed without re-signing → verification fails),

demonstrates expiry handling.

Quick goals

See how header, payload, and signature are created and combined.

Observe what happens when you tamper with the payload.

Practice generating secure secrets and understand why you must never skip verification.

Requirements

Python 3.8+ (works on 3.7 as well)

No external libraries required for the manual demo.

(Optional) PyJWT[crypto] and cryptography if you want RS256 examples later.

# optional, for PyJWT-based experiments
pip install "PyJWT[crypto]"

Files

manual_hs256_demo.py — main script (copy/paste from the lesson).

Functions:

b64url_encode(data: bytes) -> str — Base64URL-encode (no padding).

b64url_decode(data: str) -> bytes — Base64URL-decode (adds padding).

make_jwt_hs256(payload: dict, secret: str, header: dict=None) -> str — produce token.

verify_jwt_hs256(token: str, secret: str, verify_exp: bool=True) -> dict — verify signature and exp.

How to run

Save manual_hs256_demo.py into a folder.

(Optional) create & activate a virtualenv:

python -m venv venv
source venv/bin/activate    # macOS / Linux
# .\venv\Scripts\Activate.ps1 on Windows PowerShell


Run:

python manual_hs256_demo.py


You should see:

A generated JWT string: header.payload.signature

Verified OK. Header: {...} and printed payload

A tampered token printed and verification failure

An expired token test failure

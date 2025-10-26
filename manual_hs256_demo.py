# manual_hs256_demo.py
""""
This script builds a JWT by:
1) Creating a header and payload JSON
2) Base64URL-encoding them
3) Computing an HMAC-SHA256 signature over header_b64 + "." + payload_b64 using a secret
4) joining the three parts into header.payload.signature - verification then recomputes
the same HMAC and compares it, and also check the 'exp' claim.
"""

import base64 ## for Base64URL encode/decode (JWT uses Base74 URL).
import json ## to 'serialize' header & payload to JSON text.
import hmac, hashlib ## build HMAC-SHA256 signature (HS256).
import time ## to set/check 'iat' and 'exp' claims (issued-at and expiry)

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
"""

- Standard Base64encode uses A-Z-a-z-0-9 + / therefore, 
- base64.urlsafeb54encode swaps the URL-unsafe chars: + → - and / → _
- rstrip drops the '=' because JWT parts are unpadded. 
- decode("ascii:) turns bytes -> string (JWT components are ASCII) | normal text

An example: 
# b64url_encode(b'{"alg":"HS256"}')
# → 'eyJhbGciOiJIUzI1NiJ9'

note: 'b' literally means byte which we're saying This is raw binary data ready for encoding or signing
"""

def b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
'''
- When decoding, we must restore padding (=) because urlsafe_b64decode expects a length multiple of 4.
- len(data) % 4 computes how many = are needed. Example: if len%4 == 2, add 2 =

Note: if decode incorrectly, we get errors or wrong bytes. JWT spec uses Base64URL no padding. 
'''

### Creating (signing) a token
def make_jwt_hs256(payload: dict, secret: str, header: dict=None) -> str:
    ## Default header: {"alg":"HS256", "typ":"JWT"}. alg tells the verifier which algorithm was used
    header = header or {"alg":"HS256","typ":"JWT"}
    '''
    f header is “truthy”, keep it.
    Otherwise, use the default {"alg":"HS256","typ":"JWT"}.
    Note: It’s a quick way to provide a default when the caller passes nothing (None).
    '''

    ## Next one: header_b64 and payload
    header_b64 = b64url_encode(json.dumps(header, separators=(',',':')).encode('utf-8'))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',',':')).encode('utf-8'))
    '''
    json.dumps serializes (converts) a Python object -> a JSON string. 
    separators=(',', ':') → compact output (no spaces).
    Convert to bytes with .encode('utf-8').
    Then Base64URL encode both JSONs.
    
    Example: 
    - header JSON text: {"alg":"HS256","typ":"JWT"}
    - header_b64 might be: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 (this is deterministic).
    '''
    ## Signing header & payload
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    '''
    EXACT string that gets signed is the ASCII bytes of header_b64 + "." + payload_b64. 
    This is crucial — signature covers header+payload, not the decoded JSON. 
    We convert the string to bytes using ASCII (safe and unambiguous here)
    What it builds
    - header_b64 = Base64URL (no =) of the header JSON bytes
    - payload_b64 = Base64URL (no =) of the payload JSON bytes
    It concatenates them with a single dot . in between:
    '''
    ### Compute HMAC-SHA256 with the secret. This produces raw bytes.
    signature = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    '''
    hmac.new(key, msg, digestmod) builds an HMAC object
    - key → secret.encode('utf-8'): your shared secret, as bytes.
    - msg → signing_input: the exact ASCII bytes of header_b64 + b'.' + payload_b64
    - digestmod → hashlib.sha256: use SHA-256 inside HMAC (that’s HS256).
    - .digest() returns the raw 32-byte MAC (binary).
    '''
    ### Base64URL encode the signature bytes and join the three parts with . to form the final JWT.
    '''
    Note: Key point: Anyone who knows secret can produce valid tokens. 
    Anyone who doesn't know it cannot produce a valid HMAC for a changed header/payload
    '''
    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

### verify_jwt_hs256 — verifying a token
def verify_jwt_hs256(token: str, secret: str, verify_exp: bool=True) -> dict:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise ValueError("Token must have exactly two dots (header.payload.signature)")
    '''
    Note: Token must have all parts. If not, reject.
    '''
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    expected_sig = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    actual_sig = b64url_decode(sig_b64)
    '''
    - Rebuild the exact bytes that were originally signed: the ASCII of "<header_b64>.<payload_b64>".
    Note: This must match exactly what the issuer signed (same Base64URL, no padding, one dot).
    - Decode the provided signature to raw bytes.
    '''

    ### Compare signatures
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise ValueError("Invalid signature (verification failed)")
    '''
    Use hmac.compare_digest() for constant-time comparison to avoid timing attacks leaking whether bytes match.
    If different → token forged/tampered → reject.
    '''
    ### Decode payload/header back to Python dicts. Now you can inspect claims.
    payload = json.loads(b64url_decode(payload_b64).decode('utf-8'))
    header = json.loads(b64url_decode(header_b64).decode('utf-8'))

    ### Check expiry.
    '''
    Note the comparison now >= exp means token is invalid at or after the exp time. exp must be integer seconds since epoch.
    '''
    if verify_exp and "exp" in payload:
        now = int(time.time())
        if now >= int(payload["exp"]):
            raise ValueError("Token expired (exp claim)")
    return {"header": header, "payload": payload}

if __name__ == "__main__":
    secret = "my-very-strong-secret-123!" ### secret is the HMAC secret (keep it secret). DON'T EVER WRITE HARD-CODED CREDS, THIS IS JUST FOR TEST
    now = int(time.time())
    payload = {
        "sub": "user-1001",
        "name": "Myrian",
        "admin": False,
        "iat": now, # iat issued-at,
        "exp": now + 60  # exp expiry (now + 60 seconds, so token valid for 60s
    }

    ### Step 1: Generate
    print("1) Generate token (manual HS256)\n")
    token = make_jwt_hs256(payload, secret)
    print(token, "\n") #Output: a long string header.payload.signature. Save it.

    ### Step 2: verify
    print("2) Verify token (correct secret)\n")
    try:
        verified = verify_jwt_hs256(token, secret)
        print("Verified OK. Header:", verified["header"])
        print("Payload:", verified["payload"]) ### Should print header and payload JSON — verification succeeded.
    except Exception as e:
        print("Verification failed:", e)

    ### Step 3: Tamper
    print("\n3) Tamper payload (flip admin -> true) without re-signing and verify (should fail)\n")
    h_b64, p_b64, s_b64 = token.split('.')
    p = json.loads(b64url_decode(p_b64).decode('utf-8'))
    p['admin'] = True
    p_tampered_b64 = b64url_encode(json.dumps(p, separators=(',',':')).encode('utf-8'))
    tampered_token = f"{h_b64}.{p_tampered_b64}.{s_b64}"
    print("Tampered token:\n", tampered_token)
    try:
        verify_jwt_hs256(tampered_token, secret)
        print("Unexpected: tampered token verified")
    except Exception as e:
        print("Expected verification failure:", e)
    '''
    We changed the payload (made admin: True) but kept the old signature. 
    Verification will recompute expected signature over the modified payload and fail — that’s the whole defense.
    '''

    # Step 4: Expired token
    print("\n4) Expired token test (create token with exp in the past)\n")
    payload_expired = payload.copy()
    payload_expired['exp'] = now - 10 #Create payload with exp = now - 10 and sign it. Verification should fail with "Token expired".
    expired_token = make_jwt_hs256(payload_expired, secret)
    try:
        verify_jwt_hs256(expired_token, secret)
        print("Unexpected: expired token verified")
    except Exception as e:
        print("Expected expired token failure:", e)


"""
UseTruth verdict enforcer, Python reference SDK (self-contained).

Deny by default: a message is RELEASED only if it carries a fresh, signed ALLOW
attestation bound to that exact claim. No token, ignored BLOCK, replay, tamper,
or a different/appended message all fail closed. Verifies OFFLINE against
UseTruth's published JWKS (https://api.usetruth.ai/.well-known/jwks.json), no
per-message callback.

Spec: SPEC.md. This file is SHIPPABLE as-is (single module).
The canonicalization is vendored verbatim from src/claim_canonical.py; the test
`test_sdk_enforcer_sync` guarantees the copy never drifts.

Dependency: `cryptography` (ES256 verification). Stdlib otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
import urllib.request

RELEASE = "RELEASE"
DENY = "DENY"
JWKS_URL = "https://api.usetruth.ai/.well-known/jwks.json"
_P256 = 32


class CanonicalError(ValueError):
    pass


# --- canonical claim hash (VENDORED from src/claim_canonical.py, keep in sync) ---

def _normalize_content(text) -> str:
    if not isinstance(text, str):
        raise CanonicalError("content must be a string")
    s = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    if not s.strip():
        raise CanonicalError("content is empty")
    return s


def _jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("float is not allowed in a claim hash")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "{" + ",".join(_jcs(str(k)) + ":" + _jcs(v) for k, v in items) + "}"
    raise CanonicalError(f"unsupported type in claim: {type(value).__name__}")


def claim_hash(content, category, assertions=None, scopes=None) -> str:
    norm_assertions = sorted(
        ({"key": str(a["key"]), "value": a.get("value")}
         for a in (assertions or []) if isinstance(a, dict) and "key" in a),
        key=lambda a: a["key"],
    )
    obj = {
        "content": _normalize_content(content),
        "category": str(category or ""),
        "assertions": norm_assertions,
        "scopes": sorted(str(s) for s in (scopes or [])),
    }
    return hashlib.sha256(_jcs(obj).encode("utf-8")).hexdigest()


# --- JOSE helpers -----------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_to_der(raw: bytes, size: int = _P256) -> bytes:
    if len(raw) != 2 * size:
        raise ValueError("bad raw signature length")

    def enc(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = enc(int.from_bytes(raw[:size], "big")) + enc(int.from_bytes(raw[size:], "big"))
    return b"\x30" + bytes([len(body)]) + body


def public_key_from_jwk(jwk):
    from cryptography.hazmat.primitives.asymmetric import ec
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def fetch_jwks(url: str = JWKS_URL, timeout: int = 10) -> dict:
    """Fetch and parse UseTruth's JWKS into {kid: public_key}. Cache the result
    in your app (keys rotate rarely) rather than calling per message."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        keys = json.loads(resp.read().decode("utf-8")).get("keys", [])
    return {k["kid"]: public_key_from_jwk(k) for k in keys if k.get("kty") == "EC"}


# --- the enforcement decision ----------------------------------------------

def authorize(*, jws, outgoing_text, action, jwks, now, seen_jti, max_skew=60):
    """Deny-by-default authorization. Returns (RELEASE|DENY, reason).

      jws          - the compact JWS attestation the agent presents
      outgoing_text- the exact text about to be sent (rebound against the hash)
      action       - the outgoing action (assertions / claim_scopes for the rebind)
      jwks         - {kid: public_key} (see fetch_jwks)
      now          - current epoch seconds (int)
      seen_jti     - a mutable set used as the replay cache
    """
    parts = str(jws or "").split(".")
    if len(parts) != 3:
        return (DENY, "malformed_token")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:  # noqa: BLE001
        return (DENY, "unparseable_token")

    if header.get("alg") != "ES256":
        return (DENY, "bad_alg")
    pub = jwks.get(header.get("kid"))
    if pub is None:
        return (DENY, "unknown_kid")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        pub.verify(_raw_to_der(_b64url_decode(sig_b64)),
                   (header_b64 + "." + payload_b64).encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001
        return (DENY, "bad_signature")

    iat, exp = payload.get("iat"), payload.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        return (DENY, "bad_times")
    if now + max_skew < iat:
        return (DENY, "not_yet_valid")
    if now >= exp:
        return (DENY, "expired")

    jti = payload.get("jti")
    if not jti or jti in seen_jti:
        return (DENY, "replay_or_missing_jti")

    if payload.get("verdict") != "ALLOW":
        return (DENY, "verdict_" + str(payload.get("verdict")))

    claim = payload.get("claim") or {}
    try:
        recomputed = claim_hash(outgoing_text, claim.get("category"),
                                (action or {}).get("assertions"), (action or {}).get("claim_scopes"))
    except CanonicalError:
        return (DENY, "uncanonicalizable_message")
    if recomputed != claim.get("hash"):
        return (DENY, "message_mismatch")

    seen_jti.add(jti)
    return (RELEASE, "ok")

# UseTruth Signed Verdict, v1 spec (frozen 2026-07-03)

Turns the advisory verdict into a **binding, tamper-evident attestation** an
independent enforcer can act on, without UseTruth ever touching the send.

Principle: **hash what you ship, and only what you verified.** A message
RELEASES only if a fresh, signed `ALLOW` bound to *that exact claim* is present.

## 1. The claim hash (`claim.hash`), the binding

`claim.hash = SHA-256( JCS( canonical_claim ) )` in lowercase hex, where:

```
canonical_claim = {
  "content":    NFC(text-exactly-as-it-will-be-sent),   // load-bearing
  "category":   "<claim category>",
  "assertions": [ {"key": "...", "value": ...}, ... ],   // sorted by key
  "scopes":     [ "...", ... ]                            // sorted
}
```

- **Serialization = RFC 8785 (JCS).** Chosen over an ad-hoc canonical JSON so a
  Python signer and TS/Go enforcers agree byte-for-byte. Object keys sorted by
  code point; no whitespace; ECMAScript string escaping.
- **`content` normalization = Unicode NFC** (lossless) + line-endings → `\n`.
  Empty/whitespace-only content is rejected (no ALLOW is ever bound to nothing).
- **Value types allowed in the hash: string, bool, int, null, list, object.**
  `float` is REJECTED (spec a fixed-decimal string if ever needed) so we never
  touch JCS number-formatting edge cases and stay trivially cross-language.

### ⚠️ The two traps (getting either wrong = a silent false-ALLOW)

1. **NFC for the hash, NFKC for the verdict, never the reverse.** The resolver
   uses NFKC + control-strip (`_norm_text`) *loosely* to CATCH lies
   (`ＳＯＣ 2` ≡ `SOC 2`). The hash uses NFC *tightly* to BIND the exact glyphs.
   If you hashed in NFKC, `ＳＯＣ 2` and `SOC 2` would collide → an enforcer would
   release a variant UseTruth never saw. The two normalizations serve opposite
   goals; do not share a function between them.
2. **Verified span == hashed span.** Never hash more than you verified. If the
   content exceeds what the verification tier actually inspected (e.g. an LLM
   input cap), do NOT issue an `ALLOW` bound to the un-inspected tail, escalate.

## 2. The attestation (a JWS, `ES256`)

Compact JWS: `b64url(header).b64url(payload).b64url(sig)`.

```
header  { "alg":"ES256", "typ":"UTV1", "kid":"<key id>" }
payload {
  "iss":"usetruth", "sub":"<tenant>", "iat":<int>, "exp":<iat+TTL>, "jti":"<uuid>",
  "aud":"<enforcer id, optional>",
  "verdict":"ALLOW|BLOCK|ESCALATE", "terminal":"trust|repair|reject|human_review",
  "claim": { "hash":"<hex>", "category":"...", "text_sha256":"<hex>" },
  "reasons":[ {"dimension","verdict","code","message"} ],
  "audit": { "seq":<int>, "event_hash":"..." },   // link to the tamper-evident chain
  "engine":"resolver+deterministic-v0.1"
}
```
- `claim.hash` is the ONLY replay-binding field; verdict/tenant/time live outside it.
- **TTL short** (default 300 s). The verdict is about a specific send at a time.

## 3. Signing keys

- **Prod: AWS KMS asymmetric key** (`ECC_NIST_P256`, `SIGN_VERIFY`). Lambda calls
  `kms:Sign` (`SigningAlgorithm=ECDSA_SHA_256`, `MessageType=RAW`). The private
  key never leaves KMS, a compromised Lambda can request signatures, not
  exfiltrate the key (unlike a shared HMAC secret). KMS returns a DER signature;
  convert to JOSE raw `R||S` (64 bytes).
- **Local/tests: an in-process P-256 key** (`cryptography`) mirroring the same
  ES256 output, so the whole pipeline is testable offline.
- Public key published at `GET /.well-known/jwks.json`; rotation via `kid`.

## 4. Enforcer, deny by default (all 6 must pass to RELEASE)

```
1. signature valid   (ES256 over b64(header).b64(payload), public key by kid)
2. not expired       (now < exp; now + skew >= iat)
3. jti unused        (replay cache)
4. verdict == ALLOW  (BLOCK/ESCALATE -> hold/deny)
5. claim.hash rebind: SHA-256(JCS(canonical_claim(NFC(outgoing_text),
                       payload.claim.category, outgoing.assertions,
                       outgoing.scopes))) == payload.claim.hash
6. content non-empty, valid UTF-8
```
Anything else, no token, ignored BLOCK, replay, tamper, wrong message, is DENY.
No superset: the outgoing text must canonicalize to exactly the hashed content.

## 5. v1 scope

Whole published-text binding, strict: what you verify is what you ship, in one
block. Templated/dynamic messages (variable recipient/date) are **v2**, either
span-binding (beware content outside spans is unverified) or re-verify per send
(cheap; the intended path). Do NOT build span-binding in v1.

## 6. Reference implementation (this repo)

- `src/claim_canonical.py`, NFC + JCS + SHA-256 (§1). The shipped SDK vendors an
  identical copy.
- `src/attestation.py`, payload builder + `LocalEcSigner`/`KmsSigner` (§2–3).
- `sdk/enforcer.py`, the 6-check enforcer (§4).
- `tests/test_signed_verdict.py`, canonicalization traps + full sign→enforce
  round-trip (RELEASE on match; DENY on tamper/expiry/replay/appended-lie/verdict).

Not yet wired to the live handler: attaching the signed attestation to
`/v1/resolve-and-clear` responses, the JWKS route, and the KMS key resource +
`kms:Sign` IAM need a provisioned KMS key (small cost) + deploy, pending
explicit go-ahead.

# usetruth-enforcer

**Put an independent, signed clearance in front of any AI agent, in about 5 lines.**

UseTruth decides whether an agent's action or claim should go out (allow, block, escalate) and signs that decision. This enforcer is the other half: it verifies that signed verdict **offline** and **denies by default**. A message is released only if it carries a fresh, signed `ALLOW` bound to that exact text. No token, an ignored `BLOCK`/`ESCALATE`, a replay, or a tampered/appended message all fail closed.

Why an enforcer you run yourself, separate from the model and the runtime:

- **Independent.** The verdict is signed (ES256) by UseTruth and verified against a published key. Your security team, your customer, or an auditor can check it without trusting the agent, the runtime, or even UseTruth's uptime.
- **Deny by default.** If verification does not pass, nothing goes out. The safe failure is to hold.
- **Offline.** No per-message callback. Verification is a local signature check against a cached JWKS, so it scales and survives a brief outage for already-issued tokens.
- **Zero dependency (JS).** One file, `node:crypto`, Node >= 18. A Python port is included too.

This is not another policy engine deciding *whether* an agent *can* call a tool. It is the checkpoint that enforces an independent decision about whether a specific action *should* run, with proof anyone can verify.

## Install

Vendor the single file (works today, zero dependencies for JS): copy `src/enforcer.mjs` (JS) or `src/enforcer.py` (Python, needs `cryptography`) into your project.

Once published to npm:

```bash
npm install usetruth-enforcer
```

## Quickstart (JavaScript / TypeScript)

```js
import { authorize, fetchJwks, RELEASE } from 'usetruth-enforcer';

const jwks = await fetchJwks();     // cache this; keys rotate rarely
const seenJti = new Set();          // your replay cache

const [decision, reason] = authorize({
  jws: attestation,                 // the signed verdict from UseTruth
  outgoingText: messageText,        // the EXACT text about to be sent
  action,                           // the action you cleared (assertions / claim_scopes)
  jwks, now: Math.floor(Date.now() / 1000), seenJti,
});

if (decision === RELEASE) send(messageText);
else hold(reason);                  // e.g. "verdict_BLOCK", "message_mismatch", "expired"
```

## Quickstart (Python)

```python
import time, enforcer            # pip dependency: cryptography

jwks = enforcer.fetch_jwks()     # cache this
seen_jti = set()                 # replay cache

decision, reason = enforcer.authorize(
    jws=attestation, outgoing_text=message_text, action=action,
    jwks=jwks, now=int(time.time()), seen_jti=seen_jti)

send(message_text) if decision == enforcer.RELEASE else hold(reason)
```

## Try it live, no key, no signup

`examples/clearance-in-5-lines.mjs` clears a claim against the public UseTruth API and enforces the result:

```bash
node examples/clearance-in-5-lines.mjs
```

```text
UseTruth decision : ESCALATE
HELD (verdict_ESCALATE) : no fresh, signed ALLOW binds this message. Not sent.
No attestation   : DENY (malformed_token)
```

An unproven compliance claim is held (deny by default), and an agent that skips UseTruth entirely cannot send. Tamper-detection and byte-identical cross-language signing (a JS enforcer verifying a verdict signed by Python + AWS KMS) are proven in `examples/live-test.mjs`.

## Where it sits

Put the enforcer in front of whatever your agent uses to act:

```
agent (Arcade / LangChain / MCP / your own) 
   -> UseTruth  (/demo/resolve-and-clear or /v1)  -> { decision, attestation }
   -> your enforcer.authorize(...)                -> RELEASE (send) | DENY (hold / route to a human)
```

It does not replace your runtime, your auth, or your tools. It adds one signed checkpoint before a consequential action or claim leaves the building, and a receipt a third party can verify later.

## What the enforcer checks (all must pass to RELEASE)

1. **signature** valid (ES256, UseTruth's public key by `kid`)
2. **not expired** (`iat` / `exp`, short TTL)
3. **`jti` unused** (replay cache you own)
4. **`verdict == ALLOW`** (`BLOCK` / `ESCALATE` hold)
5. **claim-hash rebind**: the outgoing text canonicalizes to the signed hash (an appended lie changes the hash)
6. **content** non-empty, valid

The binding is `SHA-256(JCS(canonical_claim))` with Unicode NFC on the content. The full contract is in [`SPEC.md`](SPEC.md). Both language implementations produce byte-identical hashes on purpose (RFC 8785 JCS), so a Python signer and a JS enforcer agree exactly.

## Production notes

- **Replay cache**: the examples use an in-process set. In production use a shared, TTL'd store (Redis / DynamoDB) keyed by `jti`, expiring at the token's `exp`.
- **JWKS caching**: fetch once and refresh on `unknown_kid` (keys rotate via `kid`).
- **v1 binds the whole published text.** Dynamic messages (variable recipient / date) are v2: re-verify per send (cheap) or span-binding (later).

## Status

The enforcer and the signed-verdict spec are stable. UseTruth's hosted runtime is in **design-partner preview**: the public demo endpoint is live and signs real ES256 verdicts; production connectors and evidence sources are gated, in-progress increments. See [usetruth.ai](https://usetruth.ai).

## License

MIT. See [LICENSE](LICENSE).

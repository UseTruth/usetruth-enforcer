// UseTruth verdict enforcer, JavaScript reference SDK (zero dependency, Node >=18).
//
// Deny by default: a message is RELEASED only if it carries a fresh, signed ALLOW
// attestation bound to that exact claim. No token, ignored BLOCK, replay, tamper,
// or a different/appended message all fail closed. Verifies OFFLINE against
// UseTruth's published JWKS (no per-message callback).
//
// Spec: SPEC.md. The canonicalization below is byte-for-byte
// identical to the Python signer (NFC + RFC 8785 JCS + SHA-256), that is the
// whole point of choosing JCS, and the live test proves it cross-language.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const RELEASE = 'RELEASE';
export const DENY = 'DENY';
export const JWKS_URL = 'https://api.usetruth.ai/.well-known/jwks.json';

const b64url = (s) => Buffer.from(s, 'base64url');

// --- canonical claim hash (must match src/claim_canonical.py) ----------------

function normalizeContent(text) {
  if (typeof text !== 'string') throw new Error('content must be a string');
  const s = text.normalize('NFC').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  if (s.trim() === '') throw new Error('content is empty');
  return s;
}

function jcs(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('float is not allowed in a claim hash');
    return String(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
  if (typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => jcs(String(k)) + ':' + jcs(v[k])).join(',') + '}';
  }
  throw new Error('unsupported type in claim');
}

export function claimHash(content, category, assertions, scopes) {
  const norm = (assertions || [])
    .filter((a) => a && typeof a === 'object' && 'key' in a)
    .map((a) => ({ key: String(a.key), value: a.value }))
    .sort((x, y) => (x.key < y.key ? -1 : x.key > y.key ? 1 : 0));
  const obj = {
    content: normalizeContent(content),
    category: String(category || ''),
    assertions: norm,
    scopes: (scopes || []).map(String).sort(),
  };
  return createHash('sha256').update(jcs(obj), 'utf8').digest('hex');
}

// --- JWKS + verification -----------------------------------------------------

export async function fetchJwks(url = JWKS_URL) {
  const { keys } = await (await fetch(url)).json();
  const out = {};
  for (const k of keys || []) {
    if (k.kty === 'EC') out[k.kid] = createPublicKey({ key: k, format: 'jwk' });
  }
  return out;
}

function verifyEs256(pubKey, signingInput, rawSig) {
  // dsaEncoding 'ieee-p1363' == raw R||S, i.e. the JOSE signature form.
  return cryptoVerify('sha256', Buffer.from(signingInput, 'ascii'),
    { key: pubKey, dsaEncoding: 'ieee-p1363' }, rawSig);
}

// --- the enforcement decision ------------------------------------------------

export function authorize({ jws, outgoingText, action, jwks, now, seenJti, maxSkew = 60 }) {
  const parts = String(jws || '').split('.');
  if (parts.length !== 3) return [DENY, 'malformed_token'];
  const [h64, p64, s64] = parts;
  let header, payload;
  try {
    header = JSON.parse(b64url(h64).toString('utf8'));
    payload = JSON.parse(b64url(p64).toString('utf8'));
  } catch { return [DENY, 'unparseable_token']; }

  if (header.alg !== 'ES256') return [DENY, 'bad_alg'];
  const pub = jwks[header.kid];
  if (!pub) return [DENY, 'unknown_kid'];
  let sigOk = false;
  try { sigOk = verifyEs256(pub, h64 + '.' + p64, b64url(s64)); } catch { sigOk = false; }
  if (!sigOk) return [DENY, 'bad_signature'];

  const { iat, exp } = payload;
  if (!Number.isInteger(iat) || !Number.isInteger(exp)) return [DENY, 'bad_times'];
  if (now + maxSkew < iat) return [DENY, 'not_yet_valid'];
  if (now >= exp) return [DENY, 'expired'];

  const jti = payload.jti;
  if (!jti || seenJti.has(jti)) return [DENY, 'replay_or_missing_jti'];

  if (payload.verdict !== 'ALLOW') return [DENY, 'verdict_' + payload.verdict];

  const claim = payload.claim || {};
  let recomputed;
  try {
    recomputed = claimHash(outgoingText, claim.category, action?.assertions, action?.claim_scopes);
  } catch { return [DENY, 'uncanonicalizable_message']; }
  if (recomputed !== claim.hash) return [DENY, 'message_mismatch'];

  seenJti.add(jti);
  return [RELEASE, 'ok'];
}

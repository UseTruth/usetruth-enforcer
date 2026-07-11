// Clearance in front of any agent, end to end, against the live UseTruth API.
// No key, no signup. Run:  node examples/clearance-in-5-lines.mjs
import { authorize, fetchJwks, RELEASE } from '../src/enforcer.mjs';

const API = 'https://api.usetruth.ai/demo/resolve-and-clear';
const message = 'We are SOC 2 Type II certified.';

// 1. Ask UseTruth to clear the claim/action. You get a decision + a signed attestation.
const res = await (await fetch(API, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ claim_text: message }),
})).json();
console.log('UseTruth decision :', res.clearance_decision);

// 2. Deny by default: your enforcer verifies the signed verdict OFFLINE and enforces it.
const jwks = await fetchJwks();
const seenJti = new Set();
const [decision, reason] = authorize({
  jws: res.attestation,
  outgoingText: message,
  action: {},
  jwks,
  now: Math.floor(Date.now() / 1000),
  seenJti,
});

if (decision === RELEASE) {
  console.log('RELEASE          : signed ALLOW verified, safe to send.');
} else {
  console.log(`HELD (${reason}) : no fresh, signed ALLOW binds this message. Not sent.`);
}

// 3. Deny by default also means an agent that SKIPS UseTruth cannot send.
const [d3, r3] = authorize({
  jws: '',
  outgoingText: message,
  action: {},
  jwks,
  now: Math.floor(Date.now() / 1000),
  seenJti: new Set(),
});
console.log(`No attestation   : ${d3} (${r3})`);

// The whole point: a message is RELEASED only if it carries a fresh, signed ALLOW
// bound to that exact text. No token, an ignored BLOCK/ESCALATE, a replay, or a
// tampered/appended message all fail closed, verified offline.
// Tamper-detection and cross-language signing are proven in examples/live-test.mjs.

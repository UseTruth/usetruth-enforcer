// Live cross-language proof: a zero-dependency JavaScript enforcer verifies a
// verdict signed in PRODUCTION by Python + AWS KMS. If the rebind hash matches,
// NFC + JCS + ES256 are byte-identical across Python/KMS and JS.
//   run: node sdk/usetruth-enforcer.live-test.mjs
import { authorize, fetchJwks, RELEASE, DENY } from './usetruth-enforcer.mjs';

const API = 'https://api.usetruth.ai';
const action = {
  claim_category: 'soc2_certification', claim_scopes: ['security_posture'],
  claim_text: 'We hold a current SOC 2 Type II attestation.',
  cited_evidence: ['soc2_report_2026'], assertions: [{ key: 'soc2_status', value: 'certified' }],
};

let ok = true;
const check = (label, c) => { ok = ok && !!c; console.log(`  [${c ? 'PASS' : 'FAIL'}] ${label}`); };

const resp = await (await fetch(API + '/demo/resolve-and-clear', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action }),
})).json();
check(`verdict = ${resp.clearance_decision}`, resp.clearance_decision === 'ALLOW');
const jws = resp.attestation;
check('response carries a signed attestation', !!jws);

const jwks = await fetchJwks();
check(`live JWKS loaded (${Object.keys(jwks).length} key)`, Object.keys(jwks).length === 1);

const now = Math.floor(Date.now() / 1000);
let [d, why] = authorize({ jws, outgoingText: action.claim_text, action, jwks, now, seenJti: new Set() });
check(`JS enforcer RELEASEs the Python/KMS-signed message (${d}/${why})`, d === RELEASE);

[d, why] = authorize({
  jws, outgoingText: action.claim_text + ' We are also FedRAMP authorized.',
  action, jwks, now, seenJti: new Set(),
});
check(`JS enforcer DENIEs an appended lie (${d}/${why})`, d === DENY && why === 'message_mismatch');

const seen = new Set();
authorize({ jws, outgoingText: action.claim_text, action, jwks, now, seenJti: seen });
[d, why] = authorize({ jws, outgoingText: action.claim_text, action, jwks, now, seenJti: seen });
check(`JS enforcer DENIEs a replay (${why})`, why === 'replay_or_missing_jti');

console.log('\nRESULT:', ok
  ? 'ALL PASS, a JS enforcer verifies the live Python/KMS-signed verdict (cross-language)'
  : 'SOME FAILED');
process.exit(ok ? 0 : 1);

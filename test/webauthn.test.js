'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const webauthn = require('../src/lib/webauthn');
const { FakeAuthenticator, cbor } = require('./fake-authenticator');

const origin = 'https://example.com';
const rpId = 'example.com';

function register(alg) {
  const auth = new FakeAuthenticator({ origin, rpId, alg });
  const challenge = 'register-challenge';
  const cred = webauthn.verifyRegistration({ response: auth.create({ challenge }).response, challenge, origin, rpId });
  return { auth, cred };
}

test('CBOR decoder reads maps, arrays, negatives and byte strings', () => {
  const value = new Map([[1, 2], [-7, Buffer.from([1, 2, 3])], ['k', 'v']]);
  const out = webauthn.cborDecode(cbor(value)).value;
  assert.equal(out.get(1), 2);
  assert.deepEqual(out.get(-7), Buffer.from([1, 2, 3]));
  assert.equal(out.get('k'), 'v');
  assert.throws(() => webauthn.cborDecode(Buffer.from([0x5f])), /Unsupported/); // indefinite length
  assert.throws(() => webauthn.cborDecode(Buffer.from([0x45, 1])), /truncated/);
});

for (const [name, alg] of [['ES256', -7], ['Ed25519', -8]]) {
  test(`passkey ${name}: register and sign in`, () => {
    const { auth, cred } = register(alg);
    assert.equal(cred.id, auth.id);
    assert.equal(cred.alg, alg);
    const challenge = 'login-challenge';
    const { signCount } = webauthn.verifyAssertion({ credential: cred, response: auth.get({ challenge }).response, challenge, origin, rpId });
    assert.equal(signCount, 1);
  });
}

test('passkey: rejects wrong challenge, origin, relying party and type', () => {
  const { auth, cred } = register(-7);
  const check = (response, challenge = 'c') => () => webauthn.verifyAssertion({ credential: cred, response, challenge, origin, rpId });
  assert.throws(check(auth.get({ challenge: 'other' }).response), /Challenge mismatch/);
  assert.throws(check(auth.get({ challenge: 'c' }, { origin: 'https://evil.example' }).response), /Origin mismatch/);
  assert.throws(check(auth.get({ challenge: 'c' }, { rpId: 'evil.example' }).response), /Relying party mismatch/);
  const reg = auth.create({ challenge: 'c' }).response;
  assert.throws(() => webauthn.verifyRegistration({ response: { ...reg }, challenge: 'c', origin: 'https://evil.example', rpId }), /Origin mismatch/);
});

test('passkey: rejects a tampered signature and a key from another authenticator', () => {
  const { auth, cred } = register(-7);
  const response = auth.get({ challenge: 'c' }).response;
  const sig = Buffer.from(response.signature, 'base64url');
  sig[sig.length - 1] ^= 1;
  assert.throws(() => webauthn.verifyAssertion({ credential: cred, response: { ...response, signature: sig.toString('base64url') }, challenge: 'c', origin, rpId }));

  const other = new FakeAuthenticator({ origin, rpId });
  assert.throws(() => webauthn.verifyAssertion({ credential: cred, response: other.get({ challenge: 'c' }).response, challenge: 'c', origin, rpId }), /Bad signature/);
});

test('passkey: a counter that goes backwards means a cloned key', () => {
  const { auth, cred } = register(-7);
  const first = webauthn.verifyAssertion({ credential: cred, response: auth.get({ challenge: 'c' }, { counterStep: 5 }).response, challenge: 'c', origin, rpId });
  const stored = { ...cred, signCount: first.signCount };
  auth.counter = 2; // a copy of the key with an older counter
  assert.throws(() => webauthn.verifyAssertion({ credential: stored, response: auth.get({ challenge: 'c' }).response, challenge: 'c', origin, rpId }), /counter/);
});

'use strict';
// A software passkey for tests: produces the same data a browser would.
const crypto = require('node:crypto');

function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(3);
  b[0] = (major << 5) | 25;
  b.writeUInt16BE(n, 1);
  return b;
}

function cbor(v) {
  if (Number.isInteger(v)) return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (Buffer.isBuffer(v)) return Buffer.concat([cborHead(2, v.length), v]);
  if (typeof v === 'string') {
    const b = Buffer.from(v);
    return Buffer.concat([cborHead(3, b.length), b]);
  }
  if (v instanceof Map) {
    const parts = [cborHead(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return Buffer.concat(parts);
  }
  throw new Error('unsupported');
}

const sha256 = (d) => crypto.createHash('sha256').update(d).digest();
const b64u = (b) => Buffer.from(b).toString('base64url');

class FakeAuthenticator {
  constructor({ origin, rpId, alg = -7 }) {
    this.origin = origin;
    this.rpId = rpId;
    this.alg = alg;
    const pair = alg === -8 ? crypto.generateKeyPairSync('ed25519') : crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
    this.credentialId = crypto.randomBytes(16);
    this.counter = 0;
  }

  get id() {
    return b64u(this.credentialId);
  }

  coseKey() {
    const jwk = this.publicKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x, 'base64url');
    if (this.alg === -8) return new Map([[1, 1], [3, -8], [-1, 6], [-2, x]]);
    return new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, Buffer.from(jwk.y, 'base64url')]]);
  }

  authData(attested, rpId = this.rpId) {
    const head = Buffer.alloc(37);
    sha256(rpId).copy(head, 0);
    head[32] = 0x05 | (attested ? 0x40 : 0); // UP + UV (+ AT)
    head.writeUInt32BE(this.counter, 33);
    if (!attested) return head;
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.credentialId.length);
    return Buffer.concat([head, Buffer.alloc(16), len, this.credentialId, cbor(this.coseKey())]);
  }

  clientData(type, challenge, origin = this.origin) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** Same shape the browser UI sends to /api/mfa/passkey/enable. */
  create(publicKey) {
    const att = new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', this.authData(true)]]);
    return {
      id: this.id,
      response: {
        clientDataJSON: b64u(this.clientData('webauthn.create', publicKey.challenge)),
        attestationObject: b64u(cbor(att)),
      },
    };
  }

  /** Same shape the browser UI sends to /api/mfa/challenge/verify. */
  get(publicKey, { origin, rpId, counterStep = 1 } = {}) {
    this.counter += counterStep;
    const authData = this.authData(false, rpId);
    const clientData = this.clientData('webauthn.get', publicKey.challenge, origin);
    const signature = crypto.sign(this.alg === -8 ? null : 'sha256', Buffer.concat([authData, sha256(clientData)]), this.privateKey);
    return {
      id: this.id,
      response: { authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(signature) },
    };
  }
}

module.exports = { FakeAuthenticator, cbor };

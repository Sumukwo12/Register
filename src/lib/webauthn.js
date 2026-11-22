'use strict';
// Passkey (WebAuthn) verification. Registration uses attestation "none":
// we trust the key the browser hands us, not the authenticator's make.
const crypto = require('node:crypto');

const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified
const FLAG_AT = 0x40; // attested credential data included

// Decodes the subset of CBOR that WebAuthn uses. Returns { value, end }.
function cborDecode(buf, offset = 0, depth = 0) {
  if (depth > 16) throw new Error('CBOR nested too deeply');
  if (offset >= buf.length) throw new Error('CBOR data truncated');
  const major = buf[offset] >> 5;
  const info = buf[offset] & 31;
  let pos = offset + 1;
  let len;
  if (info < 24) len = info;
  else if (info === 24) len = buf.readUInt8(pos++);
  else if (info === 25) { len = buf.readUInt16BE(pos); pos += 2; }
  else if (info === 26) { len = buf.readUInt32BE(pos); pos += 4; }
  else throw new Error('Unsupported CBOR length');

  switch (major) {
    case 0:
      return { value: len, end: pos };
    case 1:
      return { value: -1 - len, end: pos };
    case 2:
    case 3: {
      if (pos + len > buf.length) throw new Error('CBOR data truncated');
      const bytes = buf.subarray(pos, pos + len);
      return { value: major === 2 ? Buffer.from(bytes) : bytes.toString('utf8'), end: pos + len };
    }
    case 4: {
      const arr = [];
      for (let i = 0; i < len; i++) {
        const r = cborDecode(buf, pos, depth + 1);
        arr.push(r.value);
        pos = r.end;
      }
      return { value: arr, end: pos };
    }
    case 5: {
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const k = cborDecode(buf, pos, depth + 1);
        const v = cborDecode(buf, k.end, depth + 1);
        map.set(k.value, v.value);
        pos = v.end;
      }
      return { value: map, end: pos };
    }
    case 7:
      if (info === 20) return { value: false, end: pos };
      if (info === 21) return { value: true, end: pos };
      if (info === 22) return { value: null, end: pos };
      throw new Error('Unsupported CBOR simple value');
    default:
      throw new Error('Unsupported CBOR type');
  }
}

function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('Authenticator data too short');
  const flags = buf[32];
  const out = { rpIdHash: buf.subarray(0, 32), flags, signCount: buf.readUInt32BE(33) };
  if (flags & FLAG_AT) {
    let pos = 37 + 16; // skip AAGUID
    const idLen = buf.readUInt16BE(pos);
    pos += 2;
    out.credentialId = buf.subarray(pos, pos + idLen);
    if (out.credentialId.length !== idLen) throw new Error('Authenticator data truncated');
    out.coseKey = cborDecode(buf, pos + idLen).value;
  }
  return out;
}

// Converts a COSE public key to SPKI (DER, base64). Supports ES256, EdDSA and RS256.
function coseToSpki(cose) {
  if (!(cose instanceof Map)) throw new Error('Invalid public key');
  const b64 = (b) => {
    if (!Buffer.isBuffer(b)) throw new Error('Invalid public key');
    return b.toString('base64url');
  };
  const kty = cose.get(1);
  const alg = cose.get(3);
  let jwk;
  if (kty === 2 && alg === -7 && cose.get(-1) === 1) jwk = { kty: 'EC', crv: 'P-256', x: b64(cose.get(-2)), y: b64(cose.get(-3)) };
  else if (kty === 1 && alg === -8 && cose.get(-1) === 6) jwk = { kty: 'OKP', crv: 'Ed25519', x: b64(cose.get(-2)) };
  else if (kty === 3 && alg === -257) jwk = { kty: 'RSA', n: b64(cose.get(-1)), e: b64(cose.get(-2)) };
  else throw new Error('Unsupported key type');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  return { alg, publicKey: key.export({ type: 'spki', format: 'der' }).toString('base64') };
}

function bytes(value, name) {
  if (typeof value !== 'string' || !value) throw new Error(`Missing ${name}`);
  return Buffer.from(value, 'base64url');
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function checkClientData(raw, type, challenge, origin) {
  let cd;
  try {
    cd = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new Error('Invalid client data');
  }
  if (cd.type !== type) throw new Error('Wrong ceremony type');
  const a = Buffer.from(String(cd.challenge));
  const b = Buffer.from(challenge);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('Challenge mismatch');
  if (cd.origin !== origin) throw new Error('Origin mismatch');
  if (cd.crossOrigin === true) throw new Error('Cross-origin request');
}

function checkAuthData(ad, rpId) {
  if (!ad.rpIdHash.equals(sha256(rpId))) throw new Error('Relying party mismatch');
  if (!(ad.flags & FLAG_UP)) throw new Error('User was not present');
}

/** Verifies navigator.credentials.create() output. Returns the credential to store. */
function verifyRegistration({ response, challenge, origin, rpId }) {
  if (!response || typeof response !== 'object') throw new Error('Missing response');
  const clientData = bytes(response.clientDataJSON, 'clientDataJSON');
  checkClientData(clientData, 'webauthn.create', challenge, origin);
  const att = cborDecode(bytes(response.attestationObject, 'attestationObject')).value;
  if (!(att instanceof Map) || !Buffer.isBuffer(att.get('authData'))) throw new Error('Invalid attestation object');
  const ad = parseAuthData(att.get('authData'));
  checkAuthData(ad, rpId);
  if (!ad.credentialId) throw new Error('No credential in response');
  return {
    id: ad.credentialId.toString('base64url'),
    ...coseToSpki(ad.coseKey),
    signCount: ad.signCount,
    userVerified: Boolean(ad.flags & FLAG_UV),
  };
}

/** Verifies navigator.credentials.get() output against a stored credential. Returns the new signature counter. */
function verifyAssertion({ credential, response, challenge, origin, rpId }) {
  if (!response || typeof response !== 'object') throw new Error('Missing response');
  const authData = bytes(response.authenticatorData, 'authenticatorData');
  const clientData = bytes(response.clientDataJSON, 'clientDataJSON');
  const signature = bytes(response.signature, 'signature');
  checkClientData(clientData, 'webauthn.get', challenge, origin);
  const ad = parseAuthData(authData);
  checkAuthData(ad, rpId);

  const key = crypto.createPublicKey({ key: Buffer.from(credential.publicKey, 'base64'), format: 'der', type: 'spki' });
  const signed = Buffer.concat([authData, sha256(clientData)]);
  if (!crypto.verify(credential.alg === -8 ? null : 'sha256', signed, key, signature)) throw new Error('Bad signature');

  // A counter that doesn't move forward suggests a cloned authenticator.
  // Many passkeys always report 0, which is allowed.
  if ((ad.signCount !== 0 || credential.signCount !== 0) && ad.signCount <= credential.signCount) {
    throw new Error('Signature counter did not increase');
  }
  return { signCount: ad.signCount };
}

module.exports = { cborDecode, parseAuthData, verifyRegistration, verifyAssertion };

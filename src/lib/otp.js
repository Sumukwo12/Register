'use strict';
/**
 * One-time password primitives.
 *  - HOTP: RFC 4226 (counter based)
 *  - TOTP: RFC 6238 (time based) - Google Authenticator, Microsoft Authenticator, Authy, 1Password...
 *  - Base32: RFC 4648 (the encoding authenticator apps use for secrets)
 */
const crypto = require('node:crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character');
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Constant-time string comparison (prevents timing attacks on codes). */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function hotp(key, counter, { digits = 6, algorithm = 'sha1' } = {}) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac(algorithm, key).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin =
    ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

function timeStep(time = Date.now(), step = 30) {
  return Math.floor(time / 1000 / step);
}

function totp(key, { time = Date.now(), step = 30, digits = 6, algorithm = 'sha1' } = {}) {
  return hotp(key, timeStep(time, step), { digits, algorithm });
}

/**
 * Verify a TOTP code allowing +/- `window` steps of clock drift.
 * `lastStep` = last accepted step; anything <= it is rejected (replay protection).
 * Returns the matched step, or null.
 */
function verifyTotp(key, token, { window = 1, time = Date.now(), step = 30, digits = 6, lastStep = -1 } = {}) {
  if (typeof token !== 'string' || !/^\d+$/.test(token) || token.length !== digits) return null;
  const current = timeStep(time, step);
  for (let i = -window; i <= window; i++) {
    const s = current + i;
    if (s < 0 || s <= lastStep) continue;
    if (safeEqual(hotp(key, s, { digits }), token)) return s;
  }
  return null;
}

/**
 * Verify an HOTP code with a look-ahead window (the device counter may be ahead
 * of the server if the user pressed the button without logging in).
 * Returns the NEXT counter value to store, or null.
 */
function verifyHotp(key, token, counter, { lookahead = 10, digits = 6 } = {}) {
  if (typeof token !== 'string' || !/^\d+$/.test(token) || token.length !== digits) return null;
  for (let c = counter; c <= counter + lookahead; c++) {
    if (safeEqual(hotp(key, c, { digits }), token)) return c + 1;
  }
  return null;
}

function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

/** Builds the otpauth:// URI encoded in the QR code that authenticator apps scan. */
function otpauthUri({ type = 'totp', secret, label, issuer, counter = 0, digits = 6, period = 30 }) {
  const params = new URLSearchParams({ secret, issuer, algorithm: 'SHA1', digits: String(digits) });
  if (type === 'totp') params.set('period', String(period));
  else params.set('counter', String(counter));
  const fullLabel = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://${type}/${fullLabel}?${params.toString()}`;
}

module.exports = {
  base32Encode,
  base32Decode,
  safeEqual,
  hotp,
  totp,
  timeStep,
  verifyTotp,
  verifyHotp,
  generateSecret,
  otpauthUri,
};

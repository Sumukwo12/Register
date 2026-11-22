'use strict';
/**
 * Password hashing, encryption-at-rest for 2FA secrets, token hashing,
 * one-time numeric codes and backup codes.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ---------- Passwords (scrypt, memory-hard) ----------
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 64, maxmem: 64 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT.keylen, SCRYPT, (err, key) => {
      if (err) return reject(err);
      resolve(`scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${key.toString('base64')}`);
    });
  });
}

function verifyPassword(stored, password) {
  const [alg, N, r, p, saltB64, hashB64] = String(stored).split('$');
  if (alg !== 'scrypt') return Promise.resolve(false);
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  const params = { N: Number(N), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem };
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, expected.length, params, (err, key) => {
      if (err) return reject(err);
      resolve(crypto.timingSafeEqual(key, expected));
    });
  });
}

// ---------- Master key / keyring ----------
function loadMasterKey(dataDir) {
  if (process.env.APP_SECRET) {
    const k = Buffer.from(process.env.APP_SECRET, 'hex');
    if (k.length !== 32) throw new Error('APP_SECRET must be 64 hex characters (32 bytes)');
    return k;
  }
  const file = path.join(dataDir, 'secret.key');
  if (fs.existsSync(file)) return Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  const key = crypto.randomBytes(32);
  fs.writeFileSync(file, key.toString('hex'), { mode: 0o600 });
  return key;
}

function makeKeyring(master) {
  const encKey = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), 'mfa-secret-encryption', 32));
  const pepper = Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), 'token-hash-pepper', 32));

  return {
    /** AES-256-GCM: authenticated encryption for TOTP/HOTP secrets at rest. */
    encrypt(plaintext) {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', encKey, iv);
      const ct = Buffer.concat([c.update(String(plaintext), 'utf8'), c.final()]);
      return [iv, c.getAuthTag(), ct].map((b) => b.toString('base64')).join('.');
    },
    decrypt(blob) {
      const [iv, tag, ct] = String(blob).split('.').map((s) => Buffer.from(s, 'base64'));
      const d = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
    },
    /** Keyed hash for OTP codes / backup codes / magic tokens (never stored in plain text). */
    hashToken(token) {
      return crypto.createHmac('sha256', pepper).update(String(token)).digest('hex');
    },
  };
}

// ---------- Random values ----------
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function numericCode(digits = 6) {
  return String(crypto.randomInt(0, 10 ** digits)).padStart(digits, '0');
}

const BACKUP_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'; // no 0/o/1/l/i confusion

function backupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    let s = '';
    for (let j = 0; j < 8; j++) s += BACKUP_ALPHABET[crypto.randomInt(0, BACKUP_ALPHABET.length)];
    codes.push(`${s.slice(0, 4)}-${s.slice(4)}`);
  }
  return codes;
}

function normalizeBackupCode(code) {
  return String(code).toLowerCase().replace(/[\s-]/g, '');
}

// ---------- Breached passwords ----------
/**
 * How many times a password appears in the Have I Been Pwned breach corpus.
 * Uses the k-anonymity range API: only the first 5 hex chars of the SHA-1 leave this machine.
 */
async function pwnedPasswordCount(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const res = await fetch(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { 'Add-Padding': 'true', 'User-Agent': 'secure-2fa' },
    signal: AbortSignal.timeout(3000),
  });
  if (!res.ok) throw new Error(`HIBP returned ${res.status}`);
  const suffix = hash.slice(5);
  for (const line of (await res.text()).split('\n')) {
    const [h, count] = line.trim().split(':');
    if (h === suffix) return Number(count);
  }
  return 0;
}

module.exports = {
  pwnedPasswordCount,
  hashPassword,
  verifyPassword,
  loadMasterKey,
  makeKeyring,
  randomToken,
  numericCode,
  backupCodes,
  normalizeBackupCode,
};

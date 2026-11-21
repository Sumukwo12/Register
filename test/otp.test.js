'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const otp = require('../src/lib/otp');
const cu = require('../src/lib/crypto-utils');

const RFC_KEY = Buffer.from('12345678901234567890');

test('HOTP matches RFC 4226 test vectors', () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  expected.forEach((code, i) => assert.equal(otp.hotp(RFC_KEY, i), code));
});

test('TOTP matches RFC 6238 SHA-1 test vectors (8 digits)', () => {
  const vectors = [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']];
  for (const [t, code] of vectors) assert.equal(otp.totp(RFC_KEY, { time: t * 1000, digits: 8 }), code);
});

test('base32 round-trips and matches RFC 4648', () => {
  assert.equal(otp.base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.equal(otp.base32Decode('MZXW6YTBOI').toString(), 'foobar');
  const buf = require('node:crypto').randomBytes(20);
  assert.deepEqual(otp.base32Decode(otp.base32Encode(buf)), buf);
});

test('TOTP verify: drift window and replay protection', () => {
  const key = otp.base32Decode(otp.generateSecret());
  const now = Date.now();
  const code = otp.totp(key, { time: now });
  const step = otp.verifyTotp(key, code, { time: now });
  assert.notEqual(step, null);
  assert.equal(otp.verifyTotp(key, code, { time: now, lastStep: step }), null, 'replayed code rejected');
  assert.notEqual(otp.verifyTotp(key, otp.totp(key, { time: now - 30_000 }), { time: now }), null, '1 step drift ok');
  assert.equal(otp.verifyTotp(key, otp.totp(key, { time: now - 120_000 }), { time: now }), null, '4 steps old rejected');
  assert.equal(otp.verifyTotp(key, 'abcdef', { time: now }), null);
});

test('HOTP verify: look-ahead resync', () => {
  const key = otp.base32Decode(otp.generateSecret());
  assert.equal(otp.verifyHotp(key, otp.hotp(key, 5), 0), 6);
  assert.equal(otp.verifyHotp(key, otp.hotp(key, 50), 0), null);
});

test('password hashing and encryption', async () => {
  const h = await cu.hashPassword('correct horse battery');
  assert.equal(await cu.verifyPassword(h, 'correct horse battery'), true);
  assert.equal(await cu.verifyPassword(h, 'wrong'), false);
  const k = cu.makeKeyring(require('node:crypto').randomBytes(32));
  const blob = k.encrypt('JBSWY3DPEHPK3PXP');
  assert.equal(k.decrypt(blob), 'JBSWY3DPEHPK3PXP');
  const tampered = blob.slice(0, -2) + (blob.endsWith('A') ? 'B' : 'A') + '=';
  assert.throws(() => k.decrypt(tampered));
});

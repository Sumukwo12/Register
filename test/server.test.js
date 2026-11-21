'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const otp = require('../src/lib/otp');
const { createApp } = require('../src/server');

let app;
let base;

test.before(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mfa-test-'));
  app = createApp({ dataDir: dir, production: false, log: () => {}, rateLimits: { auth: 10_000, global: 10_000 }, baseUrl: 'http://localhost' });
  await new Promise((r) => app.server.listen(0, r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
test.after(() => app.server.close());

/** Minimal client with a cookie jar. */
function client() {
  let cookie = '';
  async function req(method, p, body) {
    const headers = { cookie };
    if (method !== 'GET') Object.assign(headers, { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' });
    const res = await fetch(base + p, { method, headers, body: body ? JSON.stringify(body) : method === 'GET' ? undefined : '{}', redirect: 'manual' });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const text = await res.text();
    let data = {};
    try { data = JSON.parse(text); } catch { /* redirect */ }
    return { status: res.status, data, headers: res.headers };
  }
  return { get: (p) => req('GET', p), post: (p, b) => req('POST', p, b) };
}

const lastCode = (to) => {
  const m = app.notifier.outbox.find((x) => x.to === to);
  return m && m.text.match(/\b(\d{6})\b/)[1];
};
const resetCooldowns = (email) => {
  const u = app.store.findByEmail(email);
  for (const k of Object.keys(u.otps)) u.otps[k].sentAt = 0;
  if (u.magic) u.magic.sentAt = 0;
};

const PASS = 'Sup3r-secret-pass!';

async function registerFresh(email) {
  const c = client();
  const r = await c.post('/api/register', { email, password: PASS });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  return c;
}

async function loginToMfa(email) {
  const c = client();
  const r = await c.post('/api/login', { email, password: PASS });
  assert.equal(r.status, 200);
  assert.equal(r.data.mfaRequired, true);
  return { c, methods: r.data.methods };
}

test('register, login without 2FA, logout', async () => {
  const c = await registerFresh('plain@example.com');
  assert.equal((await c.get('/api/me')).data.authenticated, true);
  await c.post('/api/logout');
  assert.equal((await c.get('/api/me')).data.authenticated, false);
  const r = await c.post('/api/login', { email: 'plain@example.com', password: PASS });
  assert.equal(r.data.mfaRequired, false);
});

test('rejects bad login, weak password, CSRF-less POST', async () => {
  const c = client();
  assert.equal((await c.post('/api/login', { email: 'nobody@example.com', password: 'x' })).status, 401);
  assert.equal((await c.post('/api/register', { email: 'weak@example.com', password: 'short' })).status, 400);
  const res = await fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(res.status, 403);
});

test('TOTP (authenticator app): setup, enable, login, replay blocked', async () => {
  const email = 'totp@example.com';
  const c = await registerFresh(email);
  const setup = await c.post('/api/mfa/totp/setup');
  assert.match(setup.data.otpauthUrl, /^otpauth:\/\/totp\//);
  const key = otp.base32Decode(setup.data.secret);

  assert.equal((await c.post('/api/mfa/totp/enable', { code: '000000' })).status, 400);
  const en = await c.post('/api/mfa/totp/enable', { code: otp.totp(key) });
  assert.equal(en.status, 200);
  assert.equal(en.data.backupCodes.length, 10, 'backup codes auto-issued');

  // Protected routes need a full session; MFA-pending session cannot use them
  const { c: c2, methods } = await loginToMfa(email);
  assert.deepEqual(methods, ['totp', 'backup']);
  assert.equal((await c2.post('/api/mfa/totp/setup')).status, 401);

  const used = otp.totp(key); // same step as enable -> replay
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'totp', code: used })).status, 401);
  const next = otp.totp(key, { time: Date.now() + 30_000 });
  const ok = await c2.post('/api/mfa/challenge/verify', { method: 'totp', code: next });
  assert.equal(ok.status, 200, JSON.stringify(ok.data));
  assert.equal((await c2.get('/api/me')).data.authenticated, true);
});

test('HOTP: setup, enable, login with next counter', async () => {
  const email = 'hotp@example.com';
  const c = await registerFresh(email);
  const s = await c.post('/api/mfa/hotp/setup');
  const key = otp.base32Decode(s.data.secret);
  assert.equal((await c.post('/api/mfa/hotp/enable', { code: otp.hotp(key, 0) })).status, 200);

  const { c: c2 } = await loginToMfa(email);
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'hotp', code: otp.hotp(key, 0) })).status, 401, 'used counter rejected');
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'hotp', code: otp.hotp(key, 1) })).status, 200);
});

test('SMS: setup, enable, login', async () => {
  const email = 'sms@example.com';
  const phone = '+254712345678';
  const c = await registerFresh(email);
  assert.equal((await c.post('/api/mfa/sms/setup', { phone: '0712' })).status, 400);
  assert.equal((await c.post('/api/mfa/sms/setup', { phone })).status, 200);
  assert.equal((await c.post('/api/mfa/sms/enable', { code: lastCode(phone) })).status, 200);

  const { c: c2 } = await loginToMfa(email);
  assert.equal((await c2.post('/api/mfa/challenge/send', { method: 'sms' })).status, 200);
  const code = lastCode(phone);
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'sms', code })).status, 200);
  // code is single-use
  const { c: c3 } = await loginToMfa(email);
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'sms', code })).status, 401);
});

test('Email OTP: setup, enable, login, resend cooldown', async () => {
  const email = 'mail@example.com';
  const c = await registerFresh(email);
  assert.equal((await c.post('/api/mfa/email/setup')).status, 200);
  assert.equal((await c.post('/api/mfa/email/setup')).status, 429, 'cooldown enforced');
  assert.equal((await c.post('/api/mfa/email/enable', { code: lastCode(email) })).status, 200);

  const { c: c2 } = await loginToMfa(email);
  resetCooldowns(email);
  await c2.post('/api/mfa/challenge/send', { method: 'email' });
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'email', code: lastCode(email) })).status, 200);
});

test('Backup codes: single use, regenerate invalidates old', async () => {
  const email = 'backup@example.com';
  const c = await registerFresh(email);
  const key = otp.base32Decode((await c.post('/api/mfa/totp/setup')).data.secret);
  const codes = (await c.post('/api/mfa/totp/enable', { code: otp.totp(key) })).data.backupCodes;

  const { c: c2 } = await loginToMfa(email);
  const r = await c2.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[0].toUpperCase() });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.mfa.backupCodesRemaining, 9);

  const { c: c3 } = await loginToMfa(email);
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[0] })).status, 401, 'reuse blocked');

  assert.equal((await c.post('/api/mfa/backup/generate', { password: 'wrong' })).status, 401);
  const fresh = (await c.post('/api/mfa/backup/generate', { password: PASS })).data.backupCodes;
  assert.equal(fresh.length, 10);
  const { c: c4 } = await loginToMfa(email);
  assert.equal((await c4.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[1] })).status, 401, 'old code invalid');
  assert.equal((await c4.post('/api/mfa/challenge/verify', { method: 'backup', code: fresh[0] })).status, 200);
});

test('Magic link: passwordless login, single use, still requires 2FA when on', async () => {
  const email = 'magic@example.com';
  const c = await registerFresh(email);
  await c.post('/api/logout');

  const unknown = await c.post('/api/magic/request', { email: 'ghost@example.com' });
  assert.equal(unknown.status, 200, 'no account enumeration');

  await c.post('/api/magic/request', { email });
  const link = app.notifier.outbox.find((m) => m.to === email).text.match(/token=([\w-]+)/)[1];
  const r = await c.get(`/api/magic/verify?token=${link}`);
  assert.equal(r.status, 303);
  assert.equal((await c.get('/api/me')).data.authenticated, true);
  const again = await client().get(`/api/magic/verify?token=${link}`);
  assert.match(again.headers.get('location'), /magic-link-invalid/);

  // Turn on email 2FA, then magic link only gets to the MFA step
  await c.post('/api/mfa/email/setup');
  await c.post('/api/mfa/email/enable', { code: lastCode(email) });
  resetCooldowns(email);
  const c2 = client();
  await c2.post('/api/magic/request', { email });
  const t2 = app.notifier.outbox.find((m) => m.to === email && m.text.includes('token=')).text.match(/token=([\w-]+)/)[1];
  await c2.get(`/api/magic/verify?token=${t2}`);
  const me = (await c2.get('/api/me')).data;
  assert.equal(me.authenticated, false);
  assert.equal(me.mfaPending, true);
});

test('Brute force protection: MFA attempt limit and account lockout', async () => {
  const email = 'brute@example.com';
  const c = await registerFresh(email);
  const key = otp.base32Decode((await c.post('/api/mfa/totp/setup')).data.secret);
  await c.post('/api/mfa/totp/enable', { code: otp.totp(key) });

  const { c: c2 } = await loginToMfa(email);
  let last;
  for (let i = 0; i < 5; i++) last = await c2.post('/api/mfa/challenge/verify', { method: 'totp', code: '123456' === otp.totp(key) ? '654321' : '123456' });
  assert.equal(last.data.restart, true, 'session killed after 5 bad codes');
  assert.equal((await c2.get('/api/me')).data.mfaPending, undefined);

  const c3 = client();
  for (let i = 0; i < 5; i++) await c3.post('/api/login', { email, password: 'wrong-password' });
  assert.equal((await c3.post('/api/login', { email, password: PASS })).status, 423, 'locked even with correct password');
});

test('Disable a method requires password; disabling last one clears backup codes', async () => {
  const email = 'disable@example.com';
  const c = await registerFresh(email);
  await c.post('/api/mfa/email/setup');
  await c.post('/api/mfa/email/enable', { code: lastCode(email) });
  assert.equal((await c.post('/api/mfa/disable', { method: 'email', password: 'nope' })).status, 401);
  const r = await c.post('/api/mfa/disable', { method: 'email', password: PASS });
  assert.equal(r.data.user.mfaEnabled, false);
  assert.equal(r.data.user.mfa.backupCodesRemaining, 0);
});

test('2FA secrets are encrypted at rest and codes are hashed', async () => {
  const raw = fs.readFileSync(app.store.file, 'utf8');
  const u = app.store.findByEmail('totp@example.com');
  assert.ok(u.mfa.totp.secretEnc.includes('.'));
  assert.ok(!raw.includes(PASS));
  for (const m of app.notifier.outbox) {
    const code = m.text.match(/\b(\d{6})\b/)?.[1];
    if (code) assert.ok(!raw.includes(`"${code}"`));
  }
});

test('serves UI with security headers', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal((await fetch(base + '/../package.json')).status, 404);
});

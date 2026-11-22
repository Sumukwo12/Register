'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const otp = require('../src/lib/otp');
const { createApp } = require('../src/server');
const { FakeAuthenticator } = require('./fake-authenticator');

const BREACHED = 'password1234567';
let app;
let base;

function startApp(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mfa-test-'));
  return createApp({
    dataDir: dir,
    production: false,
    log: () => {},
    rateLimits: { auth: 10_000, global: 10_000, send: 10_000 },
    baseUrl: 'http://localhost',
    trustProxy: true,
    breachCheck: async (p) => (p === BREACHED ? 42 : 0),
    ...extra,
  });
}

test.before(async () => {
  app = startApp();
  await new Promise((r) => app.server.listen(0, r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
test.after(() => app.server.close());

/** Minimal client with a cookie jar. `ip` is sent as X-Forwarded-For. */
function client(ip = '10.0.0.1') {
  let cookie = '';
  async function req(method, p, body) {
    const headers = { cookie, 'X-Forwarded-For': ip };
    if (method !== 'GET') Object.assign(headers, { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' });
    const res = await fetch(base + p, { method, headers, body: body ? JSON.stringify(body) : method === 'GET' ? undefined : '{}', redirect: 'manual' });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    const text = await res.text();
    let data = {};
    try {
      data = JSON.parse(text);
    } catch {
      // not JSON
    }
    return { status: res.status, data, headers: res.headers };
  }
  return { get: (p) => req('GET', p), post: (p, b) => req('POST', p, b) };
}

const messagesTo = (to) => app.notifier.outbox.filter((m) => m.to === to);
const lastCode = (to) => messagesTo(to).find((m) => /code is \d{6}/.test(m.text))?.text.match(/code is (\d{6})/)[1];
const lastMagic = (to) => messagesTo(to).find((m) => m.text.includes('#magic='))?.text.match(/#magic=([\w-]+)/)[1];
const resetCooldowns = (email) => {
  const u = app.store.findByEmail(email);
  for (const k of Object.keys(u.otps)) u.otps[k].sentAt = 0;
  if (u.magic) u.magic.sentAt = 0;
};

const PASS = 'Sup3r-secret-pass!';

async function registerFresh(email, c = client()) {
  const r = await c.post('/api/register', { email, password: PASS });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.verifyRequired, true);
  const v = await c.post('/api/register/verify', { code: lastCode(email) });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  return c;
}

async function loginToMfa(email, ip) {
  const c = client(ip);
  const r = await c.post('/api/login', { email, password: PASS });
  assert.equal(r.status, 200, JSON.stringify(r.data));
  assert.equal(r.data.mfaRequired, true);
  return { c, methods: r.data.methods };
}

async function enableTotp(c) {
  const key = otp.base32Decode((await c.post('/api/mfa/totp/setup')).data.secret);
  const r = await c.post('/api/mfa/totp/enable', { code: otp.totp(key) });
  return { key, backupCodes: r.data.backupCodes };
}

test('register, confirm email, login without 2FA, logout', async () => {
  const c = await registerFresh('plain@example.com');
  assert.equal((await c.get('/api/me')).data.authenticated, true);
  await c.post('/api/logout');
  assert.equal((await c.get('/api/me')).data.authenticated, false);
  const r = await c.post('/api/login', { email: 'plain@example.com', password: PASS });
  assert.equal(r.data.mfaRequired, false);
});

test('rejects bad login, weak or breached password, CSRF-less POST', async () => {
  const c = client();
  assert.equal((await c.post('/api/login', { email: 'nobody@example.com', password: 'x' })).status, 401);
  assert.equal((await c.post('/api/register', { email: 'weak@example.com', password: 'short' })).status, 400);
  const breached = await c.post('/api/register', { email: 'weak@example.com', password: BREACHED });
  assert.equal(breached.status, 400);
  assert.match(breached.data.error, /breach/);
  const res = await fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(res.status, 403);
});

test('email verification: required before use, wrong codes limited, resend works', async () => {
  const email = 'unverified@example.com';
  const c = client();
  await c.post('/api/register', { email, password: PASS });
  assert.equal((await c.get('/api/me')).data.verifyPending, true);
  assert.equal((await c.post('/api/mfa/totp/setup')).status, 401, 'no access before confirming');

  // Signing in before confirming leads back to the confirmation step
  const c2 = client();
  const login = await c2.post('/api/login', { email, password: PASS });
  assert.equal(login.data.verifyRequired, true);

  assert.equal((await c2.post('/api/register/resend')).status, 429, 'resend cooldown');
  const wrong = lastCode(email) === '000000' ? '111111' : '000000';
  for (let i = 0; i < 4; i++) assert.equal((await c2.post('/api/register/verify', { code: wrong })).status, 401);
  const last = await c2.post('/api/register/verify', { code: wrong });
  assert.equal(last.data.restart, true);
  assert.equal((await c.post('/api/register/verify', { code: lastCode(email) })).status, 401, 'guessed-at code is burned');

  // After the cooldown, a new code can be requested and used.
  resetCooldowns(email);
  for (const s of app.sessions.values()) s.sentAt = 0;
  assert.equal((await c.post('/api/register/resend')).status, 200);
  assert.equal((await c.post('/api/register/verify', { code: lastCode(email) })).status, 200);
  assert.equal(app.store.findByEmail(email).emailVerified, true);
});

test('sign-up does not reveal existing accounts, and an unconfirmed sign-up can be replaced', async () => {
  const email = 'taken@example.com';
  await registerFresh(email);
  const before = messagesTo(email).length;

  const attacker = client('10.9.9.9');
  const r = await attacker.post('/api/register', { email, password: 'Another-long-pass1' });
  assert.equal(r.status, 200);
  assert.equal(r.data.verifyRequired, true, 'same response as a new sign-up');
  assert.equal((await attacker.post('/api/register/verify', { code: '123456' })).status, 401);
  assert.equal(messagesTo(email).length, before + 1);
  assert.match(messagesTo(email)[0].subject, /Sign-up attempt/);
  assert.equal((await client().post('/api/login', { email, password: PASS })).status, 200, 'real account unchanged');

  // Someone signs up with an address they don't own and never confirms...
  const squatted = 'squatted@example.com';
  await client('10.9.9.9').post('/api/register', { email: squatted, password: 'Squatter-pass-123' });
  // ...the real owner can still sign up.
  await registerFresh(squatted);
  assert.equal((await client().post('/api/login', { email: squatted, password: 'Squatter-pass-123' })).status, 401);
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

  const { c: c2, methods } = await loginToMfa(email);
  assert.deepEqual(methods, ['totp', 'backup']);
  assert.equal((await c2.post('/api/mfa/totp/setup')).status, 401, 'pending session cannot use protected routes');

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
  const { c: c3 } = await loginToMfa(email);
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'sms', code })).status, 401, 'code is single use');
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

test('Passkey: register, sign in, reject replayed or wrong-origin assertions', async () => {
  const email = 'passkey@example.com';
  const c = await registerFresh(email);
  const auth = new FakeAuthenticator({ origin: 'http://localhost', rpId: 'localhost' });

  const opts = (await c.post('/api/mfa/passkey/setup')).data.publicKey;
  assert.equal(opts.rp.id, 'localhost');
  assert.equal(opts.attestation, 'none');
  const en = await c.post('/api/mfa/passkey/enable', { credential: auth.create(opts) });
  assert.equal(en.status, 200, JSON.stringify(en.data));
  assert.equal(en.data.user.mfa.passkey, true);
  assert.equal(en.data.backupCodes.length, 10);
  assert.equal((await c.post('/api/mfa/passkey/enable', { credential: auth.create(opts) })).status, 400, 'setup challenge is single use');

  const { c: c2, methods } = await loginToMfa(email);
  assert.deepEqual(methods, ['passkey', 'backup']);
  const login = (await c2.post('/api/mfa/passkey/options')).data.publicKey;
  assert.deepEqual(login.allowCredentials.map((x) => x.id), [auth.id]);
  const assertion = auth.get(login);
  assert.equal((await c2.post('/api/mfa/challenge/verify', { method: 'passkey', credential: assertion })).status, 200);

  // Replaying the same signed response fails: the challenge was used up.
  const { c: c3 } = await loginToMfa(email);
  await c3.post('/api/mfa/passkey/options');
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'passkey', credential: assertion })).status, 401);

  // A phishing site's origin is rejected even with a valid signature.
  const phished = auth.get((await c3.post('/api/mfa/passkey/options')).data.publicKey, { origin: 'http://evil.example' });
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'passkey', credential: phished })).status, 401);
});

test('Backup codes: single use, regenerate invalidates old', async () => {
  const email = 'backup@example.com';
  const c = await registerFresh(email);
  const { backupCodes: codes } = await enableTotp(c);

  const { c: c2 } = await loginToMfa(email);
  const r = await c2.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[0].toUpperCase() });
  assert.equal(r.status, 200);
  assert.equal(r.data.user.mfa.backupCodesRemaining, 9);
  assert.match(messagesTo(email)[0].subject, /Backup code used/);

  const { c: c3 } = await loginToMfa(email);
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[0] })).status, 401, 'reuse blocked');

  assert.equal((await c.post('/api/mfa/backup/generate', { password: 'wrong' })).status, 401);
  const fresh = (await c.post('/api/mfa/backup/generate', { password: PASS })).data.backupCodes;
  assert.equal(fresh.length, 10);
  const { c: c4 } = await loginToMfa(email);
  assert.equal((await c4.post('/api/mfa/challenge/verify', { method: 'backup', code: codes[1] })).status, 401, 'old code invalid');
  assert.equal((await c4.post('/api/mfa/challenge/verify', { method: 'backup', code: fresh[0] })).status, 200);
});

test('Magic link: token only used by POST, single use, still requires 2FA when on', async () => {
  const email = 'magic@example.com';
  const c = await registerFresh(email);
  await c.post('/api/logout');

  const unknown = await c.post('/api/magic/request', { email: 'ghost@example.com' });
  assert.equal(unknown.status, 200, 'no account enumeration');

  await c.post('/api/magic/request', { email });
  const token = lastMagic(email);
  // An email scanner opening the link only loads the page; the token stays valid.
  assert.equal((await fetch(`${base}/#magic=${token}`)).status, 200);
  assert.equal((await c.post('/api/magic/verify', { token })).data.mfaRequired, false);
  assert.equal((await c.get('/api/me')).data.authenticated, true);
  assert.equal((await client().post('/api/magic/verify', { token })).status, 400, 'single use');

  // With 2FA on, the link only gets to the second step
  await c.post('/api/mfa/email/setup');
  await c.post('/api/mfa/email/enable', { code: lastCode(email) });
  resetCooldowns(email);
  const c2 = client();
  await c2.post('/api/magic/request', { email });
  const r = await c2.post('/api/magic/verify', { token: lastMagic(email) });
  assert.equal(r.data.mfaRequired, true);
  assert.equal((await c2.get('/api/me')).data.mfaPending, true);
});

test('Wrong passwords lock out that IP for that account, not the real owner', async () => {
  const email = 'lockout@example.com';
  await registerFresh(email);

  const attacker = client('10.6.6.6');
  for (let i = 0; i < 5; i++) assert.equal((await attacker.post('/api/login', { email, password: 'wrong-password' })).status, 401);
  assert.equal((await attacker.post('/api/login', { email, password: PASS })).status, 423, 'attacker IP locked even with correct password');
  assert.equal((await client('10.7.7.7').post('/api/login', { email, password: PASS })).status, 200, 'owner on another IP unaffected');

  // Unknown accounts lock the same way, so a lockout doesn't reveal that an account exists.
  for (let i = 0; i < 5; i++) await attacker.post('/api/login', { email: 'ghost@example.com', password: 'wrong-password' });
  assert.equal((await attacker.post('/api/login', { email: 'ghost@example.com', password: 'x' })).status, 423);
});

test('Wrong 2FA codes are limited per account across logins, with an alert', async () => {
  const email = 'mfabrute@example.com';
  const c = await registerFresh(email);
  const { key } = await enableTotp(c);
  const bad = () => (otp.totp(key) === '123456' ? '654321' : '123456');

  const { c: c2 } = await loginToMfa(email, '10.1.1.1');
  let last;
  for (let i = 0; i < 5; i++) last = await c2.post('/api/mfa/challenge/verify', { method: 'totp', code: bad() });
  assert.equal(last.data.restart, true, 'session ends after 5 wrong codes');

  // Logging in again (even from another IP) doesn't reset the account's count.
  const { c: c3 } = await loginToMfa(email, '10.2.2.2');
  for (let i = 0; i < 4; i++) assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'totp', code: bad() })).status, 401);
  assert.equal((await c3.post('/api/mfa/challenge/verify', { method: 'totp', code: bad() })).status, 423);
  assert.match(messagesTo(email)[0].subject, /Repeated failed sign-in attempts/);

  const { c: c4 } = await loginToMfa(email, '10.3.3.3');
  const right = otp.totp(key, { time: Date.now() + 30_000 });
  assert.equal((await c4.post('/api/mfa/challenge/verify', { method: 'totp', code: right })).status, 423, 'locked even with the right code');
  const u = app.store.findByEmail(email);
  assert.ok(u.mfaLockedUntil - Date.now() > 14 * 60_000);
});

test('Security alerts: new IP, method changes; turning a method off signs out other sessions', async () => {
  const email = 'alerts@example.com';
  const c = await registerFresh(email, client('10.4.4.4'));
  await client('10.4.4.4').post('/api/login', { email, password: PASS });
  assert.equal(messagesTo(email).filter((m) => /New sign-in/.test(m.subject)).length, 0, 'known IP: no alert');
  await client('10.5.5.5').post('/api/login', { email, password: PASS });
  assert.match(messagesTo(email)[0].subject, /New sign-in/);

  await c.post('/api/mfa/email/setup');
  await c.post('/api/mfa/email/enable', { code: lastCode(email) });
  assert.match(messagesTo(email)[0].subject, /Email codes turned on/);

  const other = client('10.4.4.4');
  await other.post('/api/login', { email, password: PASS });
  resetCooldowns(email);
  await other.post('/api/mfa/challenge/send', { method: 'email' });
  await other.post('/api/mfa/challenge/verify', { method: 'email', code: lastCode(email) });
  assert.equal((await other.get('/api/me')).data.authenticated, true);

  await c.post('/api/mfa/disable', { method: 'email', password: PASS });
  assert.match(messagesTo(email)[0].subject, /Email codes turned off/);
  assert.equal((await other.get('/api/me')).data.authenticated, false, 'other session signed out');
  assert.equal((await c.get('/api/me')).data.authenticated, true, 'current session kept');
});

test('Sign out other devices', async () => {
  const email = 'devices@example.com';
  const a = await registerFresh(email);
  const b = client();
  await b.post('/api/login', { email, password: PASS });
  assert.equal((await a.post('/api/sessions/revoke-others')).status, 200);
  assert.equal((await b.get('/api/me')).data.authenticated, false);
  assert.equal((await a.get('/api/me')).data.authenticated, true);
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

test('change password: needs current password, rejects breached, signs out other sessions', async () => {
  const email = 'chpass@example.com';
  const a = await registerFresh(email);
  const b = client();
  await b.post('/api/login', { email, password: PASS });
  assert.equal((await b.get('/api/me')).data.authenticated, true);

  assert.equal((await a.post('/api/password', { currentPassword: 'wrong', newPassword: 'Another-long-pass1' })).status, 401);
  assert.equal((await a.post('/api/password', { currentPassword: PASS, newPassword: 'short' })).status, 400);
  assert.equal((await a.post('/api/password', { currentPassword: PASS, newPassword: BREACHED })).status, 400);
  assert.equal((await a.post('/api/password', { currentPassword: PASS, newPassword: 'Another-long-pass1' })).status, 200);
  assert.match(messagesTo(email)[0].subject, /Password changed/);

  assert.equal((await a.get('/api/me')).data.authenticated, true);
  assert.equal((await b.get('/api/me')).data.authenticated, false);
  assert.equal((await client().post('/api/login', { email, password: PASS })).status, 401);
  assert.equal((await client().post('/api/login', { email, password: 'Another-long-pass1' })).status, 200);
});

test('2FA secrets are encrypted at rest and codes are hashed', async () => {
  const raw = fs.readFileSync(app.store.file, 'utf8');
  const u = app.store.findByEmail('totp@example.com');
  assert.ok(u.mfa.totp.secretEnc.includes('.'));
  assert.ok(!raw.includes(PASS));
  for (const m of app.notifier.outbox) {
    const code = m.text.match(/code is (\d{6})/)?.[1];
    if (code) assert.ok(!raw.includes(`"${code}"`));
  }
});

test('serves UI with security headers', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal((await fetch(base + '/../package.json')).status, 404);
  assert.doesNotMatch(res.headers.get('content-security-policy'), /https?:/);
});

test('malformed Origin and cookie headers get 4xx, not 500', async () => {
  const post = (headers) => fetch(base + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch', ...headers },
    body: '{}',
  });
  assert.equal((await post({ Origin: 'null' })).status, 403);
  assert.equal((await post({ Origin: 'https://evil.example' })).status, 403);
  assert.equal((await post({ Cookie: 'sid=%E0%A4%A' })).status, 401);
});

test('code sending is rate limited per IP', async () => {
  const limited = startApp({ rateLimits: { auth: 10_000, global: 10_000, send: 2 } });
  await new Promise((r) => limited.server.listen(0, r));
  const url = `http://127.0.0.1:${limited.server.address().port}/api/magic/request`;
  const send = () => fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: JSON.stringify({ email: 'x@example.com' }),
  });
  try {
    assert.equal((await send()).status, 200);
    assert.equal((await send()).status, 200);
    assert.equal((await send()).status, 429);
  } finally {
    limited.server.close();
  }
});

test('refuses to start in production without APP_SECRET', () => {
  const saved = process.env.APP_SECRET;
  delete process.env.APP_SECRET;
  try {
    assert.throws(() => startApp({ production: true }), /APP_SECRET/);
  } finally {
    if (saved !== undefined) process.env.APP_SECRET = saved;
  }
});

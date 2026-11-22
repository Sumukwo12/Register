'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const otp = require('./lib/otp');
const cu = require('./lib/crypto-utils');
const webauthn = require('./lib/webauthn');
const { Store } = require('./lib/store');
const { Notifier } = require('./lib/notify');

const CONFIG = {
  issuer: process.env.APP_NAME || 'SecureApp',
  otpTtlMs: 5 * 60_000, // SMS / email codes valid 5 minutes
  otpMaxAttempts: 5, // wrong guesses allowed per code
  otpResendMs: 30_000, // cooldown between sends
  magicTtlMs: 15 * 60_000,
  sessionTtlMs: 8 * 3600_000,
  pendingSessionTtlMs: 10 * 60_000, // time allowed to finish 2FA or email verification
  webauthnTtlMs: 5 * 60_000,
  loginFailsPerIp: 5, // wrong passwords per account per IP before that IP is locked out
  loginFailsPerAccountHour: 100, // wrong passwords per account per hour (all IPs) before the account is locked
  lockMs: 15 * 60_000,
  mfaFailsPerSession: 5,
  mfaFailsPerAccount: 10, // wrong codes across all logins before 2FA is locked
  mfaMaxLockMs: 24 * 3600_000, // lock doubles each time, up to this
  backupCount: 10,
  maxPasskeys: 10,
  knownIps: 20,
  maxBodyBytes: 16 * 1024,
};

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const PHONE_RE = /^\+[1-9]\d{7,14}$/; // E.164
const CODE_RE = /^\d{6}$/;
const PRIMARY = ['passkey', 'totp', 'hotp', 'email', 'sms'];

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function emptyMfa() {
  return {
    passkey: { enabled: false, credentials: [] },
    totp: { enabled: false, secretEnc: null, pendingSecretEnc: null, lastStep: -1 },
    hotp: { enabled: false, secretEnc: null, pendingSecretEnc: null, counter: 0 },
    sms: { enabled: false, phone: null, pendingPhone: null },
    email: { enabled: false },
    backup: { hashes: [] },
  };
}

function createApp(opts = {}) {
  const dataDir = opts.dataDir || path.join(__dirname, '..', 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const production = opts.production ?? process.env.NODE_ENV === 'production';
  if (production && !process.env.APP_SECRET) {
    throw new Error('APP_SECRET must be set in production. Without it the encryption key is stored next to the database.');
  }
  const baseUrl = (opts.baseUrl || process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
  const rp = { id: new URL(baseUrl).hostname, origin: new URL(baseUrl).origin, name: CONFIG.issuer };
  const trustProxy = opts.trustProxy ?? process.env.TRUST_PROXY === '1';
  const limits = { auth: 30, send: 10, global: 300, ...(opts.rateLimits || {}) };
  const log = opts.log ?? console.log;
  const breachCheck = opts.breachCheck !== undefined
    ? opts.breachCheck
    : process.env.BREACH_CHECK === '0' ? null : cu.pwnedPasswordCount;
  const publicDir = path.join(__dirname, '..', 'public');

  const store = new Store(dataDir);
  for (const u of store.allUsers()) {
    // Fill in fields added after the account was created.
    const fresh = emptyMfa();
    for (const k of Object.keys(fresh)) u.mfa[k] ??= fresh[k];
    u.knownIps ??= [];
  }
  const keys = cu.makeKeyring(cu.loadMasterKey(dataDir));
  const notifier = new Notifier({ production, log });
  const sessions = new Map();
  const buckets = new Map();
  const loginFails = new Map(); // `${email}|${ip}` -> { count, reset, lockedUntil }
  const dummyHash = cu.hashPassword(crypto.randomBytes(16).toString('hex'));

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, s] of sessions) if (s.expires < now) sessions.delete(k);
    for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
    for (const [k, f] of loginFails) if (f.reset < now && f.lockedUntil < now) loginFails.delete(k);
  }, 60_000);
  sweeper.unref();

  function rateLimit(key, limit, windowMs = 60_000) {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.reset < now) {
      b = { count: 0, reset: now + windowMs };
      buckets.set(key, b);
    }
    if (++b.count > limit) {
      throw new HttpError(429, 'Too many requests. Please slow down.', { retryAfter: Math.ceil((b.reset - now) / 1000) });
    }
  }

  const retryIn = (until) => Math.ceil((until - Date.now()) / 1000);

  function parseCookies(req) {
    const out = {};
    for (const part of (req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i <= 0) continue;
      try {
        out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        // ignore malformed cookie values
      }
    }
    return out;
  }

  function setCookie(res, value, maxAgeMs) {
    const attrs = [`sid=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.floor(maxAgeMs / 1000)}`];
    if (production) attrs.push('Secure');
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  function getSession(req) {
    const sid = parseCookies(req).sid;
    if (!sid) return null;
    const s = sessions.get(sid);
    if (!s) return null;
    if (s.expires < Date.now()) {
      sessions.delete(sid);
      return null;
    }
    return s;
  }

  /**
   * Always issues a new session id (prevents session fixation).
   * stage: 'verify' (email not confirmed) | 'mfa' (password ok, 2nd factor pending) | 'full'
   */
  function createSession(res, old, userId, stage, extra = {}) {
    if (old) sessions.delete(old.sid);
    const sid = cu.randomToken(32);
    const ttl = stage === 'full' ? CONFIG.sessionTtlMs : CONFIG.pendingSessionTtlMs;
    const s = { sid, userId, stage, expires: Date.now() + ttl, fails: 0, ...extra };
    sessions.set(sid, s);
    setCookie(res, sid, ttl);
    return s;
  }

  function revokeSessions(userId, keepSid) {
    for (const [sid, s] of sessions) if (s.userId === userId && sid !== keepSid) sessions.delete(sid);
  }

  function destroySession(res, s) {
    if (s) sessions.delete(s.sid);
    setCookie(res, '', 0);
  }

  function newUser(email, passwordHash) {
    return {
      id: crypto.randomUUID(),
      email,
      emailVerified: false,
      passwordHash,
      createdAt: new Date().toISOString(),
      lockedUntil: 0,
      mfa: emptyMfa(),
      otps: {},
      magic: null,
      knownIps: [],
    };
  }

  const isVerified = (u) => u.emailVerified !== false;
  const mfaEnabled = (u) => PRIMARY.some((m) => u.mfa[m].enabled);
  function enabledMethods(u) {
    const list = PRIMARY.filter((m) => u.mfa[m].enabled);
    if (list.length && u.mfa.backup.hashes.length) list.push('backup');
    return list;
  }

  function checkPasswordPolicy(password, email) {
    if (password.length < 10 || password.length > 256) throw new HttpError(400, 'Password must be 10-256 characters.');
    const name = email.split('@')[0];
    if (name.length >= 3 && password.toLowerCase().includes(name)) throw new HttpError(400, 'Password must not contain your email name.');
  }

  async function rejectBreached(password) {
    if (!breachCheck) return;
    let count = 0;
    try {
      count = await breachCheck(password);
    } catch (err) {
      // Fail open: an outage at the breach service shouldn't block sign-ups.
      log('[warn] breached-password check failed:', err.message);
      return;
    }
    if (count > 0) throw new HttpError(400, 'This password has appeared in a known data breach. Choose a different one.');
  }

  const maskPhone = (p) => (p ? `${p.slice(0, 3)}${'*'.repeat(Math.max(0, p.length - 5))}${p.slice(-2)}` : null);
  const maskEmail = (e) => e.replace(/^(.)(.*)(@.*)$/, (_, a, b, c) => a + '*'.repeat(Math.min(b.length, 6)) + c);

  function publicUser(u) {
    return {
      id: u.id,
      email: u.email,
      mfaEnabled: mfaEnabled(u),
      mfa: {
        passkey: u.mfa.passkey.enabled,
        passkeys: u.mfa.passkey.credentials.map((c) => ({ id: c.id, name: c.name, createdAt: c.createdAt })),
        totp: u.mfa.totp.enabled,
        hotp: u.mfa.hotp.enabled,
        sms: u.mfa.sms.enabled,
        smsPhone: maskPhone(u.mfa.sms.phone),
        email: u.mfa.email.enabled,
        backupCodesRemaining: u.mfa.backup.hashes.length,
      },
    };
  }

  function mfaPrompt(u) {
    return { methods: enabledMethods(u), email: maskEmail(u.email), smsPhone: maskPhone(u.mfa.sms.phone) };
  }

  /** Security notice by email. Never fails the request that triggered it. */
  async function alert(user, subject, text) {
    try {
      await notifier.email(user.email, `${CONFIG.issuer}: ${subject}`, `${text}\n\nTime: ${new Date().toUTCString()}`);
    } catch (err) {
      log('[warn] could not send security alert:', err.message);
    }
  }

  const METHOD_NAMES = { passkey: 'Passkey', totp: 'Authenticator app', hotp: 'Hardware token', sms: 'Text message', email: 'Email codes' };

  /** Creates a full session and emails the user if this IP hasn't signed in before. */
  async function completeSignIn(res, session, user, ip) {
    createSession(res, session, user.id, 'full');
    const ipHash = keys.hashToken(`ip:${ip}`);
    if (!user.knownIps.includes(ipHash)) {
      const firstEver = user.knownIps.length === 0;
      user.knownIps = [ipHash, ...user.knownIps].slice(0, CONFIG.knownIps);
      store.save();
      if (!firstEver) {
        await alert(user, 'New sign-in', `Your account was signed in to from a new location (IP ${ip}).\nIf this wasn't you, change your password now.`);
      }
    }
  }

  // One-time codes (SMS / email)
  async function sendCode(user, purpose, channel, destination) {
    const prev = user.otps[purpose];
    if (prev && Date.now() - prev.sentAt < CONFIG.otpResendMs) {
      throw new HttpError(429, 'Please wait before requesting another code.', {
        retryAfter: Math.ceil((CONFIG.otpResendMs - (Date.now() - prev.sentAt)) / 1000),
      });
    }
    const code = cu.numericCode(6);
    user.otps[purpose] = { hash: keys.hashToken(code), expires: Date.now() + CONFIG.otpTtlMs, attempts: 0, sentAt: Date.now() };
    store.save();
    const text = `Your ${CONFIG.issuer} verification code is ${code}. It expires in 5 minutes. Never share it.`;
    if (channel === 'sms') await notifier.sms(destination, text);
    else await notifier.email(destination, `${CONFIG.issuer} verification code`, text);
  }

  function checkCode(user, purpose, code) {
    const rec = user.otps[purpose];
    if (!rec) return false;
    if (rec.expires < Date.now()) {
      delete user.otps[purpose];
      store.save();
      return false;
    }
    rec.attempts += 1;
    if (rec.attempts > CONFIG.otpMaxAttempts) {
      delete user.otps[purpose];
      store.save();
      return false;
    }
    if (otp.safeEqual(rec.hash, keys.hashToken(code))) {
      delete user.otps[purpose]; // single use
      store.save();
      return true;
    }
    store.save();
    return false;
  }

  function issueBackupCodes(user) {
    const codes = cu.backupCodes(CONFIG.backupCount);
    user.mfa.backup.hashes = codes.map((c) => keys.hashToken(cu.normalizeBackupCode(c)));
    return codes;
  }

  function requireCode(code) {
    if (typeof code !== 'string' || !CODE_RE.test(code.trim())) throw new HttpError(400, 'Enter the 6-digit code.');
    return code.trim();
  }

  function newChallenge(session, type) {
    const challenge = cu.randomToken(32);
    session.webauthn = { challenge, type, expires: Date.now() + CONFIG.webauthnTtlMs };
    return challenge;
  }

  /** Single use: the challenge is cleared whether or not it's valid. */
  function takeChallenge(session, type) {
    const w = session.webauthn;
    session.webauthn = null;
    if (!w || w.type !== type || w.expires < Date.now()) return null;
    return w.challenge;
  }

  /** Verify a second factor. Mutates replay/counter state on success. */
  function verifyFactor(user, body, session) {
    const m = user.mfa;
    const rawCode = body.code;
    switch (body.method) {
      case 'passkey': {
        if (!m.passkey.enabled) return false;
        const challenge = takeChallenge(session, 'get');
        const cred = body.credential;
        const stored = challenge && cred && m.passkey.credentials.find((c) => c.id === cred.id);
        if (!stored) return false;
        try {
          const { signCount } = webauthn.verifyAssertion({ credential: stored, response: cred.response, challenge, origin: rp.origin, rpId: rp.id });
          stored.signCount = signCount;
          stored.lastUsedAt = new Date().toISOString();
          return true;
        } catch (err) {
          log('[info] passkey assertion rejected:', err.message);
          return false;
        }
      }
      case 'totp': {
        if (!m.totp.enabled) return false;
        const step = otp.verifyTotp(otp.base32Decode(keys.decrypt(m.totp.secretEnc)), requireCode(rawCode), { lastStep: m.totp.lastStep });
        if (step === null) return false;
        m.totp.lastStep = step;
        return true;
      }
      case 'hotp': {
        if (!m.hotp.enabled) return false;
        const next = otp.verifyHotp(otp.base32Decode(keys.decrypt(m.hotp.secretEnc)), requireCode(rawCode), m.hotp.counter);
        if (next === null) return false;
        m.hotp.counter = next;
        return true;
      }
      case 'sms':
        return m.sms.enabled && checkCode(user, 'login-sms', requireCode(rawCode));
      case 'email':
        return m.email.enabled && checkCode(user, 'login-email', requireCode(rawCode));
      case 'backup': {
        const h = keys.hashToken(cu.normalizeBackupCode(rawCode || ''));
        const idx = m.backup.hashes.findIndex((x) => otp.safeEqual(x, h));
        if (idx === -1) return false;
        m.backup.hashes.splice(idx, 1); // single use
        return true;
      }
      default:
        throw new HttpError(400, 'Unknown 2FA method.');
    }
  }

  function assertMfaNotLocked(user) {
    if (user.mfaLockedUntil > Date.now()) {
      throw new HttpError(423, 'Too many failed verification attempts on this account. Try again later.', {
        retryAfter: retryIn(user.mfaLockedUntil),
        restart: true,
      });
    }
  }

  /** Counts a wrong second factor against the account, across all logins. */
  async function recordMfaFailure(user) {
    const now = Date.now();
    if (!user.mfaFailStart || user.mfaFailStart + 3600_000 < now) {
      user.mfaFailStart = now;
      user.mfaFails = 0;
    }
    user.mfaFails += 1;
    if (user.mfaFails < CONFIG.mfaFailsPerAccount) {
      store.save();
      return false;
    }
    // Each lock lasts twice as long as the last one.
    user.mfaLockCount = (user.mfaLockCount || 0) + 1;
    user.mfaLockedUntil = now + Math.min(CONFIG.lockMs * 2 ** (user.mfaLockCount - 1), CONFIG.mfaMaxLockMs);
    user.mfaFails = 0;
    store.save();
    revokeSessions(user.id); // drop every pending login for this account
    await alert(user, 'Repeated failed sign-in attempts',
      'Someone entered your password correctly but then failed two-step verification several times.\n'
      + 'Two-step sign-in is paused for a while. If this wasn\'t you, change your password now.');
    return true;
  }

  async function recordLoginFailure(key, user) {
    const now = Date.now();
    let f = loginFails.get(key);
    if (!f || (f.reset < now && f.lockedUntil < now)) f = { count: 0, reset: now + CONFIG.lockMs, lockedUntil: 0 };
    f.count += 1;
    if (f.count >= CONFIG.loginFailsPerIp) {
      f.lockedUntil = now + CONFIG.lockMs;
      f.reset = f.lockedUntil;
      f.count = 0;
    }
    loginFails.set(key, f);
    if (!user) return;

    if (!user.failWindow || user.failWindow.start + 3600_000 < now) user.failWindow = { start: now, count: 0 };
    user.failWindow.count += 1;
    if (user.failWindow.count >= CONFIG.loginFailsPerAccountHour) {
      user.lockedUntil = now + CONFIG.lockMs;
      user.failWindow = null;
      store.save();
      await alert(user, 'Account temporarily locked',
        'There were a large number of failed sign-in attempts on your account, so it is locked for 15 minutes.\n'
        + 'Your password was not accepted. If you use this password anywhere else, change it there too.');
      return;
    }
    store.save();
  }

  /** After enabling the first 2FA method, auto-issue backup codes so the user can't get locked out. */
  function maybeInitialBackup(user) {
    if (user.mfa.backup.hashes.length === 0) return issueBackupCodes(user);
    return undefined;
  }

  async function methodEnabled(user, method) {
    const backupCodes = maybeInitialBackup(user);
    store.save();
    await alert(user, `${METHOD_NAMES[method]} turned on`, `${METHOD_NAMES[method]} was added as a way to verify sign-ins.\nIf this wasn't you, change your password and review your security settings.`);
    return { ok: true, user: publicUser(user), backupCodes };
  }

  async function requirePassword(user, password) {
    if (!(await cu.verifyPassword(user.passwordHash, String(password || '')))) throw new HttpError(401, 'Password is incorrect.');
  }

  const routes = {
    'GET /api/me': {
      auth: 'none',
      handler: ({ session, user }) => {
        if (session?.stage === 'verify') return { authenticated: false, verifyPending: true, email: maskEmail(session.email) };
        if (!session || !user) return { authenticated: false };
        if (session.stage === 'mfa') return { authenticated: false, mfaPending: true, ...mfaPrompt(user) };
        return { authenticated: true, user: publicUser(user) };
      },
    },

    // Sign-up. The response is the same whether or not the email is already registered.
    'POST /api/register': {
      auth: 'none',
      handler: async ({ body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        rateLimit(`send:${ip}`, limits.send);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Enter a valid email address.');
        checkPasswordPolicy(password, email);
        await rejectBreached(password);
        const passwordHash = await cu.hashPassword(password);
        const reply = { ok: true, verifyRequired: true, email: maskEmail(email) };

        const existing = store.findByEmail(email);
        if (existing && isVerified(existing)) {
          createSession(res, session, null, 'verify', { email, sentAt: Date.now() });
          await alert(existing, 'Sign-up attempt', 'Someone tried to create a new account with this email address.\nIf it was you, sign in instead. Your account has not changed.');
          return reply;
        }
        // An unconfirmed sign-up can't hold an address hostage: a new sign-up replaces it.
        if (existing) store.deleteUser(existing.id);
        const user = store.addUser(newUser(email, passwordHash));
        await sendCode(user, 'verify-email', 'email', email);
        createSession(res, session, user.id, 'verify', { email, sentAt: Date.now() });
        return reply;
      },
    },

    'POST /api/register/verify': {
      auth: 'verify',
      handler: async ({ body, user, session, res, ip }) => {
        rateLimit(`mfa:${ip}`, limits.auth);
        const code = requireCode(body.code);
        if (!user || !checkCode(user, 'verify-email', code)) {
          session.fails += 1;
          if (session.fails >= CONFIG.mfaFailsPerSession) {
            destroySession(res, session);
            throw new HttpError(401, 'Too many invalid codes. Please start again.', { restart: true });
          }
          throw new HttpError(401, 'Invalid or expired code.', { attemptsLeft: CONFIG.mfaFailsPerSession - session.fails });
        }
        user.emailVerified = true;
        store.save();
        await completeSignIn(res, session, user, ip);
        return { ok: true, user: publicUser(user) };
      },
    },

    'POST /api/register/resend': {
      auth: 'verify',
      handler: async ({ user, session, ip }) => {
        rateLimit(`send:${ip}`, limits.send);
        if (Date.now() - session.sentAt < CONFIG.otpResendMs) {
          throw new HttpError(429, 'Please wait before requesting another code.', { retryAfter: retryIn(session.sentAt + CONFIG.otpResendMs) });
        }
        session.sentAt = Date.now();
        if (user) {
          delete user.otps['verify-email'];
          await sendCode(user, 'verify-email', 'email', user.email);
        }
        return { ok: true };
      },
    },

    'POST /api/login': {
      auth: 'none',
      handler: async ({ body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        const generic = new HttpError(401, 'Invalid email or password.');

        // Lockouts are per account *and* IP, so a stranger can't lock the real owner out.
        // They apply to unknown emails too, so a lockout doesn't reveal that an account exists.
        const failKey = `${email}|${ip}`;
        const ipLock = loginFails.get(failKey);
        if (ipLock && ipLock.lockedUntil > Date.now()) {
          throw new HttpError(423, 'Too many failed attempts. Try again later.', { retryAfter: retryIn(ipLock.lockedUntil) });
        }
        const user = store.findByEmail(email);
        if (user && user.lockedUntil > Date.now()) {
          throw new HttpError(423, 'Too many failed attempts. Try again later.', { retryAfter: retryIn(user.lockedUntil) });
        }

        const valid = user
          ? await cu.verifyPassword(user.passwordHash, password)
          : (await cu.verifyPassword(await dummyHash, password), false); // same timing for unknown emails
        if (!valid) {
          await recordLoginFailure(failKey, user);
          throw generic;
        }
        loginFails.delete(failKey);

        if (!isVerified(user)) {
          createSession(res, session, user.id, 'verify', { email, sentAt: Date.now() });
          try {
            await sendCode(user, 'verify-email', 'email', user.email);
          } catch (err) {
            if (err.status !== 429) throw err; // a code was sent recently; it's still valid
          }
          return { ok: true, verifyRequired: true, email: maskEmail(email) };
        }
        if (mfaEnabled(user)) {
          createSession(res, session, user.id, 'mfa');
          return { ok: true, mfaRequired: true, ...mfaPrompt(user) };
        }
        await completeSignIn(res, session, user, ip);
        return { ok: true, mfaRequired: false, user: publicUser(user) };
      },
    },

    'POST /api/logout': {
      auth: 'none',
      handler: ({ res, session }) => {
        destroySession(res, session);
        return { ok: true };
      },
    },

    'POST /api/sessions/revoke-others': {
      auth: 'full',
      handler: ({ user, session }) => {
        revokeSessions(user.id, session.sid);
        return { ok: true };
      },
    },

    // Second factor during login
    'POST /api/mfa/challenge/send': {
      auth: 'mfa',
      handler: async ({ body, user, ip }) => {
        rateLimit(`send:${ip}`, limits.send);
        assertMfaNotLocked(user);
        if (body.method === 'sms' && user.mfa.sms.enabled) await sendCode(user, 'login-sms', 'sms', user.mfa.sms.phone);
        else if (body.method === 'email' && user.mfa.email.enabled) await sendCode(user, 'login-email', 'email', user.email);
        else throw new HttpError(400, 'That method cannot send codes.');
        return { ok: true, sent: true };
      },
    },

    'POST /api/mfa/passkey/options': {
      auth: 'mfa',
      handler: ({ user, session }) => {
        assertMfaNotLocked(user);
        if (!user.mfa.passkey.enabled) throw new HttpError(400, 'No passkey on this account.');
        return {
          publicKey: {
            challenge: newChallenge(session, 'get'),
            rpId: rp.id,
            timeout: CONFIG.webauthnTtlMs,
            userVerification: 'preferred',
            allowCredentials: user.mfa.passkey.credentials.map((c) => ({ type: 'public-key', id: c.id })),
          },
        };
      },
    },

    'POST /api/mfa/challenge/verify': {
      auth: 'mfa',
      handler: async ({ body, user, session, res, ip }) => {
        rateLimit(`mfa:${ip}`, limits.auth);
        assertMfaNotLocked(user);
        if (!verifyFactor(user, body, session)) {
          if (await recordMfaFailure(user)) {
            destroySession(res, session);
            throw new HttpError(423, 'Too many failed verification attempts on this account. Try again later.', {
              retryAfter: retryIn(user.mfaLockedUntil),
              restart: true,
            });
          }
          session.fails += 1;
          if (session.fails >= CONFIG.mfaFailsPerSession) {
            destroySession(res, session);
            throw new HttpError(401, 'Too many invalid codes. Please log in again.', { restart: true });
          }
          throw new HttpError(401, 'Invalid or expired code.', { attemptsLeft: CONFIG.mfaFailsPerSession - session.fails });
        }
        user.mfaFails = 0;
        user.mfaLockCount = 0;
        store.save();
        await completeSignIn(res, session, user, ip);
        if (body.method === 'backup') {
          await alert(user, 'Backup code used', `A backup code was used to sign in. ${user.mfa.backup.hashes.length} codes remain.\nIf this wasn't you, change your password now.`);
        }
        return { ok: true, user: publicUser(user), usedBackupCode: body.method === 'backup' };
      },
    },

    // Passkeys (WebAuthn)
    'POST /api/mfa/passkey/setup': {
      auth: 'full',
      handler: ({ user, session }) => {
        const creds = user.mfa.passkey.credentials;
        if (creds.length >= CONFIG.maxPasskeys) throw new HttpError(400, `You can register up to ${CONFIG.maxPasskeys} passkeys.`);
        return {
          publicKey: {
            challenge: newChallenge(session, 'create'),
            rp: { id: rp.id, name: rp.name },
            user: { id: Buffer.from(user.id).toString('base64url'), name: user.email, displayName: user.email },
            pubKeyCredParams: [-7, -8, -257].map((alg) => ({ type: 'public-key', alg })),
            timeout: CONFIG.webauthnTtlMs,
            attestation: 'none',
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
            excludeCredentials: creds.map((c) => ({ type: 'public-key', id: c.id })),
          },
        };
      },
    },
    'POST /api/mfa/passkey/enable': {
      auth: 'full',
      handler: async ({ user, body, session }) => {
        const challenge = takeChallenge(session, 'create');
        if (!challenge) throw new HttpError(400, 'Passkey setup expired. Try again.');
        let cred;
        try {
          cred = webauthn.verifyRegistration({ response: body.credential?.response, challenge, origin: rp.origin, rpId: rp.id });
        } catch (err) {
          throw new HttpError(400, `Passkey could not be verified: ${err.message}.`);
        }
        const p = user.mfa.passkey;
        if (p.credentials.some((c) => c.id === cred.id)) throw new HttpError(409, 'This passkey is already registered.');
        const name = String(body.name || '').trim().slice(0, 60) || `Passkey ${p.credentials.length + 1}`;
        p.credentials.push({ id: cred.id, publicKey: cred.publicKey, alg: cred.alg, signCount: cred.signCount, name, createdAt: new Date().toISOString() });
        p.enabled = true;
        return methodEnabled(user, 'passkey');
      },
    },

    // TOTP (authenticator app)
    'POST /api/mfa/totp/setup': {
      auth: 'full',
      handler: ({ user }) => {
        const secret = otp.generateSecret(20);
        user.mfa.totp.pendingSecretEnc = keys.encrypt(secret);
        store.save();
        return { secret, otpauthUrl: otp.otpauthUri({ type: 'totp', secret, label: user.email, issuer: CONFIG.issuer }) };
      },
    },
    'POST /api/mfa/totp/enable': {
      auth: 'full',
      handler: async ({ user, body }) => {
        const t = user.mfa.totp;
        if (!t.pendingSecretEnc) throw new HttpError(400, 'Start TOTP setup first.');
        const secret = keys.decrypt(t.pendingSecretEnc);
        const step = otp.verifyTotp(otp.base32Decode(secret), requireCode(body.code));
        if (step === null) throw new HttpError(400, 'Code did not match. Check your device clock and try again.');
        Object.assign(t, { enabled: true, secretEnc: t.pendingSecretEnc, pendingSecretEnc: null, lastStep: step });
        return methodEnabled(user, 'totp');
      },
    },

    // HOTP (counter-based token)
    'POST /api/mfa/hotp/setup': {
      auth: 'full',
      handler: ({ user }) => {
        const secret = otp.generateSecret(20);
        user.mfa.hotp.pendingSecretEnc = keys.encrypt(secret);
        store.save();
        return { secret, counter: 0, otpauthUrl: otp.otpauthUri({ type: 'hotp', secret, label: user.email, issuer: CONFIG.issuer, counter: 0 }) };
      },
    },
    'POST /api/mfa/hotp/enable': {
      auth: 'full',
      handler: async ({ user, body }) => {
        const h = user.mfa.hotp;
        if (!h.pendingSecretEnc) throw new HttpError(400, 'Start HOTP setup first.');
        const next = otp.verifyHotp(otp.base32Decode(keys.decrypt(h.pendingSecretEnc)), requireCode(body.code), 0);
        if (next === null) throw new HttpError(400, 'Code did not match.');
        Object.assign(h, { enabled: true, secretEnc: h.pendingSecretEnc, pendingSecretEnc: null, counter: next });
        return methodEnabled(user, 'hotp');
      },
    },

    // SMS
    'POST /api/mfa/sms/setup': {
      auth: 'full',
      handler: async ({ user, body, ip }) => {
        rateLimit(`send:${ip}`, limits.send);
        const phone = String(body.phone || '').replace(/[\s()-]/g, '');
        if (!PHONE_RE.test(phone)) throw new HttpError(400, 'Enter the phone number in international format, e.g. +254712345678.');
        user.mfa.sms.pendingPhone = phone;
        await sendCode(user, 'setup-sms', 'sms', phone);
        return { ok: true, sent: true, phone: maskPhone(phone) };
      },
    },
    'POST /api/mfa/sms/enable': {
      auth: 'full',
      handler: async ({ user, body }) => {
        const s = user.mfa.sms;
        if (!s.pendingPhone) throw new HttpError(400, 'Start SMS setup first.');
        if (!checkCode(user, 'setup-sms', requireCode(body.code))) throw new HttpError(400, 'Invalid or expired code.');
        Object.assign(s, { enabled: true, phone: s.pendingPhone, pendingPhone: null });
        return methodEnabled(user, 'sms');
      },
    },

    // Email
    'POST /api/mfa/email/setup': {
      auth: 'full',
      handler: async ({ user, ip }) => {
        rateLimit(`send:${ip}`, limits.send);
        await sendCode(user, 'setup-email', 'email', user.email);
        return { ok: true, sent: true };
      },
    },
    'POST /api/mfa/email/enable': {
      auth: 'full',
      handler: async ({ user, body }) => {
        if (!checkCode(user, 'setup-email', requireCode(body.code))) throw new HttpError(400, 'Invalid or expired code.');
        user.mfa.email.enabled = true;
        return methodEnabled(user, 'email');
      },
    },

    // Backup codes
    'POST /api/mfa/backup/generate': {
      auth: 'full',
      handler: async ({ user, body }) => {
        if (!mfaEnabled(user)) throw new HttpError(400, 'Enable a 2FA method first.');
        await requirePassword(user, body.password);
        const codes = issueBackupCodes(user); // replaces (invalidates) old codes
        store.save();
        await alert(user, 'New backup codes', 'New backup codes were generated. Your old codes no longer work.\nIf this wasn\'t you, change your password now.');
        return { ok: true, backupCodes: codes, user: publicUser(user) };
      },
    },

    'POST /api/password': {
      auth: 'full',
      handler: async ({ user, body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        if (!(await cu.verifyPassword(user.passwordHash, String(body.currentPassword || '')))) throw new HttpError(401, 'Current password is incorrect.');
        const next = String(body.newPassword || '');
        checkPasswordPolicy(next, user.email);
        await rejectBreached(next);
        user.passwordHash = await cu.hashPassword(next);
        store.save();
        const fresh = createSession(res, session, user.id, 'full');
        revokeSessions(user.id, fresh.sid);
        await alert(user, 'Password changed', 'Your password was changed and all other sessions were signed out.\nIf this wasn\'t you, reset your password immediately.');
        return { ok: true };
      },
    },

    // Turning a method off requires the password and signs out other sessions.
    'POST /api/mfa/disable': {
      auth: 'full',
      handler: async ({ user, body, session }) => {
        if (!PRIMARY.includes(body.method)) throw new HttpError(400, 'Unknown 2FA method.');
        await requirePassword(user, body.password);
        const m = user.mfa;
        const fresh = emptyMfa();
        m[body.method] = fresh[body.method];
        if (!mfaEnabled(user)) m.backup.hashes = [];
        store.save();
        revokeSessions(user.id, session.sid);
        await alert(user, `${METHOD_NAMES[body.method]} turned off`, `${METHOD_NAMES[body.method]} was removed from your account and other sessions were signed out.\nIf this wasn't you, change your password now.`);
        return { ok: true, user: publicUser(user) };
      },
    },

    // Magic link (passwordless first factor). The token is in the URL fragment, which
    // browsers never send to the server, and is only used by an explicit POST. So
    // email scanners that pre-open links can't use it up.
    'POST /api/magic/request': {
      auth: 'none',
      handler: async ({ body, ip }) => {
        rateLimit(`send:${ip}`, limits.send);
        const email = String(body.email || '').trim().toLowerCase();
        const user = EMAIL_RE.test(email) ? store.findByEmail(email) : null;
        if (user && isVerified(user) && !(user.magic && Date.now() - user.magic.sentAt < CONFIG.otpResendMs)) {
          const token = cu.randomToken(32);
          user.magic = { hash: keys.hashToken(token), expires: Date.now() + CONFIG.magicTtlMs, sentAt: Date.now() };
          store.save();
          await notifier.email(user.email, `Your ${CONFIG.issuer} sign-in link`,
            `Sign in: ${baseUrl}/#magic=${token}\nThe link expires in 15 minutes and works once. If you didn't ask for it, ignore this email.`);
        }
        // Same response whether or not the account exists (no enumeration)
        return { ok: true, message: 'If an account exists for that email, a sign-in link has been sent.' };
      },
    },
    'POST /api/magic/verify': {
      auth: 'none',
      handler: async ({ body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const token = typeof body.token === 'string' ? body.token : '';
        const h = keys.hashToken(token);
        const user = token ? store.find((u) => u.magic && otp.safeEqual(u.magic.hash, h)) : null;
        const valid = user && user.magic.expires >= Date.now();
        if (user) {
          user.magic = null; // single use
          store.save();
        }
        if (!valid) throw new HttpError(400, 'This sign-in link is invalid or has expired.');
        if (mfaEnabled(user)) {
          createSession(res, session, user.id, 'mfa');
          return { ok: true, mfaRequired: true, ...mfaPrompt(user) };
        }
        await completeSignIn(res, session, user, ip);
        return { ok: true, mfaRequired: false, user: publicUser(user) };
      },
    },
  };

  if (!production) {
    routes['GET /api/dev/outbox'] = { auth: 'none', handler: () => ({ messages: notifier.outbox }) };
  }

  function securityHeaders(res) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), publickey-credentials-create=(self), publickey-credentials-get=(self)');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    if (production) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }

  function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(body);
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > CONFIG.maxBodyBytes) {
          reject(new HttpError(413, 'Request body too large.'));
          req.destroy();
        } else chunks.push(c);
      });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {});
        } catch {
          reject(new HttpError(400, 'Invalid JSON.'));
        }
      });
      req.on('error', reject);
    });
  }

  function serveStatic(req, res, pathname) {
    const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
    const file = path.resolve(publicDir, rel);
    if (!file.startsWith(publicDir + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(file).pipe(res);
  }

  function originHost(origin) {
    try {
      return new URL(origin).host;
    } catch {
      return null;
    }
  }

  function clientIp(req) {
    if (trustProxy) {
      const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (forwarded) return forwarded;
    }
    return req.socket.remoteAddress || 'unknown';
  }

  async function handle(req, res) {
    securityHeaders(res);
    const url = new URL(req.url, 'http://localhost');
    const ip = clientIp(req);
    try {
      rateLimit(`global:${ip}`, limits.global);
      const route = routes[`${req.method} ${url.pathname}`];
      if (!route) {
        if (req.method === 'GET' && !url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
        throw new HttpError(404, 'Not found.');
      }

      let body = {};
      if (req.method !== 'GET') {
        // CSRF: custom header + Origin check, on top of SameSite=Strict cookies
        if (req.headers['x-requested-with'] !== 'fetch') throw new HttpError(403, 'Missing CSRF header.');
        const origin = req.headers.origin;
        if (origin !== undefined && originHost(origin) !== req.headers.host) throw new HttpError(403, 'Cross-origin request blocked.');
        if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Use application/json.');
        body = await readJson(req);
      }

      const session = getSession(req);
      const user = session?.userId ? store.getUser(session.userId) : null;
      if (route.auth === 'full' && !(session && user && session.stage === 'full')) throw new HttpError(401, 'Please log in.');
      if (route.auth === 'mfa' && !(session && user && session.stage === 'mfa')) throw new HttpError(401, 'No pending 2FA login. Please log in again.', { restart: true });
      if (route.auth === 'verify' && !(session && session.stage === 'verify')) throw new HttpError(401, 'No pending sign-up. Please start again.', { restart: true });

      const result = await route.handler({ req, res, url, body, session, user, ip });
      sendJson(res, 200, result);
    } catch (err) {
      const status = err.status || 500;
      if (status >= 500) log('[error]', err);
      if (err.extra?.retryAfter) res.setHeader('Retry-After', String(err.extra.retryAfter));
      if (!res.headersSent) sendJson(res, status, { error: status >= 500 && !err.status ? 'Internal server error.' : err.message, ...(err.extra || {}) });
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res);
  });
  server.on('close', () => clearInterval(sweeper));
  return { server, store, notifier, sessions };
}

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  const { server } = createApp();
  server.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
    if (process.env.NODE_ENV !== 'production') console.log('Dev mode: SMS/email codes are printed here and shown in the page\'s Dev Outbox.');
  });
}

module.exports = { createApp, CONFIG };

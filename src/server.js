'use strict';
/**
 * Secure authentication server with every common 2FA type:
 *   1. TOTP  - authenticator apps (Google/Microsoft Authenticator, Authy...)  RFC 6238
 *   2. HOTP  - counter-based hardware/software tokens                         RFC 4226
 *   3. SMS one-time codes
 *   4. Email one-time codes
 *   5. Backup / recovery codes (single use)
 *   6. Magic links (passwordless email login; still requires 2FA if enabled)
 *
 * Hardening: scrypt password hashing, AES-256-GCM encrypted 2FA secrets, hashed codes,
 * code expiry + attempt limits, TOTP replay protection, account lockout, rate limiting,
 * session rotation on privilege change, HttpOnly/SameSite cookies, CSRF checks, security headers.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const otp = require('./lib/otp');
const cu = require('./lib/crypto-utils');
const { Store } = require('./lib/store');
const { Notifier } = require('./lib/notify');

const CONFIG = {
  issuer: process.env.APP_NAME || 'SecureApp',
  otpTtlMs: 5 * 60_000, // SMS / email codes valid 5 minutes
  otpMaxAttempts: 5, // wrong guesses allowed per code
  otpResendMs: 30_000, // cooldown between sends
  magicTtlMs: 15 * 60_000,
  sessionTtlMs: 8 * 3600_000,
  mfaSessionTtlMs: 10 * 60_000, // time allowed to complete the 2nd factor
  maxLoginFails: 5,
  lockMs: 15 * 60_000,
  maxMfaFails: 5,
  backupCount: 10,
  maxBodyBytes: 10 * 1024,
};

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const PHONE_RE = /^\+[1-9]\d{7,14}$/; // E.164
const CODE_RE = /^\d{6}$/;

class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function createApp(opts = {}) {
  const dataDir = opts.dataDir || path.join(__dirname, '..', 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const production = opts.production ?? process.env.NODE_ENV === 'production';
  const baseUrl = (opts.baseUrl || process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
  const limits = { auth: 30, global: 300, ...(opts.rateLimits || {}) };
  const log = opts.log ?? console.log;
  const publicDir = path.join(__dirname, '..', 'public');

  const store = new Store(dataDir);
  const keys = cu.makeKeyring(cu.loadMasterKey(dataDir));
  const notifier = new Notifier({ production, log });
  const sessions = new Map();
  const buckets = new Map();
  const dummyHash = cu.hashPassword(crypto.randomBytes(16).toString('hex'));

  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const [k, s] of sessions) if (s.expires < now) sessions.delete(k);
    for (const [k, b] of buckets) if (b.reset < now) buckets.delete(k);
  }, 60_000);
  sweeper.unref();

  // ---------------- helpers ----------------
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

  function parseCookies(req) {
    const out = {};
    for (const part of (req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
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

  /** Always issues a NEW session id (prevents session fixation). */
  function createSession(res, old, userId, stage) {
    if (old) sessions.delete(old.sid);
    const sid = cu.randomToken(32);
    const ttl = stage === 'full' ? CONFIG.sessionTtlMs : CONFIG.mfaSessionTtlMs;
    const s = { sid, userId, stage, expires: Date.now() + ttl, mfaFails: 0 };
    sessions.set(sid, s);
    setCookie(res, sid, ttl);
    return s;
  }

  function destroySession(res, s) {
    if (s) sessions.delete(s.sid);
    setCookie(res, '', 0);
  }

  function newUser(email, passwordHash) {
    return {
      id: crypto.randomUUID(),
      email,
      passwordHash,
      createdAt: new Date().toISOString(),
      failedLogins: 0,
      lockedUntil: 0,
      mfa: {
        totp: { enabled: false, secretEnc: null, pendingSecretEnc: null, lastStep: -1 },
        hotp: { enabled: false, secretEnc: null, pendingSecretEnc: null, counter: 0 },
        sms: { enabled: false, phone: null, pendingPhone: null },
        email: { enabled: false },
        backup: { hashes: [] },
      },
      otps: {},
      magic: null,
    };
  }

  const PRIMARY = ['totp', 'hotp', 'sms', 'email'];
  const mfaEnabled = (u) => PRIMARY.some((m) => u.mfa[m].enabled);
  function enabledMethods(u) {
    const list = PRIMARY.filter((m) => u.mfa[m].enabled);
    if (list.length && u.mfa.backup.hashes.length) list.push('backup');
    return list;
  }

  const maskPhone = (p) => (p ? `${p.slice(0, 3)}${'*'.repeat(Math.max(0, p.length - 5))}${p.slice(-2)}` : null);
  const maskEmail = (e) => e.replace(/^(.)(.*)(@.*)$/, (_, a, b, c) => a + '*'.repeat(Math.min(b.length, 6)) + c);

  function publicUser(u) {
    return {
      id: u.id,
      email: u.email,
      mfaEnabled: mfaEnabled(u),
      mfa: {
        totp: u.mfa.totp.enabled,
        hotp: u.mfa.hotp.enabled,
        sms: u.mfa.sms.enabled,
        smsPhone: maskPhone(u.mfa.sms.phone),
        email: u.mfa.email.enabled,
        backupCodesRemaining: u.mfa.backup.hashes.length,
      },
    };
  }

  // ----- one-time codes (SMS / email) -----
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

  /** Verify a second-factor code. Mutates replay/counter state on success. */
  function verifyFactor(user, method, rawCode) {
    const m = user.mfa;
    switch (method) {
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

  /** After enabling the first 2FA method, auto-issue backup codes so the user can't get locked out. */
  function maybeInitialBackup(user) {
    if (user.mfa.backup.hashes.length === 0) return issueBackupCodes(user);
    return undefined;
  }

  // ---------------- routes ----------------
  // auth: 'none' | 'mfa' (password ok, 2nd factor pending) | 'full'
  const routes = {
    'GET /api/me': {
      auth: 'none',
      handler: ({ session, user }) => {
        if (!session || !user) return { authenticated: false };
        if (session.stage === 'mfa') return { authenticated: false, mfaPending: true, methods: enabledMethods(user), email: maskEmail(user.email), smsPhone: maskPhone(user.mfa.sms.phone) };
        return { authenticated: true, user: publicUser(user) };
      },
    },

    'POST /api/register': {
      auth: 'none',
      handler: async ({ body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        if (!EMAIL_RE.test(email)) throw new HttpError(400, 'Enter a valid email address.');
        if (password.length < 10 || password.length > 256) throw new HttpError(400, 'Password must be 10-256 characters.');
        if (password.toLowerCase().includes(email.split('@')[0])) throw new HttpError(400, 'Password must not contain your email name.');
        if (store.findByEmail(email)) throw new HttpError(409, 'An account with this email already exists.');
        const user = store.addUser(newUser(email, await cu.hashPassword(password)));
        createSession(res, session, user.id, 'full');
        return { ok: true, user: publicUser(user) };
      },
    },

    'POST /api/login': {
      auth: 'none',
      handler: async ({ body, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        const user = store.findByEmail(email);
        const generic = new HttpError(401, 'Invalid email or password.');
        if (!user) {
          await cu.verifyPassword(await dummyHash, password); // equalize timing (no user enumeration)
          throw generic;
        }
        if (user.lockedUntil > Date.now()) {
          throw new HttpError(423, 'Account temporarily locked after too many failed attempts. Try again later.', {
            retryAfter: Math.ceil((user.lockedUntil - Date.now()) / 1000),
          });
        }
        if (!(await cu.verifyPassword(user.passwordHash, password))) {
          user.failedLogins += 1;
          if (user.failedLogins >= CONFIG.maxLoginFails) {
            user.lockedUntil = Date.now() + CONFIG.lockMs;
            user.failedLogins = 0;
          }
          store.save();
          throw generic;
        }
        user.failedLogins = 0;
        store.save();
        if (mfaEnabled(user)) {
          createSession(res, session, user.id, 'mfa');
          return { ok: true, mfaRequired: true, methods: enabledMethods(user), email: maskEmail(user.email), smsPhone: maskPhone(user.mfa.sms.phone) };
        }
        createSession(res, session, user.id, 'full');
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

    // ----- second-factor challenge during login -----
    'POST /api/mfa/challenge/send': {
      auth: 'mfa',
      handler: async ({ body, user }) => {
        if (body.method === 'sms' && user.mfa.sms.enabled) await sendCode(user, 'login-sms', 'sms', user.mfa.sms.phone);
        else if (body.method === 'email' && user.mfa.email.enabled) await sendCode(user, 'login-email', 'email', user.email);
        else throw new HttpError(400, 'That method cannot send codes.');
        return { ok: true, sent: true };
      },
    },

    'POST /api/mfa/challenge/verify': {
      auth: 'mfa',
      handler: ({ body, user, session, res, ip }) => {
        rateLimit(`mfa:${ip}`, limits.auth);
        const ok = verifyFactor(user, body.method, body.code);
        if (!ok) {
          store.save();
          session.mfaFails += 1;
          if (session.mfaFails >= CONFIG.maxMfaFails) {
            destroySession(res, session);
            throw new HttpError(401, 'Too many invalid codes. Please log in again.', { restart: true });
          }
          throw new HttpError(401, 'Invalid or expired code.', { attemptsLeft: CONFIG.maxMfaFails - session.mfaFails });
        }
        store.save();
        createSession(res, session, user.id, 'full');
        return { ok: true, user: publicUser(user), usedBackupCode: body.method === 'backup' };
      },
    },

    // ----- TOTP (authenticator app) -----
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
      handler: ({ user, body }) => {
        const t = user.mfa.totp;
        if (!t.pendingSecretEnc) throw new HttpError(400, 'Start TOTP setup first.');
        const secret = keys.decrypt(t.pendingSecretEnc);
        const step = otp.verifyTotp(otp.base32Decode(secret), requireCode(body.code));
        if (step === null) throw new HttpError(400, 'Code did not match. Check your device clock and try again.');
        Object.assign(t, { enabled: true, secretEnc: t.pendingSecretEnc, pendingSecretEnc: null, lastStep: step });
        const backupCodes = maybeInitialBackup(user);
        store.save();
        return { ok: true, user: publicUser(user), backupCodes };
      },
    },

    // ----- HOTP (counter-based token) -----
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
      handler: ({ user, body }) => {
        const h = user.mfa.hotp;
        if (!h.pendingSecretEnc) throw new HttpError(400, 'Start HOTP setup first.');
        const next = otp.verifyHotp(otp.base32Decode(keys.decrypt(h.pendingSecretEnc)), requireCode(body.code), 0);
        if (next === null) throw new HttpError(400, 'Code did not match.');
        Object.assign(h, { enabled: true, secretEnc: h.pendingSecretEnc, pendingSecretEnc: null, counter: next });
        const backupCodes = maybeInitialBackup(user);
        store.save();
        return { ok: true, user: publicUser(user), backupCodes };
      },
    },

    // ----- SMS -----
    'POST /api/mfa/sms/setup': {
      auth: 'full',
      handler: async ({ user, body }) => {
        const phone = String(body.phone || '').replace(/[\s()-]/g, '');
        if (!PHONE_RE.test(phone)) throw new HttpError(400, 'Enter the phone number in international format, e.g. +254712345678.');
        user.mfa.sms.pendingPhone = phone;
        await sendCode(user, 'setup-sms', 'sms', phone);
        return { ok: true, sent: true, phone: maskPhone(phone) };
      },
    },
    'POST /api/mfa/sms/enable': {
      auth: 'full',
      handler: ({ user, body }) => {
        const s = user.mfa.sms;
        if (!s.pendingPhone) throw new HttpError(400, 'Start SMS setup first.');
        if (!checkCode(user, 'setup-sms', requireCode(body.code))) throw new HttpError(400, 'Invalid or expired code.');
        Object.assign(s, { enabled: true, phone: s.pendingPhone, pendingPhone: null });
        const backupCodes = maybeInitialBackup(user);
        store.save();
        return { ok: true, user: publicUser(user), backupCodes };
      },
    },

    // ----- Email -----
    'POST /api/mfa/email/setup': {
      auth: 'full',
      handler: async ({ user }) => {
        await sendCode(user, 'setup-email', 'email', user.email);
        return { ok: true, sent: true };
      },
    },
    'POST /api/mfa/email/enable': {
      auth: 'full',
      handler: ({ user, body }) => {
        if (!checkCode(user, 'setup-email', requireCode(body.code))) throw new HttpError(400, 'Invalid or expired code.');
        user.mfa.email.enabled = true;
        const backupCodes = maybeInitialBackup(user);
        store.save();
        return { ok: true, user: publicUser(user), backupCodes };
      },
    },

    // ----- Backup codes -----
    'POST /api/mfa/backup/generate': {
      auth: 'full',
      handler: async ({ user, body }) => {
        if (!mfaEnabled(user)) throw new HttpError(400, 'Enable a 2FA method first.');
        if (!(await cu.verifyPassword(user.passwordHash, String(body.password || '')))) throw new HttpError(401, 'Password is incorrect.');
        const codes = issueBackupCodes(user); // replaces (invalidates) old codes
        store.save();
        return { ok: true, backupCodes: codes, user: publicUser(user) };
      },
    },

    // ----- Disable a method (requires password re-authentication) -----
    'POST /api/mfa/disable': {
      auth: 'full',
      handler: async ({ user, body }) => {
        if (!PRIMARY.includes(body.method)) throw new HttpError(400, 'Unknown 2FA method.');
        if (!(await cu.verifyPassword(user.passwordHash, String(body.password || '')))) throw new HttpError(401, 'Password is incorrect.');
        const m = user.mfa;
        if (body.method === 'totp') m.totp = { enabled: false, secretEnc: null, pendingSecretEnc: null, lastStep: -1 };
        if (body.method === 'hotp') m.hotp = { enabled: false, secretEnc: null, pendingSecretEnc: null, counter: 0 };
        if (body.method === 'sms') m.sms = { enabled: false, phone: null, pendingPhone: null };
        if (body.method === 'email') m.email = { enabled: false };
        if (!mfaEnabled(user)) m.backup.hashes = [];
        store.save();
        return { ok: true, user: publicUser(user) };
      },
    },

    // ----- Magic link (passwordless first factor) -----
    'POST /api/magic/request': {
      auth: 'none',
      handler: async ({ body, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const email = String(body.email || '').trim().toLowerCase();
        const user = EMAIL_RE.test(email) ? store.findByEmail(email) : null;
        if (user && !(user.magic && Date.now() - user.magic.sentAt < CONFIG.otpResendMs)) {
          const token = cu.randomToken(32);
          user.magic = { hash: keys.hashToken(token), expires: Date.now() + CONFIG.magicTtlMs, sentAt: Date.now() };
          store.save();
          await notifier.email(user.email, `Your ${CONFIG.issuer} sign-in link`, `Sign in: ${baseUrl}/api/magic/verify?token=${token}  (expires in 15 minutes, single use)`);
        }
        // Same response whether or not the account exists (no enumeration)
        return { ok: true, message: 'If an account exists for that email, a sign-in link has been sent.' };
      },
    },
    'GET /api/magic/verify': {
      auth: 'none',
      raw: true,
      handler: ({ url, res, session, ip }) => {
        rateLimit(`auth:${ip}`, limits.auth);
        const token = url.searchParams.get('token') || '';
        const h = keys.hashToken(token);
        const user = token ? store.find((u) => u.magic && otp.safeEqual(u.magic.hash, h)) : null;
        const redirect = (loc) => {
          res.writeHead(303, { Location: loc });
          res.end();
        };
        if (!user || user.magic.expires < Date.now()) {
          if (user) {
            user.magic = null;
            store.save();
          }
          return redirect('/?error=magic-link-invalid');
        }
        user.magic = null; // single use
        store.save();
        createSession(res, session, user.id, mfaEnabled(user) ? 'mfa' : 'full');
        return redirect('/');
      },
    },
  };

  if (!production) {
    routes['GET /api/dev/outbox'] = { auth: 'none', handler: () => ({ messages: notifier.outbox }) };
  }

  // ---------------- request pipeline ----------------
  function securityHeaders(res) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
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

  async function handle(req, res) {
    securityHeaders(res);
    const url = new URL(req.url, 'http://localhost');
    const ip = req.socket.remoteAddress || 'unknown';
    try {
      rateLimit(`global:${ip}`, limits.global);
      const route = routes[`${req.method} ${url.pathname}`];
      if (!route) {
        if (req.method === 'GET' && !url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
        throw new HttpError(404, 'Not found.');
      }

      let body = {};
      if (req.method !== 'GET') {
        // CSRF defence (in addition to SameSite=Strict cookies)
        if (req.headers['x-requested-with'] !== 'fetch') throw new HttpError(403, 'Missing CSRF header.');
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-origin request blocked.');
        if (!/^application\/json/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Use application/json.');
        body = await readJson(req);
      }

      const session = getSession(req);
      const user = session ? store.getUser(session.userId) : null;
      if (route.auth === 'full' && !(session && user && session.stage === 'full')) throw new HttpError(401, 'Please log in.');
      if (route.auth === 'mfa' && !(session && user && session.stage === 'mfa')) throw new HttpError(401, 'No pending 2FA login. Please log in again.', { restart: true });

      const result = await route.handler({ req, res, url, body, session, user, ip });
      if (!route.raw) sendJson(res, 200, result);
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
    console.log(`Secure 2FA server running at http://localhost:${port}`);
    if (process.env.NODE_ENV !== 'production') console.log('Dev mode: SMS/email codes are printed here and shown in the page\'s Dev Outbox.');
  });
}

module.exports = { createApp, CONFIG };

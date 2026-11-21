# Secure 2FA Server

A zero-dependency Node.js (18+) login system with every common type of two-factor authentication.

| Method | How it works |
|---|---|
| **TOTP**: authenticator app | Scan a QR code with Google/Microsoft Authenticator, Authy, 1Password, etc. Gives a new 6-digit code every 30 s (RFC 6238). |
| **HOTP**: counter token | Hardware key fobs or apps that support HOTP. Gives a new code each time you press the button (RFC 4226). |
| **SMS code** | Sends a 6-digit code to a verified phone number. |
| **Email code** | Sends a 6-digit code to the account email. |
| **Backup codes** | 10 recovery codes, each usable once. They are issued automatically when you turn on your first method, and you can regenerate them. |
| **Magic link** | Passwordless sign-in by email. If 2FA is on, you still have to pass the second factor. |

## Run

```bash
cd security
npm start          # http://localhost:3000
npm test           # 18 tests: RFC vectors + every flow end to end
```

Open http://localhost:3000, create an account and turn on the methods. In development, SMS and email messages are not really sent. They show up in the **Dev outbox** panel on the page and in the server console.

## Sending real SMS and email

Set these environment variables:

```bash
# SMS via Twilio
TWILIO_ACCOUNT_SID=ACxxxx  TWILIO_AUTH_TOKEN=xxxx  TWILIO_FROM=+15551234567
# Email via SendGrid
SENDGRID_API_KEY=SG.xxxx   EMAIL_FROM=no-reply@yourdomain.com
# Production
NODE_ENV=production  BASE_URL=https://yourdomain.com  APP_SECRET=<64 hex chars>  APP_NAME=YourApp
```

With `NODE_ENV=production` the dev outbox is turned off, cookies get the `Secure` flag, and HSTS is sent. Put the server behind HTTPS.

Generate `APP_SECRET` with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

## Security measures

- Passwords are hashed with **scrypt**, and logins for unknown users take the same time as for real ones (no user enumeration).
- TOTP and HOTP secrets are **encrypted at rest** with AES-256-GCM. SMS codes, email codes, backup codes and magic tokens are stored only as **HMAC hashes**.
- All codes are compared in constant time.
- **TOTP replay protection**: a code can't be used twice. HOTP counter resync uses a look-ahead window.
- Codes expire after 5 minutes, allow at most 5 attempts each, and have a 30-second resend cooldown.
- **Account lockout**: 15 minutes after 5 failed passwords.
- **2FA attempt limit**: after 5 bad codes the login is cancelled and has to restart.
- Rate limiting is applied per IP, both globally and on the auth endpoints.
- Sessions are server-side, use `HttpOnly` + `SameSite=Strict` cookies, and get a **new ID** on every privilege change (prevents session fixation).
- **CSRF**: requests must carry a custom header, use a JSON content type, and pass an Origin check.
- Security headers are set: strict CSP, X-Frame-Options, nosniff, Referrer-Policy and HSTS.
- Turning off a method or regenerating backup codes requires the password again.

## API

| Endpoint | Session | Body |
|---|---|---|
| `POST /api/register` | none | `{email, password}` |
| `POST /api/login` | none | `{email, password}` → `{mfaRequired, methods}` |
| `POST /api/mfa/challenge/send` | pending 2FA | `{method: "sms" \| "email"}` |
| `POST /api/mfa/challenge/verify` | pending 2FA | `{method, code}` |
| `POST /api/mfa/{totp\|hotp}/setup` | full | → `{secret, otpauthUrl}` |
| `POST /api/mfa/{totp\|hotp}/enable` | full | `{code}` |
| `POST /api/mfa/sms/setup` / `enable` | full | `{phone}` / `{code}` |
| `POST /api/mfa/email/setup` / `enable` | full | `{}` / `{code}` |
| `POST /api/mfa/backup/generate` | full | `{password}` |
| `POST /api/mfa/disable` | full | `{method, password}` |
| `POST /api/magic/request` | none | `{email}` |
| `GET /api/magic/verify?token=` | none | redirects |
| `GET /api/me`, `POST /api/logout` | any | |

## Files

```
src/server.js            HTTP server, routes, sessions, rate limiting
src/lib/otp.js           TOTP / HOTP / Base32 (RFC 6238 / 4226 / 4648)
src/lib/crypto-utils.js  scrypt, AES-GCM, token hashing, backup codes
src/lib/notify.js        Twilio SMS / SendGrid email / dev outbox
src/lib/store.js         JSON-file user database (swap for a real DB in production)
public/                  Web UI
test/                    Automated tests
```

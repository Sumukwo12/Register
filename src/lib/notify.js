'use strict';
/**
 * Delivers SMS and email codes.
 *  - SMS via Twilio if TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM are set
 *  - Email via SendGrid if SENDGRID_API_KEY / EMAIL_FROM are set
 *  - Otherwise (development only) messages go to a local "dev outbox" shown in the UI and console.
 */
class Notifier {
  constructor({ production = false, log = console.log } = {}) {
    this.production = production;
    this.log = log;
    this.outbox = [];
  }

  _dev(channel, to, subject, text) {
    if (this.production) {
      const err = new Error(`No ${channel} provider configured`);
      err.status = 503;
      throw err;
    }
    const msg = { channel, to, subject, text, at: new Date().toISOString() };
    this.outbox.unshift(msg);
    this.outbox.length = Math.min(this.outbox.length, 50);
    this.log(`[dev-outbox] ${channel.toUpperCase()} -> ${to}: ${text}`);
  }

  async sms(to, text) {
    const { TWILIO_ACCOUNT_SID: sid, TWILIO_AUTH_TOKEN: token, TWILIO_FROM: from } = process.env;
    if (!sid || !token || !from) return this._dev('sms', to, null, text);
    const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: to, From: from, Body: text }),
    });
    if (!res.ok) throw Object.assign(new Error('SMS delivery failed'), { status: 502 });
  }

  async email(to, subject, text) {
    const { SENDGRID_API_KEY: key, EMAIL_FROM: from } = process.env;
    if (!key || !from) return this._dev('email', to, subject, text);
    const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: from },
        subject,
        content: [{ type: 'text/plain', value: text }],
      }),
    });
    if (!res.ok) throw Object.assign(new Error('Email delivery failed'), { status: 502 });
  }
}

module.exports = { Notifier };

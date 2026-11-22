'use strict';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

async function api(path, body) {
  const opts = body === undefined
    ? { credentials: 'same-origin' }
    : { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' }, body: JSON.stringify(body) };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    Object.assign(err, data, { status: res.status });
    throw err;
  }
  return data;
}

function flash(msg, type = 'ok') {
  const el = $('#flash');
  el.textContent = msg;
  el.className = `flash ${type}`;
  clearTimeout(flash.t);
  flash.t = setTimeout(() => el.classList.add('hidden'), 6000);
}

function show(view) {
  for (const id of ['view-auth', 'view-mfa', 'view-dash']) $(`#${id}`).classList.toggle('hidden', id !== view);
}

/** Wraps a form/button handler: disables while running, shows errors. */
function guard(fn) {
  return async (e) => {
    e?.preventDefault?.();
    const btn = e?.submitter || (e?.currentTarget instanceof HTMLButtonElement ? e.currentTarget : null);
    if (btn) btn.disabled = true;
    try { await fn(e); } catch (err) {
      flash(err.retryAfter ? `${err.message} (retry in ${err.retryAfter}s)` : err.message, 'error');
      if (err.restart) await refresh();
    } finally { if (btn) btn.disabled = false; }
  };
}

const formData = (form) => Object.fromEntries(new FormData(form));

$$('.tab').forEach((t) => t.addEventListener('click', () => {
  $$('.tab').forEach((x) => x.classList.toggle('active', x === t));
  $$('[data-pane]').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== t.dataset.tab));
}));

$('#form-login').addEventListener('submit', guard(async (e) => {
  const r = await api('/api/login', formData(e.target));
  e.target.reset();
  if (r.mfaRequired) showMfa(r); else renderDash(r.user);
}));

$('#form-register').addEventListener('submit', guard(async (e) => {
  const r = await api('/api/register', formData(e.target));
  e.target.reset();
  flash('Account created. Turn on at least one verification method.');
  renderDash(r.user);
}));

$('#form-magic').addEventListener('submit', guard(async (e) => {
  const r = await api('/api/magic/request', formData(e.target));
  flash(r.message);
}));

const METHOD_LABELS = { totp: 'Authenticator app', hotp: 'Hardware token', sms: 'Text message', email: 'Email', backup: 'Backup code' };
let mfaState = null;

function showMfa(info) {
  mfaState = { ...info, method: info.methods[0] };
  const box = $('#mfa-methods');
  box.replaceChildren(...info.methods.map((m) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = METHOD_LABELS[m] || m;
    b.addEventListener('click', () => selectMfa(m));
    b.dataset.m = m;
    return b;
  }));
  selectMfa(mfaState.method);
  show('view-mfa');
}

function selectMfa(m) {
  mfaState.method = m;
  $$('#mfa-methods button').forEach((b) => b.classList.toggle('active', b.dataset.m === m));
  const hints = {
    totp: 'Enter the 6-digit code from your authenticator app.',
    hotp: 'Press the button on your token and enter the code.',
    sms: `Send a code to ${mfaState.smsPhone || 'your phone'}.`,
    email: `Send a code to ${mfaState.email || 'your email'}.`,
    backup: 'Enter one of your backup codes, e.g. abcd-efgh.',
  };
  $('#mfa-hint').textContent = hints[m];
  $('#btn-send-code').classList.toggle('hidden', !(m === 'sms' || m === 'email'));
  const input = $('#mfa-code');
  input.value = '';
  input.inputMode = m === 'backup' ? 'text' : 'numeric';
  input.focus();
}

$('#btn-send-code').addEventListener('click', guard(async () => {
  await api('/api/mfa/challenge/send', { method: mfaState.method });
  flash('Code sent.');
}));

$('#form-mfa').addEventListener('submit', guard(async (e) => {
  try {
    const r = await api('/api/mfa/challenge/verify', { method: mfaState.method, code: $('#mfa-code').value.trim() });
    if (r.usedBackupCode) flash(`Backup code used. ${r.user.mfa.backupCodesRemaining} remaining.`);
    renderDash(r.user);
  } catch (err) {
    if (err.attemptsLeft !== undefined) err.message += ` ${err.attemptsLeft} attempt(s) left.`;
    throw err;
  }
}));

$('#btn-cancel-mfa').addEventListener('click', guard(async () => { await api('/api/logout', {}); await refresh(); }));

let currentUser = null;

function renderDash(user) {
  currentUser = user;
  $('#dash-email').textContent = user.email;
  const status = $('#dash-status');
  status.textContent = user.mfaEnabled
    ? 'Two-step verification is on.'
    : 'Two-step verification is off. Your account is protected by your password only.';
  status.className = `status ${user.mfaEnabled ? 'on' : 'off'}`;
  for (const card of $$('.method')) {
    const m = card.dataset.method;
    const on = m === 'backup' ? user.mfa.backupCodesRemaining > 0 : user.mfa[m];
    const badge = $('.badge', card);
    badge.textContent = on ? 'On' : '';
    badge.className = `badge ${on ? 'on' : 'off'}`;
    $('.btn-setup', card)?.classList.toggle('hidden', on);
    $('.btn-disable', card)?.classList.toggle('hidden', !on);
    if (on) $$('.setup, .start-form, .enable-form', card).forEach((x) => x.classList.add('hidden'));
  }
  $('.method[data-method="sms"] .phone').textContent = user.mfa.smsPhone ? `Phone: ${user.mfa.smsPhone}` : '';
  $('.method[data-method="backup"] .remaining').textContent = `${user.mfa.backupCodesRemaining} remaining.`;
  $('.method[data-method="backup"] .btn-regen').disabled = !user.mfaEnabled;
  show('view-dash');
}

function showBackupCodes(codes) {
  if (!codes) return;
  $('#backup-list').replaceChildren(...codes.map((c) => Object.assign(document.createElement('li'), { textContent: c })));
  $('#backup-reveal').classList.remove('hidden');
  $('#backup-reveal').scrollIntoView({ behavior: 'smooth' });
}
$('#btn-hide-backup').addEventListener('click', () => { $('#backup-reveal').classList.add('hidden'); $('#backup-list').replaceChildren(); });
$('#btn-copy-backup').addEventListener('click', guard(async () => {
  await navigator.clipboard.writeText($$('#backup-list li').map((li) => li.textContent).join('\n'));
  flash('Copied.');
}));

function drawQr(el, text) {
  el.replaceChildren();
  if (window.QRCode) new window.QRCode(el, { text, width: 180, height: 180 });
  else el.textContent = 'QR code unavailable. Use the key below.';
}

function onEnabled(r, label) {
  flash(`${label} turned on.`);
  renderDash(r.user);
  showBackupCodes(r.backupCodes);
}

// TOTP + HOTP share the same UI shape
for (const kind of ['totp', 'hotp']) {
  const card = $(`.method[data-method="${kind}"]`);
  $('.btn-setup', card).addEventListener('click', guard(async () => {
    const r = await api(`/api/mfa/${kind}/setup`, {});
    $('.secret', card).textContent = r.secret.replace(/(.{4})/g, '$1 ').trim();
    drawQr($('.qr', card), r.otpauthUrl);
    $('.setup', card).classList.remove('hidden');
  }));
  $('.enable-form', card).addEventListener('submit', guard(async (e) => {
    const r = await api(`/api/mfa/${kind}/enable`, { code: e.target.code.value.trim() });
    e.target.reset();
    onEnabled(r, METHOD_LABELS[kind]);
  }));
}

// SMS
{
  const card = $('.method[data-method="sms"]');
  $('.btn-setup', card).addEventListener('click', () => $('.start-form', card).classList.remove('hidden'));
  $('.start-form', card).addEventListener('submit', guard(async (e) => {
    const r = await api('/api/mfa/sms/setup', { phone: e.target.phone.value });
    flash(`Code sent to ${r.phone}.`);
    $('.enable-form', card).classList.remove('hidden');
  }));
  $('.enable-form', card).addEventListener('submit', guard(async (e) => {
    const r = await api('/api/mfa/sms/enable', { code: e.target.code.value.trim() });
    e.target.reset();
    onEnabled(r, 'SMS');
  }));
}

// Email
{
  const card = $('.method[data-method="email"]');
  $('.btn-setup', card).addEventListener('click', guard(async () => {
    await api('/api/mfa/email/setup', {});
    flash('Code sent to your email.');
    $('.enable-form', card).classList.remove('hidden');
  }));
  $('.enable-form', card).addEventListener('submit', guard(async (e) => {
    const r = await api('/api/mfa/email/enable', { code: e.target.code.value.trim() });
    e.target.reset();
    onEnabled(r, 'Email');
  }));
}

/** Asks for the password in a modal dialog. Resolves to the password, or null if cancelled. */
function askPassword(title) {
  const dialog = $('#confirm-dialog');
  const form = $('#confirm-form');
  $('#confirm-title').textContent = title;
  form.reset();
  return new Promise((resolve) => {
    const finish = (value) => {
      form.removeEventListener('submit', onSubmit);
      $('#confirm-cancel').removeEventListener('click', onCancel);
      dialog.removeEventListener('cancel', onCancel);
      dialog.close();
      resolve(value);
    };
    const onSubmit = (e) => { e.preventDefault(); finish(form.password.value); };
    const onCancel = (e) => { e.preventDefault(); finish(null); };
    form.addEventListener('submit', onSubmit);
    $('#confirm-cancel').addEventListener('click', onCancel);
    dialog.addEventListener('cancel', onCancel);
    dialog.showModal();
  });
}

for (const btn of $$('.btn-disable')) {
  btn.addEventListener('click', guard(async () => {
    const method = btn.closest('.method').dataset.method;
    const password = await askPassword(`Turn off ${METHOD_LABELS[method].toLowerCase()}`);
    if (!password) return;
    const r = await api('/api/mfa/disable', { method, password });
    flash(`${METHOD_LABELS[method]} turned off.`);
    renderDash(r.user);
  }));
}

$('.btn-regen').addEventListener('click', guard(async () => {
  const password = await askPassword('Regenerate backup codes');
  if (!password) return;
  const r = await api('/api/mfa/backup/generate', { password });
  renderDash(r.user);
  showBackupCodes(r.backupCodes);
}));

$('#form-password').addEventListener('submit', guard(async (e) => {
  await api('/api/password', formData(e.target));
  e.target.reset();
  flash('Password updated. Other sessions were signed out.');
}));

$('#btn-logout').addEventListener('click', guard(async () => {
  await api('/api/logout', {});
  currentUser = null;
  flash('Signed out.');
  await refresh();
}));

async function pollOutbox() {
  try {
    const r = await api('/api/dev/outbox');
    $('#dev-outbox').classList.remove('hidden');
    $('#outbox-list').replaceChildren(...r.messages.map((m) => {
      const li = document.createElement('li');
      const head = document.createElement('strong');
      head.textContent = `${m.channel.toUpperCase()} → ${m.to}`;
      const time = document.createElement('span');
      time.className = 'muted';
      time.textContent = ` ${new Date(m.at).toLocaleTimeString()}`;
      const text = document.createElement('div');
      text.textContent = m.text;
      li.append(head, time, text);
      return li;
    }));
  } catch {
    // outbox is disabled in production
  }
}
setInterval(pollOutbox, 3000);

async function refresh() {
  const me = await api('/api/me');
  if (me.authenticated) renderDash(me.user);
  else if (me.mfaPending) showMfa(me);
  else show('view-auth');
}

const params = new URLSearchParams(location.search);
if (params.get('error') === 'magic-link-invalid') flash('That sign-in link is invalid or expired.', 'error');
if (params.toString()) history.replaceState(null, '', '/');
refresh();
pollOutbox();

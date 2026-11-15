const path = require('path');
const express = require('express');
const { sendToSupport } = require('./support');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const MIN_FILL_TIME_MS = 3000;

const FORM_TOKEN_SECRET = process.env.FORM_TOKEN_SECRET || crypto.randomBytes(32).toString('hex');

function sign(value) {
  return crypto.createHmac('sha256', FORM_TOKEN_SECRET).update(value).digest('base64url');
}

function createFormToken() {
  const issuedAt = String(Date.now());
  return `${issuedAt}.${sign(issuedAt)}`;
}

function formAgeMs(token) {
  if (typeof token !== 'string') return null;

  const [issuedAt, signature] = token.split('.');
  if (!/^\d+$/.test(issuedAt || '') || !signature) return null;

  const expected = Buffer.from(sign(issuedAt));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    return null;
  }

  return Date.now() - Number(issuedAt);
}

function spamReason(body = {}) {
  if (String(body.website ?? '') !== '') {
    return 'honeypot field was filled in';
  }

  const ageMs = formAgeMs(body.form_started);
  if (ageMs === null) {
    return 'missing or invalid form_started';
  }
  if (ageMs < MIN_FILL_TIME_MS) {
    return `sent ${ageMs}ms after the form loaded`;
  }

  return null;
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get(['/contact', '/contact.html'], (req, res, next) => {
  fs.readFile(path.join(PUBLIC_DIR, 'contact.html'), 'utf8', (error, html) => {
    if (error) return next(error);

    res.set('Cache-Control', 'no-store');
    res.type('html').send(
      html.replace('name="form_started" value=""', `name="form_started" value="${createFormToken()}"`)
    );
  });
});

app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

app.post('/contact', (req, res) => {
  const reason = spamReason(req.body);
  if (reason) {
    console.log(`[spam] Dropped a contact form submission: ${reason}`);
    return res.json({ ok: true });
  }
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();
  const message = (req.body.message || '').trim();

  if (!name || !email || !message) {
    return res.status(400).json({ ok: false, error: 'Please fill in your name, email and message.' });
  }

  sendToSupport({ name, email, message });
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Calico Media site running at http://localhost:${PORT}`);
});

/**
 * KaizoCore — Backend integration (Node.js / Express)
 *
 * Environment variables required:
 *   KAIZO_API_KEY=sk_live_xxx    ← your secret key from app.kaizocore.com/api-keys
 *
 * That's the only env var you need. The HMAC is derived directly from your
 * secret key — there is no separate HMAC secret.
 *
 * Install: npm install express cookie-parser
 */

'use strict';

const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');

const KAIZO_API_URL = 'https://api.kaizocore.com';

// ─────────────────────────────────────────────────────────────────────────────
// kaizoDecide — core signing + request helper
// Call this from any protected endpoint before processing the action.
//
// @param {Object} params
//   ip          {string}  — visitor IP (X-Forwarded-For or req.ip)
//   userAgent   {string}  — User-Agent header from the browser request
//   kzSt        {string}  — value of the kz_st cookie (set automatically by c.js)
//   eventType   {string}  — 'login' | 'checkout' | 'signup' | 'payment' | etc.
//   entityKeys  {Object}  — optional identifiers: { user_id, email, phone }
//
// @returns {Promise<{ decision, score, reasons, session_mode, latency_ms, request_id }>}
// ─────────────────────────────────────────────────────────────────────────────
async function kaizoDecide({ ip, userAgent, kzSt, eventType, entityKeys = {} }) {
  const apiKey = process.env.KAIZO_API_KEY;
  if (!apiKey || !apiKey.startsWith('sk_live_')) {
    throw new Error('KaizoCore: KAIZO_API_KEY must be set to sk_live_xxx');
  }

  const ts   = Math.floor(Date.now() / 1000).toString();
  const rid  = crypto.randomUUID();
  const body = JSON.stringify({
    ip,
    user_agent:    userAgent,
    session_token: kzSt,         // the value of the kz_st cookie
    event_type:    eventType,
    entity_keys:   entityKeys,
    timestamp:     parseInt(ts, 10),
  });

  // HMAC-SHA256 — signed with your sk_live_xxx secret key directly.
  // Buffer.from(apiKey) treats the string as UTF-8 bytes — do NOT hex-decode it.
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n');
  const sig      = crypto
    .createHmac('sha256', Buffer.from(apiKey))
    .update(sigStr)
    .digest('hex');

  const res = await fetch(`${KAIZO_API_URL}/v1/decide`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-KZ-Key':     apiKey,
      'X-KZ-Ts':      ts,
      'X-KZ-Sig':     sig,
      'X-KZ-Rid':     rid,
    },
    body,
  });

  if (res.status === 429) {
    // Rate-limited — see error handling section below for the retry pattern
    const retryAfter = res.headers.get('Retry-After') || '1';
    const err = new Error('KaizoCore: rate limited');
    err.code = 'RATE_LIMITED';
    err.retryAfter = parseInt(retryAfter, 10);
    throw err;
  }

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`KaizoCore: decide failed with status ${res.status}: ${text}`);
  }

  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// USE CASE 1: Express checkout endpoint
//
// The kz_st cookie is set automatically by c.js on the client's domain.
// For same-origin requests it is sent by the browser automatically — you just
// read it with req.cookies.kz_st. No JS token passing needed.
// ─────────────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(cookieParser());

app.post('/api/checkout', async (req, res) => {
  const kzSt = req.cookies['kz_st'];

  if (!kzSt) {
    // The browser never ran c.js — or the client is calling the API directly.
    // Treat as suspicious; you can also call decide with kzSt=null for a signal-only score.
    return res.status(403).json({ error: 'session_missing' });
  }

  let result;
  try {
    result = await kaizoDecide({
      ip:         req.ip,
      userAgent:  req.headers['user-agent'],
      kzSt,
      eventType:  'checkout',
      entityKeys: { user_id: req.user?.id },  // pass any IDs you have
    });
  } catch (err) {
    if (err.code === 'RATE_LIMITED') {
      return res.status(429).json({ error: 'try_again_later', retryAfter: err.retryAfter });
    }
    // On unexpected errors, fail open (allow) to avoid blocking real users.
    // Log the error for alerting.
    console.error('KaizoCore error:', err.message);
    result = { decision: 'ALLOW', score: 0, reasons: ['decide_error_fail_open'] };
  }

  console.log(`[kaizo] checkout decision=${result.decision} score=${result.score}`);

  switch (result.decision) {
    case 'BLOCK':
      return res.status(403).json({ error: 'blocked' });

    case 'SOFT_CHALLENGE':
      // Prompt for 2FA / CAPTCHA before proceeding
      return res.status(202).json({ action: 'challenge_required' });

    case 'REVIEW':
      // Optimistic response to user; queue for manual ops review in background
      // await enqueueForReview({ orderId, userId: req.user?.id, kaizoResult: result });
      break; // fall through to process normally

    case 'ALLOW':
    case 'ALLOW_WATCH':
    default:
      break;
  }

  // Process the order
  res.json({ message: 'Order placed!', orderId: `ord_${Date.now()}` });
});

// ─────────────────────────────────────────────────────────────────────────────
// USE CASE 2: Express login endpoint (same pattern)
// ─────────────────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  const kzSt = req.cookies['kz_st'];

  if (!kzSt) {
    return res.status(403).json({ error: 'session_missing' });
  }

  const result = await kaizoDecide({
    ip:         req.ip,
    userAgent:  req.headers['user-agent'],
    kzSt,
    eventType:  'login',
    entityKeys: { email: req.body.email }, // pass email/phone — does NOT need to be hashed
  }).catch((err) => {
    console.error('KaizoCore error:', err.message);
    return { decision: 'ALLOW', score: 0 }; // fail open
  });

  if (result.decision === 'BLOCK') {
    return res.status(403).json({ error: 'blocked' });
  }

  // Authenticate the user
  // const user = await authenticateUser(req.body.email, req.body.password)
  res.json({ message: 'Logged in!' });
});

// ─────────────────────────────────────────────────────────────────────────────
// USE CASE 3: Global middleware — protect every route automatically
//
// Use this when you want KaizoCore on all endpoints without touching each one.
// Skip public routes (health checks, webhooks, static assets) as needed.
// ─────────────────────────────────────────────────────────────────────────────

const SKIP_PATHS = new Set(['/health', '/webhook/stripe']);

async function kaizoMiddleware(req, res, next) {
  // Only inspect mutating requests
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  if (SKIP_PATHS.has(req.path)) {
    return next();
  }

  const kzSt = req.cookies['kz_st'];
  if (!kzSt) {
    // No session — you may want to allow GETs/public routes and only block POSTs
    return res.status(403).json({ error: 'session_missing' });
  }

  let result;
  try {
    result = await kaizoDecide({
      ip:        req.ip,
      userAgent: req.headers['user-agent'],
      kzSt,
      eventType: 'api_call',
    });
  } catch (err) {
    console.error('KaizoCore middleware error:', err.message);
    return next(); // fail open
  }

  // Attach decision to request for downstream handlers to inspect
  req.kaizoResult = result;

  if (result.decision === 'BLOCK') {
    return res.status(403).json({ error: 'blocked' });
  }

  next();
}

// Apply after cookieParser
app.use(kaizoMiddleware);

// ─────────────────────────────────────────────────────────────────────────────
// USE CASE 4: Rate-limit aware error handling with exponential backoff
//
// In high-traffic scenarios KaizoCore may return 429. Wrap calls in a retry
// helper rather than letting the error propagate to your user.
// ─────────────────────────────────────────────────────────────────────────────

async function kaizoDecideWithRetry(params, { maxRetries = 2, baseDelayMs = 500 } = {}) {
  let attempt = 0;
  while (true) {
    try {
      return await kaizoDecide(params);
    } catch (err) {
      if (err.code === 'RATE_LIMITED' && attempt < maxRetries) {
        const delay = (err.retryAfter * 1000) || (baseDelayMs * Math.pow(2, attempt));
        await new Promise((r) => setTimeout(r, delay));
        attempt++;
        continue;
      }
      throw err;
    }
  }
}

// Example: payment endpoint using retry wrapper
app.post('/api/payment', async (req, res) => {
  const kzSt = req.cookies['kz_st'];
  if (!kzSt) return res.status(403).json({ error: 'session_missing' });

  const result = await kaizoDecideWithRetry({
    ip:        req.ip,
    userAgent: req.headers['user-agent'],
    kzSt,
    eventType: 'payment',
    entityKeys: { user_id: req.user?.id },
  }).catch((err) => {
    console.error('KaizoCore payment error:', err.message);
    return { decision: 'ALLOW', score: 0 };
  });

  if (result.decision === 'BLOCK') {
    return res.status(403).json({ error: 'blocked' });
  }

  res.json({ message: 'Payment processed!' });
});

// ─────────────────────────────────────────────────────────────────────────────

app.listen(3000, () => console.log('Server running on :3000'));

module.exports = { kaizoDecide, kaizoDecideWithRetry };

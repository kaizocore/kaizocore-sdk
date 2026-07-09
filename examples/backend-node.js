/**
 * KaizoCore — Backend integration example (Node.js)
 *
 * Call this from your checkout/login/signup endpoint BEFORE processing the action.
 * If decision is BLOCK → reject. If ALLOW → proceed. If REVIEW → queue for ops.
 */

const crypto = require('crypto');

const KAIZO_API_URL = 'https://api.kaizocore.com';

/**
 * Call /v1/decide for a given user action.
 *
 * @param {Object} params
 * @param {string} params.ip           - Visitor IP (forward from your web server)
 * @param {string} params.userAgent    - User-Agent header from the browser request
 * @param {string} params.sessionToken - window.__kz.getToken() sent by your frontend
 * @param {string} params.eventType    - 'login' | 'checkout' | 'signup' | 'payment' | etc.
 * @param {Object} [params.entityKeys] - Any identifier you have: { user_id: '123', email: 'a@b.com' }
 * @returns {Promise<{ decision: string, score: number, reasons: string[], latency_ms: number }>}
 */
async function kaizoDecide({ ip, userAgent, sessionToken, eventType, entityKeys = {} }) {
  const apiKey = process.env.KAIZO_API_KEY;     // pk_live_xxx from /api-keys
  const hmacSecret = process.env.KAIZO_HMAC_SECRET;  // from your KaizoCore account

  const ts      = Math.floor(Date.now() / 1000).toString();
  const rid     = crypto.randomUUID();
  const body    = JSON.stringify({
    ip,
    user_agent:    userAgent,
    session_token: sessionToken,
    event_type:    eventType,
    entity_keys:   entityKeys,
    timestamp:     parseInt(ts),
  });

  // HMAC-SHA256 signing
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n');
  const sig      = crypto.createHmac('sha256', Buffer.from(hmacSecret, 'hex'))
                         .update(sigStr)
                         .digest('hex');

  const res = await fetch(`${KAIZO_API_URL}/v1/decide`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-KZ-Key': apiKey,
      'X-KZ-Ts':  ts,
      'X-KZ-Sig': sig,
      'X-KZ-Rid': rid,
    },
    body,
  });

  if (!res.ok) throw new Error(`KaizoCore: decide failed ${res.status}`);
  return res.json();
}

// ── Express.js example ────────────────────────────────────────────────────────

const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/checkout', async (req, res) => {
  const { session_token, ...orderData } = req.body;

  const result = await kaizoDecide({
    ip:           req.ip,
    userAgent:    req.headers['user-agent'],
    sessionToken: session_token,
    eventType:    'checkout',
    entityKeys:   { user_id: req.user?.id },
  });

  console.log('KaizoCore decision:', result.decision, 'score:', result.score);

  if (result.decision === 'BLOCK') {
    return res.status(403).json({ message: 'Request blocked.' });
  }
  if (result.decision === 'REVIEW') {
    // Queue for manual review — return optimistic response to user
    // enqueueForReview(orderData, result)
  }

  // ALLOW or ALLOW_WATCH → proceed
  res.json({ message: 'Order placed!', orderId: 'ord_' + Date.now() });
});

module.exports = { kaizoDecide };

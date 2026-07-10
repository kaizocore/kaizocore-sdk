/**
 * KaizoCore Server SDK — Node.js backend helper
 *
 * Usage (Next.js API route):
 *   import { kaizoDecide } from '@kaizocore/sdk/server';
 *
 *   export default async function handler(req, res) {
 *     const result = await kaizoDecide(req, { apiKey: 'sk_live_xxx' });
 *     if (result.decision === 'BLOCK') return res.status(403).end();
 *     // ...
 *   }
 */

import { createHmac, createHash, randomUUID } from 'crypto';

const API_URL = 'https://api.kaizocore.com';

/**
 * kaizoDecide — call /v1/decide from your backend.
 *
 * @param {import('http').IncomingMessage} req  — the incoming request from your user
 * @param {object} opts
 * @param {string} opts.apiKey                  — your sk_live_ secret key
 * @param {string} [opts.eventType='page_view'] — event type string
 * @param {string} [opts.apiUrl]                — override API URL (for testing)
 * @returns {Promise<{decision: string, score: number, reasons: string[], request_id: string}>}
 */
export async function kaizoDecide(req, { apiKey, eventType = 'page_view', apiUrl = API_URL } = {}) {
  if (!apiKey || !apiKey.startsWith('sk_live_')) {
    throw new Error('kaizoDecide: apiKey must be a sk_live_ secret key');
  }

  const sessionToken = _extractSessionToken(req);
  const ip = _extractIP(req);
  const userAgent = req.headers['user-agent'] || '';

  const body = JSON.stringify({
    session_token: sessionToken || undefined,
    ip,
    user_agent: userAgent,
    event_type: eventType,
    headers: _safeHeaders(req.headers),
  });

  const ts  = Math.floor(Date.now() / 1000).toString();
  const rid = randomUUID();
  const bodyHash = sha256Hex(body);
  const signingString = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n');
  const sig = computeHMAC(apiKey, signingString);

  const response = await fetch(`${apiUrl}/v1/decide`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-KZ-Key': apiKey,
      'X-KZ-Ts':  ts,
      'X-KZ-Rid': rid,
      'X-KZ-Sig': sig,
    },
    body,
  });

  if (!response.ok) {
    throw new Error(`kaizoDecide: API error ${response.status}`);
  }

  return response.json();
}

function _extractSessionToken(req) {
  const cookie = req.headers['cookie'] || '';
  const match = cookie.match(/(?:^|;\s*)kz_st=([^;]+)/);
  return match ? match[1] : null;
}

function _extractIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || '';
}

function _safeHeaders(headers) {
  const allowed = [
    'accept', 'accept-language', 'accept-encoding',
    'referer', 'origin', 'x-forwarded-for', 'x-real-ip',
    'user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
    'cache-control', 'pragma',
  ];
  const out = {};
  for (const k of allowed) {
    if (headers[k]) out[k] = headers[k];
  }
  return out;
}

function sha256Hex(str) {
  return createHash('sha256').update(str).digest('hex');
}

function computeHMAC(secret, message) {
  return createHmac('sha256', secret).update(message).digest('hex');
}

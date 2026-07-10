# KaizoCore SDK

Invisible bot detection for high-stakes web flows — one script tag, zero friction for real users.

---

## How it works

```
┌─────────────────────────────────────────────────────────────────────┐
│ BROWSER                                                             │
│                                                                     │
│  <script src="cdn.kaizocore.com/l.js?k=pk_live_xxx">              │
│         │                                                           │
│         ▼                                                           │
│  l.js (1KB loader) downloads a unique, obfuscated c.js per session │
│         │                                                           │
│         ▼                                                           │
│  c.js collects 50+ signals + solves proof-of-work challenge        │
│  (~600ms for FORGE mode)                                            │
│         │                                                           │
│         ▼                                                           │
│  Sends encrypted payload to api.kaizocore.com                      │
│         │                                                           │
│         ▼                                                           │
│  Sets kz_st cookie on YOUR domain  ◄────── this is the key step   │
│  (e.g. kz_st=st_abc123...)                                         │
│         │                                                           │
│         ▼                                                           │
│  User clicks "Place Order"                                          │
│  → await window.__kz.settle()   ◄────── MUST await this first     │
│  → fetch('/api/checkout') sends kz_st cookie automatically         │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│ YOUR BACKEND                                                        │
│                                                                     │
│  Read kz_st from request cookies                                   │
│  POST https://api.kaizocore.com/v1/decide  {ip, kz_st, event}     │
│         │                                                           │
│         ▼                                                           │
│  { decision: "ALLOW", score: 12, reasons: [...] }                  │
│                                                                     │
│  if decision === "BLOCK" → reject (403)                            │
│  if decision === "ALLOW" → process order                           │
└─────────────────────────────────────────────────────────────────────┘
```

**The `kz_st` cookie is set automatically by c.js.** Your frontend does not need to read or pass it — for same-origin requests, the browser includes it automatically in every fetch/XHR.

---

## Quick start

### Step 1 — Get your API keys

Sign up at [app.kaizocore.com](https://app.kaizocore.com) → API Keys → Create Key.

You get two keys:

| Key | Prefix | Where it goes |
|-----|--------|---------------|
| Public key | `pk_live_xxx` | Frontend `<script>` tag — safe to expose |
| Secret key | `sk_live_xxx` | Backend only — never expose in frontend code |

### Step 2 — Add the script tag

```html
<!-- Add to your <head>. Replace pk_live_xxx with your public key. -->
<script src="https://cdn.kaizocore.com/l.js?k=pk_live_xxx" defer></script>
```

The script loads asynchronously and starts the challenge immediately. By the time the user fills out a form and clicks submit (~600ms+), the challenge is already done.

### Step 3 — Await settle() before a protected action

```javascript
document.getElementById('checkout-btn').addEventListener('click', async () => {
  // Wait for the bot detection challenge to complete.
  // This resolves in <50ms if the challenge already finished,
  // or waits up to 8 seconds if the user clicked very quickly.
  await window.__kz.settle()

  // The kz_st cookie is now set. For same-origin requests,
  // the browser sends it automatically — no token in the body needed.
  const res = await fetch('/api/checkout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ items: cart }),
  })
})
```

### Step 4 — Call /v1/decide from your backend

**Node.js:**
```javascript
const crypto = require('crypto')

async function kaizoDecide({ ip, userAgent, kzSt, eventType }) {
  const apiKey = process.env.KAIZO_API_KEY  // sk_live_xxx
  const ts     = Math.floor(Date.now() / 1000).toString()
  const rid    = crypto.randomUUID()
  const body   = JSON.stringify({ ip, user_agent: userAgent,
                   session_token: kzSt, event_type: eventType,
                   timestamp: parseInt(ts) })

  const bodyHash = crypto.createHash('sha256').update(body).digest('hex')
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n')
  const sig      = crypto.createHmac('sha256', Buffer.from(apiKey))
                         .update(sigStr).digest('hex')

  const res = await fetch('https://api.kaizocore.com/v1/decide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json',
               'X-KZ-Key': apiKey, 'X-KZ-Ts': ts,
               'X-KZ-Sig': sig, 'X-KZ-Rid': rid },
    body,
  })
  return res.json()
}

// In your Express handler:
app.post('/api/checkout', async (req, res) => {
  const kzSt = req.cookies['kz_st']
  if (!kzSt) return res.status(403).json({ error: 'session_missing' })

  const result = await kaizoDecide({
    ip: req.ip, userAgent: req.headers['user-agent'],
    kzSt, eventType: 'checkout',
  })

  if (result.decision === 'BLOCK') return res.status(403).json({ error: 'blocked' })
  res.json({ message: 'Order placed!' })
})
```

**Python:**
```python
import hashlib, hmac, json, os, time, uuid
import httpx

def kaizo_decide(*, ip, user_agent, kz_st, event_type):
    api_key = os.environ['KAIZO_API_KEY']  # sk_live_xxx
    ts  = str(int(time.time()))
    rid = str(uuid.uuid4())
    body = json.dumps({ 'ip': ip, 'user_agent': user_agent,
                        'session_token': kz_st, 'event_type': event_type,
                        'timestamp': int(ts) }, separators=(',', ':'))

    body_hash = hashlib.sha256(body.encode()).hexdigest()
    sig_str   = '\n'.join(['POST', '/v1/decide', ts, body_hash, rid])
    sig       = hmac.new(api_key.encode(), sig_str.encode(), hashlib.sha256).hexdigest()

    r = httpx.post('https://api.kaizocore.com/v1/decide', content=body,
        headers={ 'Content-Type': 'application/json', 'X-KZ-Key': api_key,
                  'X-KZ-Ts': ts, 'X-KZ-Sig': sig, 'X-KZ-Rid': rid }, timeout=5.0)
    r.raise_for_status()
    return r.json()
```

See the `examples/` directory for complete, copy-paste ready code for Node.js, Python, Go, and Next.js.

---

## Protection modes

Configure your site's protection mode from the **Settings** page in your dashboard. The mode is served from the CDN — you don't change the `<script>` tag.

| Mode | What it does | Latency | Best for |
|------|-------------|---------|----------|
| **FORGE** | Full hardware challenge + proof-of-work. Token is hardware-bound and cannot be replicated. | ~600ms | Checkout, payment, login, signup, OTP verify |
| **AMBIENT** | Passive signal collection only. No challenge to solve. | ~50ms | Browse pages, product listings, search, content APIs |
| **PULSE** | FORGE up front, then a heartbeat every 4s to prove continuous human presence. | ~600ms init | Ticket queues, flash sales, live auctions, long sessions |

### Use-case guide

```
Checkout page        → FORGE
Login / signup       → FORGE
Payment / OTP        → FORGE
Password reset       → FORGE

Product listing      → AMBIENT
Search results       → AMBIENT
Blog / content       → AMBIENT
Public API           → AMBIENT

Ticket queue         → PULSE
Flash sale wait      → PULSE
Live auction         → PULSE
Leaderboard refresh  → PULSE
```

---

## Frontend integration

### FORGE — checkout, login, signup

FORGE is the default mode for high-stakes actions. The challenge runs in the background while the user fills out the form. **You must `await settle()` before calling your protected endpoint.**

```html
<script src="https://cdn.kaizocore.com/l.js?k=pk_live_xxx" defer></script>

<button id="checkout-btn">Place Order</button>

<script>
  document.getElementById('checkout-btn').addEventListener('click', async () => {
    // ✅ CORRECT: await settle() BEFORE the fetch.
    // Challenge runs in the background — usually already done by the time user clicks.
    await window.__kz.settle()

    // kz_st cookie is now set. Browser sends it automatically.
    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: cart, total: 999 }),
    })
    const data = await res.json()
    if (res.ok) alert(`Order placed! ${data.orderId}`)
  })
</script>
```

**Login form:**
```html
<form id="login-form">
  <input type="email" name="email" required>
  <input type="password" name="password" required>
  <button type="submit">Log in</button>
</form>

<script>
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault()
    // ✅ await settle() before sending credentials
    await window.__kz.settle()

    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: e.target.email.value,
        password: e.target.password.value,
      }),
    })
    if (res.ok) window.location.href = '/dashboard'
  })
</script>
```

### AMBIENT — browse/content pages

AMBIENT mode is passive. The `kz_st` cookie is set within ~50ms of page load. **No `settle()` call is needed** — just make your fetch normally.

```html
<script src="https://cdn.kaizocore.com/l.js?k=pk_live_xxx" defer></script>

<script>
  // ✅ CORRECT for AMBIENT: no settle() call. Cookie is already there.
  async function loadSearchResults(query) {
    const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`)
    return res.json()
  }

  // Your backend reads kz_st from the cookie header and calls /v1/decide
</script>
```

### PULSE — ticket queues, long sessions

PULSE combines the FORGE challenge with a periodic heartbeat every 4 seconds. Use `minHeartbeats` to require proof of genuine human presence before a high-stakes action at the end of a queue.

```html
<script src="https://cdn.kaizocore.com/l.js?k=pk_live_xxx" defer></script>

<button id="book-btn">Book Ticket</button>

<script>
  document.getElementById('book-btn').addEventListener('click', async () => {
    // Require 3 heartbeats = ~12 seconds of verified human presence.
    // Bots that joined the queue programmatically at t=0 won't have these.
    await window.__kz.settle({ minHeartbeats: 3, timeoutMs: 20000 })

    const res = await fetch('/api/book-ticket', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ eventId: 'evt_123', quantity: 2 }),
    })
    const data = await res.json()
    alert(`Booking confirmed! ${data.bookingRef}`)
  })
</script>
```

**`settle()` options:**

| Option | Default | Description |
|--------|---------|-------------|
| `minHeartbeats` | `1` | Minimum PULSE heartbeats required. Each heartbeat is ~4 seconds apart. Ignored in FORGE/AMBIENT mode. |
| `timeoutMs` | `8000` | Maximum time to wait in milliseconds before rejecting. |

---

## Backend integration

### The kz_st cookie

`kz_st` is a cookie set automatically on your domain by `c.js`. You do not need any JavaScript to "get" it or pass it around — for same-origin requests, the browser includes it automatically in every `fetch()` or `XMLHttpRequest`.

```
Browser domain: yoursite.com
Cookie set:     kz_st=st_abc123...  (domain=yoursite.com)

User clicks "Place Order":
  → fetch('https://yoursite.com/api/checkout', { method: 'POST', body: ... })
  → Browser automatically includes: Cookie: kz_st=st_abc123...
  → Your backend reads: req.cookies['kz_st']
```

For **cross-origin** requests (frontend on `app.yoursite.com`, backend on `api.yoursite.com`), add `credentials: 'include'` to your fetch and configure CORS to `allow-credentials`.

### HMAC signing

Every `/v1/decide` call is authenticated with HMAC-SHA256. The key is your `sk_live_xxx` secret key — encoded as UTF-8 bytes. There is no separate HMAC secret.

**Signing string format:**
```
POST\n
/v1/decide\n
{unix_timestamp_seconds}\n
{sha256hex(request_body)}\n
{random_uuid}
```

**Headers to send:**
```
X-KZ-Key: sk_live_xxx          ← your secret key
X-KZ-Ts:  1720000000           ← unix timestamp (seconds)
X-KZ-Sig: abc123...            ← HMAC-SHA256 hex of signing string
X-KZ-Rid: uuid-v4              ← random request ID (for idempotency)
```

### Node.js / Express

```javascript
// install: npm install express cookie-parser
const crypto = require('crypto')
const express = require('express')
const cookieParser = require('cookie-parser')

const app = express()
app.use(express.json())
app.use(cookieParser())

async function kaizoDecide({ ip, userAgent, kzSt, eventType, entityKeys = {} }) {
  const apiKey = process.env.KAIZO_API_KEY   // sk_live_xxx
  const ts     = Math.floor(Date.now() / 1000).toString()
  const rid    = crypto.randomUUID()
  const body   = JSON.stringify({
    ip, user_agent: userAgent, session_token: kzSt,
    event_type: eventType, entity_keys: entityKeys,
    timestamp: parseInt(ts),
  })

  const bodyHash = crypto.createHash('sha256').update(body).digest('hex')
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n')

  // Key is Buffer.from(apiKey) — UTF-8 bytes of sk_live_xxx. Not hex-decoded.
  const sig = crypto.createHmac('sha256', Buffer.from(apiKey))
                    .update(sigStr).digest('hex')

  const res = await fetch('https://api.kaizocore.com/v1/decide', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-KZ-Key': apiKey, 'X-KZ-Ts': ts,
      'X-KZ-Sig': sig, 'X-KZ-Rid': rid,
    },
    body,
  })
  if (!res.ok) throw new Error(`KaizoCore: ${res.status}`)
  return res.json()
}

app.post('/api/checkout', async (req, res) => {
  const kzSt = req.cookies['kz_st']
  if (!kzSt) return res.status(403).json({ error: 'session_missing' })

  const result = await kaizoDecide({
    ip: req.ip, userAgent: req.headers['user-agent'],
    kzSt, eventType: 'checkout',
    entityKeys: { user_id: req.user?.id },
  }).catch((err) => {
    console.error('KaizoCore error:', err.message)
    return { decision: 'ALLOW', score: 0 } // fail open
  })

  if (result.decision === 'BLOCK') return res.status(403).json({ error: 'blocked' })
  if (result.decision === 'SOFT_CHALLENGE') return res.status(202).json({ action: 'challenge_required' })

  res.json({ message: 'Order placed!', orderId: `ord_${Date.now()}` })
})
```

See `examples/backend-node.js` for 4 use cases including middleware and retry handling.

### Next.js (App Router API route)

```typescript
// app/api/checkout/route.ts
import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

async function kaizoDecide(kzSt: string, req: NextRequest) {
  const apiKey = process.env.KAIZO_API_KEY!
  const ts     = Math.floor(Date.now() / 1000).toString()
  const rid    = crypto.randomUUID()
  const body   = JSON.stringify({
    ip:            req.headers.get('x-forwarded-for') ?? req.ip ?? '',
    user_agent:    req.headers.get('user-agent') ?? '',
    session_token: kzSt,
    event_type:    'checkout',
    timestamp:     parseInt(ts),
  })

  const bodyHash = crypto.createHash('sha256').update(body).digest('hex')
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n')
  const sig      = crypto.createHmac('sha256', Buffer.from(apiKey))
                         .update(sigStr).digest('hex')

  const res = await fetch('https://api.kaizocore.com/v1/decide', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json',
               'X-KZ-Key': apiKey, 'X-KZ-Ts': ts,
               'X-KZ-Sig': sig, 'X-KZ-Rid': rid },
    body, cache: 'no-store',
  })
  return res.json()
}

export async function POST(request: NextRequest) {
  const kzSt = request.cookies.get('kz_st')?.value
  if (!kzSt) return NextResponse.json({ error: 'session_missing' }, { status: 403 })

  const result = await kaizoDecide(kzSt, request)
    .catch(() => ({ decision: 'ALLOW' }))  // fail open

  if (result.decision === 'BLOCK') {
    return NextResponse.json({ error: 'blocked' }, { status: 403 })
  }

  // Parse body and process checkout
  const body = await request.json()
  return NextResponse.json({ message: 'Order placed!', orderId: `ord_${Date.now()}` })
}
```

**Frontend component (CheckoutButton.tsx):**
```typescript
'use client'
import { useState } from 'react'

declare global {
  interface Window {
    __kz: { settle: (opts?: { minHeartbeats?: number; timeoutMs?: number }) => Promise<void> }
  }
}

export function CheckoutButton({ onSuccess }: { onSuccess: (id: string) => void }) {
  const [loading, setLoading] = useState(false)

  const handleClick = async () => {
    setLoading(true)
    // ✅ await settle() BEFORE the fetch
    await window.__kz.settle()

    const res = await fetch('/api/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: [] }),
    })
    const data = await res.json()
    setLoading(false)
    if (res.ok) onSuccess(data.orderId)
  }

  return (
    <button onClick={handleClick} disabled={loading}>
      {loading ? 'Processing...' : 'Place Order'}
    </button>
  )
}
```

See `examples/nextjs.js` for the complete App Router example including middleware and TypeScript types.

### Python (FastAPI)

```python
# pip install fastapi uvicorn httpx
import hashlib, hmac, json, os, time, uuid
import httpx
from fastapi import Cookie, FastAPI, HTTPException, Request

app = FastAPI()

def kaizo_decide(*, ip, user_agent, kz_st, event_type, entity_keys=None):
    api_key = os.environ['KAIZO_API_KEY']   # sk_live_xxx
    ts  = str(int(time.time()))
    rid = str(uuid.uuid4())
    body = json.dumps({
        'ip': ip, 'user_agent': user_agent, 'session_token': kz_st,
        'event_type': event_type, 'entity_keys': entity_keys or {},
        'timestamp': int(ts),
    }, separators=(',', ':'))

    body_hash = hashlib.sha256(body.encode()).hexdigest()
    sig_str   = '\n'.join(['POST', '/v1/decide', ts, body_hash, rid])

    # Key is api_key.encode() — UTF-8 bytes of sk_live_xxx. Not hex-decoded.
    sig = hmac.new(api_key.encode(), sig_str.encode(), hashlib.sha256).hexdigest()

    r = httpx.post('https://api.kaizocore.com/v1/decide', content=body,
        headers={ 'Content-Type': 'application/json', 'X-KZ-Key': api_key,
                  'X-KZ-Ts': ts, 'X-KZ-Sig': sig, 'X-KZ-Rid': rid }, timeout=5.0)
    r.raise_for_status()
    return r.json()

@app.post('/api/checkout')
async def checkout(request: Request, kz_st: str | None = Cookie(default=None)):
    if not kz_st:
        raise HTTPException(status_code=403, detail='session_missing')

    try:
        result = kaizo_decide(
            ip=request.client.host,
            user_agent=request.headers.get('user-agent', ''),
            kz_st=kz_st,
            event_type='checkout',
        )
    except Exception as e:
        print(f'KaizoCore error: {e}')
        result = {'decision': 'ALLOW'}   # fail open

    if result['decision'] == 'BLOCK':
        raise HTTPException(status_code=403, detail='blocked')

    return {'message': 'Order placed!', 'order_id': f'ord_{int(time.time())}'}
```

See `examples/backend-python.py` for FastAPI middleware and Flask examples.

### Go

```go
// See examples/backend-go.go for the complete implementation.
// The key signing detail:

mac := hmac.New(sha256.New, []byte(apiKey))  // []byte(apiKey) = UTF-8 of sk_live_xxx
mac.Write([]byte(sigStr))
sig := hex.EncodeToString(mac.Sum(nil))

// Use the KaizoHandler wrapper for clean route protection:
mux.Handle("/api/checkout", KaizoHandler("checkout", http.HandlerFunc(checkoutHandler)))
```

---

## Decision values

| Decision | Score range | Meaning | Recommended action |
|----------|-------------|---------|-------------------|
| `ALLOW` | 0–30 | High confidence human | Proceed normally |
| `ALLOW_WATCH` | 25–50 | Likely human, minor signals | Proceed, log for review |
| `SOFT_CHALLENGE` | 45–70 | Suspicious — possible bot or scripted client | Prompt for 2FA / CAPTCHA |
| `REVIEW` | 60–85 | Ambiguous — cannot confidently classify | Queue for manual ops review |
| `BLOCK` | 70–100 | High confidence bot or fraud | Reject with 403 |

**Score:** 0 = definitely human, 100 = definitely bot.

**Fail-open pattern:** If the `/v1/decide` call fails (network error, timeout), default to `ALLOW` and log the error. Never let a KaizoCore outage block real users.

---

## Response schema

```json
{
  "decision":     "ALLOW",
  "score":        12.4,
  "reasons":      ["journey_high_confidence", "pow_verified"],
  "session_mode": "FORGE:BOUND",
  "latency_ms":   18,
  "request_id":   "3f8a2b1c-..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `decision` | string | One of: `ALLOW`, `ALLOW_WATCH`, `SOFT_CHALLENGE`, `REVIEW`, `BLOCK` |
| `score` | float | 0–100 suspicion score (higher = more suspicious) |
| `reasons` | string[] | Machine-readable signals that influenced the decision |
| `session_mode` | string | The mode that was active: `FORGE:BOUND`, `AMBIENT`, `PULSE` |
| `latency_ms` | int | Time KaizoCore spent processing the request |
| `request_id` | string | Unique ID for this decision — include in support tickets |

---

## Supported event types

Pass any of these, or any custom string — it appears in your dashboard analytics:

`login` · `signup` · `checkout` · `payment` · `password_reset` · `otp_verify` · `coupon_apply` · `api_call`

---

## Entity keys (optional but recommended)

Pass any identifiers you have. They power the cross-session entity graph and improve accuracy over time:

```javascript
entityKeys: {
  user_id: '123',
  email:   'user@example.com',   // plain or hashed — both work
  phone:   '+919876543210',
}
```

Entity keys are stored as stable hashes internally. You can pass plain values — KaizoCore normalises and hashes PII before storage.

---

## Common pitfalls

### Pitfall 1 — Not awaiting settle() before the protected fetch

This is the #1 integration mistake. If you call your API before `settle()` resolves, the `kz_st` cookie has not been set yet, and the decision will be low-confidence or missing.

```javascript
// ✗ WRONG: fetch happens before the challenge completes
document.getElementById('checkout-btn').addEventListener('click', async () => {
  const res = await fetch('/api/checkout', { method: 'POST', body: JSON.stringify(cart) })
})

// ✓ RIGHT: await settle() first, then fetch
document.getElementById('checkout-btn').addEventListener('click', async () => {
  await window.__kz.settle()   // ← this line is required
  const res = await fetch('/api/checkout', { method: 'POST', body: JSON.stringify(cart) })
})
```

**Why it matters:** The FORGE challenge takes ~600ms. A user can click a fast-loading page's button in under 200ms. Without `settle()`, the cookie isn't ready.

---

### Pitfall 2 — Checking cookie presence instead of calling /v1/decide

Just checking `if (!kz_st) return 403` provides no protection — a bot can trivially set any cookie value. You must call `/v1/decide` to get the actual decision.

```javascript
// ✗ WRONG: just checking cookie presence
app.post('/api/checkout', (req, res) => {
  const kzSt = req.cookies['kz_st']
  if (!kzSt) return res.status(403).json({ error: 'blocked' })  // bots can fake this
  res.json({ success: true })
})

// ✓ RIGHT: call /v1/decide with the cookie value
app.post('/api/checkout', async (req, res) => {
  const kzSt = req.cookies['kz_st']
  if (!kzSt) return res.status(403).json({ error: 'session_missing' })

  const result = await kaizoDecide({ ip: req.ip, userAgent: req.headers['user-agent'],
                                      kzSt, eventType: 'checkout' })
  if (result.decision === 'BLOCK') return res.status(403).json({ error: 'blocked' })
  res.json({ success: true })
})
```

---

### Pitfall 3 — Wrong HMAC key (hex-decoding the secret key)

The HMAC key is your `sk_live_xxx` string encoded as UTF-8 bytes. Do NOT treat it as a hex string.

```javascript
// ✗ WRONG: hex-decoding the key (treats sk_live_xxx as a hex string — it isn't)
const sig = crypto.createHmac('sha256', Buffer.from(apiKey, 'hex'))
                  .update(sigStr).digest('hex')

// ✓ RIGHT: UTF-8 bytes of the sk_live_xxx string
const sig = crypto.createHmac('sha256', Buffer.from(apiKey))
                  .update(sigStr).digest('hex')
```

```python
# ✗ WRONG
sig = hmac.new(bytes.fromhex(api_key), sig_str.encode(), hashlib.sha256).hexdigest()

# ✓ RIGHT
sig = hmac.new(api_key.encode(), sig_str.encode(), hashlib.sha256).hexdigest()
```

---

### Pitfall 4 — Using the public key (pk_live_xxx) on the backend

The public key is for the frontend `<script>` tag only. Backend `/v1/decide` calls must use your **secret key** (`sk_live_xxx`).

```bash
# ✗ WRONG — .env with public key on backend
KAIZO_API_KEY=pk_live_xxx

# ✓ RIGHT — secret key on backend
KAIZO_API_KEY=sk_live_xxx
```

The secret key must never appear in frontend code, client-side bundles, or public repositories.

---

### Pitfall 5 — Not handling the fail-open case

If `/v1/decide` returns an error (network timeout, service outage), do not propagate the error to your user as a rejection. Fail open: allow the request and log the error for alerting.

```javascript
// ✗ WRONG: error blocks real users
const result = await kaizoDecide({ ... })  // throws on network error → 500 to user

// ✓ RIGHT: catch and fail open
const result = await kaizoDecide({ ... }).catch((err) => {
  console.error('KaizoCore error:', err.message)
  // Alert your on-call team here
  return { decision: 'ALLOW', score: 0, reasons: ['fail_open'] }
})
```

---

## Environment variables

```bash
# Backend — required
KAIZO_API_KEY=sk_live_xxx           # your secret key from app.kaizocore.com/api-keys

# Frontend — used in your HTML/template to populate the <script> tag
# (Next.js: NEXT_PUBLIC_KAIZO_PUBLIC_KEY=pk_live_xxx)
KAIZO_PUBLIC_KEY=pk_live_xxx        # your public key — safe to expose
```

There is no `KAIZO_HMAC_SECRET`. The HMAC is derived directly from `KAIZO_API_KEY`.

---

## npm / bundler usage

If you use a bundler (webpack, Vite, Rollup) instead of a plain `<script>` tag:

```bash
npm install @kaizocore/sdk
```

```javascript
import { KaizoCore } from '@kaizocore/sdk'

const kz = new KaizoCore({ apiKey: 'pk_live_xxx' })

// In your click handler:
await kz.settle()
// Then fetch your protected endpoint
```

The `KaizoCore` class delegates to `window.__kz` (loaded from CDN) for all operations. `settle()`, `getState()`, and `getDeviceId()` are the same APIs.

---

## Support

- Dashboard: [app.kaizocore.com](https://app.kaizocore.com)
- Issues: [github.com/kaizocore/sdk/issues](https://github.com/kaizocore/sdk/issues)
- Email: support@kaizocore.com

When reporting an issue, include the `request_id` from the `/v1/decide` response and your `pk_live_xxx` public key (never your secret key).

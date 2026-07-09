# KaizoCore SDK

Bot detection for Indian platforms. One script tag. Zero friction for real users.

## How it works

```
Your page loads
  → l.js (tiny loader, 1KB) boots from cdn.kaizocore.com
  → Downloads a unique, obfuscated c.js per session
  → c.js runs hardware challenges + collects 50+ signals
  → Sends encrypted payload to api.kaizocore.com
  → Returns session_token

Your backend calls /v1/decide with the session_token
  → Gets: ALLOW | BLOCK | REVIEW | SOFT_CHALLENGE | ALLOW_WATCH
```

## Quick Start

### 1. Get your API key

Sign up at [app.kaizocore.com](https://app.kaizocore.com) → API Keys → Create Key.

You get two keys:
- `pk_live_xxx` — **public key**, goes in your frontend HTML (safe to expose)
- `sk_live_xxx` — **secret key**, stays on your server for `/v1/decide` calls

### 2. Add the script tag

```html
<!-- Add to your <head>. That's it. -->
<script src="https://cdn.kaizocore.com/l.js?k=pk_live_YOUR_KEY" defer></script>
```

### 3. Settle before a protected action

```javascript
// Before checkout / login / signup:
await window.__kz.settle({ minHeartbeats: 1 })
const sessionToken = window.__kz.getToken()

// Send sessionToken to your backend
fetch('/api/checkout', {
  method: 'POST',
  body: JSON.stringify({ session_token: sessionToken, ...orderData })
})
```

### 4. Call /v1/decide from your backend

**Node.js:**
```javascript
// See examples/backend-node.js for full HMAC signing code
const result = await kaizoDecide({
  ip: req.ip,
  userAgent: req.headers['user-agent'],
  sessionToken: req.body.session_token,
  eventType: 'checkout',
})

if (result.decision === 'BLOCK') return res.status(403).json({ error: 'blocked' })
// else proceed
```

**Python:**
```python
# See examples/backend-python.py for full HMAC signing code
result = kaizo_decide(
    ip=request.client.host,
    user_agent=request.headers.get("user-agent"),
    session_token=body.session_token,
    event_type="checkout",
)
if result["decision"] == "BLOCK":
    raise HTTPException(403)
```

## Decision values

| Value | Meaning | Recommended action |
|-------|---------|-------------------|
| `ALLOW` | High confidence human | Proceed |
| `ALLOW_WATCH` | Likely human, minor signals | Proceed, log |
| `SOFT_CHALLENGE` | Suspicious | Show 2FA / re-auth |
| `REVIEW` | Ambiguous | Queue for manual ops |
| `BLOCK` | High confidence bot | Reject |

## Response shape

```json
{
  "decision": "ALLOW",
  "score": 12.4,
  "reasons": ["journey_high_confidence"],
  "session_mode": "FORGE:BOUND",
  "latency_ms": 18,
  "request_id": "uuid"
}
```

## Supported event types

`login` · `signup` · `checkout` · `payment` · `password_reset` · `otp_verify` · `coupon_apply` · `api_call`

Or pass any custom string — it appears in your dashboard.

## Entity keys (optional but recommended)

Pass any identifiers you have. They power the cross-session entity graph:

```javascript
// On your /v1/decide call
entity_keys: {
  user_id: '123',
  email:   'hash_of_email',   // hash PII before sending
  phone:   'hash_of_phone',
}
```

## HMAC signing

Every `/v1/decide` call is signed with HMAC-SHA256. See `examples/backend-node.js` or `examples/backend-python.py` for copy-paste signing code.

## Environment variables

```bash
KAIZO_API_KEY=sk_live_xxx         # secret key — never expose in frontend
KAIZO_HMAC_SECRET=hexstring       # from your KaizoCore API deployment
```

## Detection modes

The SDK operates in one of three modes (configurable from your dashboard):

| Mode | What it proves | Use when |
|------|---------------|----------|
| **FORGE** | Hardware-bound token — cannot be replicated | Checkout, payment, login |
| **PULSE** | Human signals present continuously | Long-lived sessions, queues |
| **AMBIENT** | JS ran, confidence scored from signals | Low-friction pages |

## Support

- Dashboard: [app.kaizocore.com](https://app.kaizocore.com)
- Issues: [github.com/kaizocore/sdk/issues](https://github.com/kaizocore/sdk/issues)
- Email: support@kaizocore.com

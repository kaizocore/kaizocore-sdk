/**
 * KaizoCore — Complete Next.js App Router integration
 *
 * This file contains 4 sections. Copy each into the corresponding file in your
 * Next.js project. All examples use TypeScript and App Router (Next.js 13+).
 *
 * Environment variables (.env.local):
 *   NEXT_PUBLIC_KAIZO_PUBLIC_KEY=pk_live_xxx   ← safe to expose, used in <script> tag
 *   KAIZO_API_KEY=sk_live_xxx                  ← secret, server-side only
 *
 * The #1 mistake (seen with anbudencsk.com and others):
 *   ✗ WRONG: Calling /api/checkout at page load without await settle()
 *   ✗ WRONG: Backend just checks `if (!kz_st) return 403` without calling /v1/decide
 *   ✓ RIGHT: await window.__kz.settle() before the fetch, then call /v1/decide server-side
 */

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 1: Frontend — app/layout.tsx (or any layout that wraps protected pages)
//
// Load the KaizoCore script once at the layout level. The script is tiny (1KB)
// and boots asynchronously — it does not block page render.
// ═══════════════════════════════════════════════════════════════════════════════

/*
// app/layout.tsx

import Script from 'next/script'

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head />
      <body>
        {children}

        {/*
          Load KaizoCore. 'afterInteractive' means it runs after hydration —
          the challenge starts automatically. By the time the user clicks a
          button (~600ms later), settle() resolves immediately.
        * /}
        <Script
          src={`https://cdn.kaizocore.com/l.js?k=${process.env.NEXT_PUBLIC_KAIZO_PUBLIC_KEY}`}
          strategy="afterInteractive"
        />
      </body>
    </html>
  )
}
*/

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 2: Backend — app/api/checkout/route.ts
//
// The kz_st cookie is set automatically by c.js and sent by the browser with
// every same-origin request. Read it with cookies() — no token in the body.
// ═══════════════════════════════════════════════════════════════════════════════

/*
// app/api/checkout/route.ts

import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

const KAIZO_API_URL = 'https://api.kaizocore.com'

interface KaizoDecision {
  decision: 'ALLOW' | 'ALLOW_WATCH' | 'SOFT_CHALLENGE' | 'REVIEW' | 'BLOCK'
  score: number
  reasons: string[]
  session_mode: string
  latency_ms: number
  request_id: string
}

async function kaizoDecide(params: {
  ip: string
  userAgent: string
  kzSt: string
  eventType: string
  entityKeys?: Record<string, string>
}): Promise<KaizoDecision> {
  const apiKey = process.env.KAIZO_API_KEY!
  if (!apiKey?.startsWith('sk_live_')) {
    throw new Error('KAIZO_API_KEY must be set to sk_live_xxx')
  }

  const ts  = Math.floor(Date.now() / 1000).toString()
  const rid = crypto.randomUUID()
  const body = JSON.stringify({
    ip:            params.ip,
    user_agent:    params.userAgent,
    session_token: params.kzSt,
    event_type:    params.eventType,
    entity_keys:   params.entityKeys ?? {},
    timestamp:     parseInt(ts, 10),
  })

  // HMAC-SHA256 using sk_live_xxx directly — no separate HMAC secret
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex')
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n')
  const sig      = crypto
    .createHmac('sha256', Buffer.from(apiKey))
    .update(sigStr)
    .digest('hex')

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
    // Don't cache decide calls
    cache: 'no-store',
  })

  if (!res.ok) {
    throw new Error(`KaizoCore: decide failed ${res.status}`)
  }
  return res.json()
}

export async function POST(request: NextRequest) {
  // Read kz_st from the incoming request cookies — set automatically by c.js
  const kzSt = request.cookies.get('kz_st')?.value

  if (!kzSt) {
    return NextResponse.json({ error: 'session_missing' }, { status: 403 })
  }

  let result: KaizoDecision
  try {
    result = await kaizoDecide({
      ip:        request.headers.get('x-forwarded-for') ?? request.ip ?? '',
      userAgent: request.headers.get('user-agent') ?? '',
      kzSt,
      eventType: 'checkout',
    })
  } catch (err) {
    // Fail open — log and allow on unexpected errors
    console.error('KaizoCore error:', err)
    result = { decision: 'ALLOW', score: 0, reasons: ['fail_open'], session_mode: '', latency_ms: 0, request_id: '' }
  }

  console.log(`[kaizo] checkout decision=${result.decision} score=${result.score}`)

  if (result.decision === 'BLOCK') {
    return NextResponse.json({ error: 'blocked' }, { status: 403 })
  }
  if (result.decision === 'SOFT_CHALLENGE') {
    return NextResponse.json({ action: 'challenge_required' }, { status: 202 })
  }

  const body = await request.json()
  // Process checkout with body.items, body.total, etc.
  return NextResponse.json({ message: 'Order placed!', orderId: `ord_${Date.now()}` })
}
*/

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 3: Middleware — middleware.ts (runs on every matched request)
//
// Use middleware to enforce KaizoCore on all API routes without modifying
// each route handler individually.
// ═══════════════════════════════════════════════════════════════════════════════

/*
// middleware.ts  (place at the root of your project, next to app/)

import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

const KAIZO_API_URL = 'https://api.kaizocore.com'

// Paths that skip bot detection (public webhooks, health checks, etc.)
const SKIP_PATHS = ['/api/webhook', '/api/health', '/api/public']

async function decide(kzSt: string, req: NextRequest): Promise<string> {
  const apiKey = process.env.KAIZO_API_KEY!
  const ts     = Math.floor(Date.now() / 1000).toString()
  const rid    = crypto.randomUUID()
  const body   = JSON.stringify({
    ip:            req.headers.get('x-forwarded-for') ?? '',
    user_agent:    req.headers.get('user-agent') ?? '',
    session_token: kzSt,
    event_type:    'api_call',
    timestamp:     parseInt(ts, 10),
  })

  const bodyHash = crypto.createHash('sha256').update(body).digest('hex')
  const sigStr   = ['POST', '/v1/decide', ts, bodyHash, rid].join('\n')
  const sig      = crypto
    .createHmac('sha256', Buffer.from(apiKey))
    .update(sigStr)
    .digest('hex')

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
    cache: 'no-store',
  })

  if (!res.ok) return 'ALLOW'  // fail open
  const data = await res.json()
  return data.decision as string
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Only intercept POST requests to /api routes
  if (request.method !== 'POST' || !pathname.startsWith('/api')) {
    return NextResponse.next()
  }

  // Skip explicitly excluded paths
  if (SKIP_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next()
  }

  const kzSt = request.cookies.get('kz_st')?.value
  if (!kzSt) {
    return NextResponse.json({ error: 'session_missing' }, { status: 403 })
  }

  try {
    const decision = await decide(kzSt, request)
    if (decision === 'BLOCK') {
      return NextResponse.json({ error: 'blocked' }, { status: 403 })
    }
  } catch {
    // Fail open on errors
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/api/:path*'],
}
*/

// ═══════════════════════════════════════════════════════════════════════════════
// SECTION 4: Frontend component — CheckoutButton.tsx
//
// The critical pattern: await window.__kz.settle() BEFORE the protected fetch.
//
// This is the mistake that caused the anbudencsk.com incident:
//   ✗ WRONG: calling the API at page load, before settle() — kz_st not set yet
//   ✓ RIGHT: settle() inside the click handler, BEFORE the fetch
// ═══════════════════════════════════════════════════════════════════════════════

/*
// components/CheckoutButton.tsx
'use client'

import { useState } from 'react'

interface CheckoutButtonProps {
  items: Array<{ id: string; quantity: number }>
  total: number
  onSuccess: (orderId: string) => void
}

declare global {
  interface Window {
    __kz: {
      settle: (opts?: { minHeartbeats?: number; timeoutMs?: number }) => Promise<void>
      getState: () => string
      getDeviceId: () => string | null
    }
  }
}

export function CheckoutButton({ items, total, onSuccess }: CheckoutButtonProps) {
  const [status, setStatus] = useState<'idle' | 'verifying' | 'processing' | 'error'>('idle')

  const handleCheckout = async () => {
    setStatus('verifying')

    try {
      // ✅ CORRECT: await settle() BEFORE the fetch.
      // The FORGE challenge runs in the background while the user fills the form.
      // settle() resolves in <50ms if the challenge already completed, or waits
      // up to timeoutMs if the user clicked very quickly after page load.
      await window.__kz.settle({ timeoutMs: 8000 })

      setStatus('processing')

      // kz_st cookie is now set — browser sends it automatically (same-origin)
      const res = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items, total }),
      })

      if (!res.ok) {
        const data = await res.json()
        if (data.action === 'challenge_required') {
          // Prompt for 2FA
          setStatus('idle')
          return
        }
        throw new Error(data.error ?? 'Checkout failed')
      }

      const data = await res.json()
      onSuccess(data.orderId)
      setStatus('idle')
    } catch (err) {
      console.error('Checkout error:', err)
      setStatus('error')
    }
  }

  const labels = {
    idle:       'Place Order',
    verifying:  'Verifying...',
    processing: 'Processing...',
    error:      'Try Again',
  }

  return (
    <button
      onClick={handleCheckout}
      disabled={status === 'verifying' || status === 'processing'}
      className="checkout-btn"
    >
      {labels[status]}
    </button>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Usage in a page:
// ─────────────────────────────────────────────────────────────────────────────

// app/checkout/page.tsx
// 'use client'
//
// import { CheckoutButton } from '@/components/CheckoutButton'
//
// export default function CheckoutPage() {
//   return (
//     <main>
//       <h1>Checkout</h1>
//       <CheckoutButton
//         items={[{ id: 'item_1', quantity: 1 }]}
//         total={999}
//         onSuccess={(orderId) => router.push(`/order/${orderId}`)}
//       />
//     </main>
//   )
// }
*/

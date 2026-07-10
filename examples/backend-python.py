"""
KaizoCore — Backend integration (Python)

pip install fastapi uvicorn httpx flask

Environment variables required:
    KAIZO_API_KEY=sk_live_xxx    ← your secret key from app.kaizocore.com/api-keys

That's the only env var you need. The HMAC is derived directly from your
secret key — there is no separate HMAC secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any

import httpx

KAIZO_API_URL = "https://api.kaizocore.com"


# ─────────────────────────────────────────────────────────────────────────────
# kaizo_decide — core signing + request helper
#
# Args:
#   ip           str  — visitor IP from your web framework
#   user_agent   str  — User-Agent header from the browser request
#   kz_st        str  — value of the kz_st cookie (set automatically by c.js)
#   event_type   str  — 'login' | 'checkout' | 'signup' | 'payment' | etc.
#   entity_keys  dict — optional identifiers: { "user_id": "123", "email": "..." }
#
# Returns: dict with keys: decision, score, reasons, session_mode, latency_ms, request_id
# ─────────────────────────────────────────────────────────────────────────────
def kaizo_decide(
    *,
    ip: str,
    user_agent: str,
    kz_st: str,
    event_type: str,
    entity_keys: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_key = os.environ["KAIZO_API_KEY"]
    if not api_key.startswith("sk_live_"):
        raise ValueError("KAIZO_API_KEY must be set to sk_live_xxx")

    ts  = str(int(time.time()))
    rid = str(uuid.uuid4())

    body = json.dumps(
        {
            "ip":            ip,
            "user_agent":    user_agent,
            "session_token": kz_st,       # value of the kz_st cookie
            "event_type":    event_type,
            "entity_keys":   entity_keys or {},
            "timestamp":     int(ts),
        },
        separators=(",", ":"),            # compact — no extra whitespace
    )

    # HMAC-SHA256 — signed with your sk_live_xxx secret key directly.
    # api_key.encode() treats the string as UTF-8 bytes — do NOT hex-decode it.
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    sig_str   = "\n".join(["POST", "/v1/decide", ts, body_hash, rid])
    sig       = hmac.new(api_key.encode(), sig_str.encode(), hashlib.sha256).hexdigest()

    r = httpx.post(
        f"{KAIZO_API_URL}/v1/decide",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-KZ-Key":     api_key,
            "X-KZ-Ts":      ts,
            "X-KZ-Sig":     sig,
            "X-KZ-Rid":     rid,
        },
        timeout=5.0,
    )
    r.raise_for_status()
    return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# USE CASE 1: FastAPI checkout endpoint
#
# The kz_st cookie is sent automatically by the browser for same-origin
# requests — read it from the Cookie header via FastAPI's Cookie dependency.
# ─────────────────────────────────────────────────────────────────────────────

from fastapi import Cookie, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()


class CheckoutRequest(BaseModel):
    items: list[str]
    total: float


@app.post("/api/checkout")
async def checkout(
    body: CheckoutRequest,
    request: Request,
    kz_st: str | None = Cookie(default=None),
):
    if not kz_st:
        # Browser never ran c.js, or client is calling the API directly
        raise HTTPException(status_code=403, detail="session_missing")

    try:
        result = kaizo_decide(
            ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            kz_st=kz_st,
            event_type="checkout",
            entity_keys={"user_id": "123"},  # pass any IDs you have
        )
    except Exception as exc:
        # On unexpected errors, fail open to avoid blocking real users
        print(f"KaizoCore error: {exc}")
        result = {"decision": "ALLOW", "score": 0}

    decision = result["decision"]
    print(f"[kaizo] checkout decision={decision} score={result.get('score')}")

    if decision == "BLOCK":
        raise HTTPException(status_code=403, detail="blocked")
    if decision == "SOFT_CHALLENGE":
        return JSONResponse(status_code=202, content={"action": "challenge_required"})
    if decision == "REVIEW":
        # Queue for manual ops review; respond optimistically to user
        pass  # await enqueue_for_review(body, result)

    # ALLOW or ALLOW_WATCH — process the order
    return {"message": "Order placed!", "order_id": f"ord_{int(time.time())}"}


# ─────────────────────────────────────────────────────────────────────────────
# USE CASE 2: FastAPI login endpoint (same pattern)
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/login")
async def login(
    body: LoginRequest,
    request: Request,
    kz_st: str | None = Cookie(default=None),
):
    if not kz_st:
        raise HTTPException(status_code=403, detail="session_missing")

    try:
        result = kaizo_decide(
            ip=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
            kz_st=kz_st,
            event_type="login",
            entity_keys={"email": body.email},
        )
    except Exception as exc:
        print(f"KaizoCore error: {exc}")
        result = {"decision": "ALLOW", "score": 0}

    if result["decision"] == "BLOCK":
        raise HTTPException(status_code=403, detail="blocked")

    # Authenticate the user
    # user = await authenticate_user(body.email, body.password)
    return {"message": "Logged in!"}


# ─────────────────────────────────────────────────────────────────────────────
# USE CASE 3: FastAPI middleware — protect every mutating endpoint automatically
# ─────────────────────────────────────────────────────────────────────────────

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

SKIP_PATHS = {"/health", "/webhook/stripe", "/docs", "/openapi.json"}


class KaizoMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next) -> Response:
        # Only inspect mutating requests
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        kz_st = request.cookies.get("kz_st")
        if not kz_st:
            return JSONResponse(status_code=403, content={"error": "session_missing"})

        try:
            result = kaizo_decide(
                ip=request.client.host,
                user_agent=request.headers.get("user-agent", ""),
                kz_st=kz_st,
                event_type="api_call",
            )
        except Exception as exc:
            print(f"KaizoCore middleware error: {exc}")
            return await call_next(request)  # fail open

        if result["decision"] == "BLOCK":
            return JSONResponse(status_code=403, content={"error": "blocked"})

        # Attach result to request state for downstream handlers
        request.state.kaizo = result
        return await call_next(request)


# Register middleware (do this before adding routes in production)
# app.add_middleware(KaizoMiddleware)


# ─────────────────────────────────────────────────────────────────────────────
# USE CASE 4: Flask checkout (for Flask users)
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask, jsonify, request as flask_request

flask_app = Flask(__name__)


@flask_app.route("/api/checkout", methods=["POST"])
def flask_checkout():
    kz_st = flask_request.cookies.get("kz_st")
    if not kz_st:
        return jsonify({"error": "session_missing"}), 403

    try:
        result = kaizo_decide(
            ip=flask_request.remote_addr,
            user_agent=flask_request.headers.get("User-Agent", ""),
            kz_st=kz_st,
            event_type="checkout",
        )
    except Exception as exc:
        print(f"KaizoCore error: {exc}")
        result = {"decision": "ALLOW", "score": 0}

    if result["decision"] == "BLOCK":
        return jsonify({"error": "blocked"}), 403
    if result["decision"] == "SOFT_CHALLENGE":
        return jsonify({"action": "challenge_required"}), 202

    # Process the order
    return jsonify({"message": "Order placed!", "order_id": f"ord_{int(time.time())}"})

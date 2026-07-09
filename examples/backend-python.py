"""
KaizoCore — Backend integration example (Python)

pip install httpx
"""

import hashlib
import hmac
import json
import os
import time
import uuid

import httpx

KAIZO_API_URL = "https://api.kaizocore.com"


def kaizo_decide(*, ip: str, user_agent: str, session_token: str,
                 event_type: str, entity_keys: dict = None) -> dict:
    """
    Call /v1/decide before processing a protected action.

    Returns dict with: decision, score, reasons, latency_ms
    decision values: ALLOW | ALLOW_WATCH | SOFT_CHALLENGE | REVIEW | BLOCK
    """
    api_key     = os.environ["KAIZO_API_KEY"]       # pk_live_xxx
    hmac_secret = bytes.fromhex(os.environ["KAIZO_HMAC_SECRET"])

    ts  = str(int(time.time()))
    rid = str(uuid.uuid4())
    body = json.dumps({
        "ip":            ip,
        "user_agent":    user_agent,
        "session_token": session_token,
        "event_type":    event_type,
        "entity_keys":   entity_keys or {},
        "timestamp":     int(ts),
    }, separators=(",", ":"))

    body_hash = hashlib.sha256(body.encode()).hexdigest()
    sig_str   = "\n".join(["POST", "/v1/decide", ts, body_hash, rid])
    sig       = hmac.new(hmac_secret, sig_str.encode(), hashlib.sha256).hexdigest()

    r = httpx.post(
        f"{KAIZO_API_URL}/v1/decide",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-KZ-Key": api_key,
            "X-KZ-Ts":  ts,
            "X-KZ-Sig": sig,
            "X-KZ-Rid": rid,
        },
        timeout=5.0,
    )
    r.raise_for_status()
    return r.json()


# ── FastAPI / Flask example ───────────────────────────────────────────────────

# FastAPI:
# @app.post("/api/checkout")
# async def checkout(req: CheckoutRequest, request: Request):
#     result = kaizo_decide(
#         ip=request.client.host,
#         user_agent=request.headers.get("user-agent", ""),
#         session_token=req.session_token,
#         event_type="checkout",
#         entity_keys={"user_id": str(current_user.id)},
#     )
#     if result["decision"] == "BLOCK":
#         raise HTTPException(403, "Blocked")
#     # proceed...

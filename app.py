'use strict' if False else None  # noqa — this is Python, not Node

"""
HRFlow License Server
=====================
FastAPI server for license key activation, verification, and management.

Environment variables:
  LICENSE_SECRET   Required. HMAC-SHA256 signing secret (must match app/electron/license.js VERIFY_SECRET)
  ADMIN_KEY        Required. Bearer token for /admin/* endpoints
  DATABASE_PATH    Optional. SQLite DB path (default: ./licenses.db)
  PORT             Optional. Listen port (default: 9000)

Token format (must match Electron license.js exactly):
  base64url(payload_json) + "." + hex(HMAC-SHA256(payload_b64, LICENSE_SECRET))
  Payload: { key, mid, iat, exp, type, seats }
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import defaultdict, deque
from contextlib import contextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# ── Config ────────────────────────────────────────────────────────────────────

LICENSE_SECRET: str = os.environ.get("LICENSE_SECRET", "")
ADMIN_KEY: str = os.environ.get("ADMIN_KEY", "")
DATABASE_PATH: str = os.environ.get("DATABASE_PATH", "./licenses.db")

if not LICENSE_SECRET:
    raise RuntimeError("LICENSE_SECRET environment variable is required")
if not ADMIN_KEY:
    raise RuntimeError("ADMIN_KEY environment variable is required")

TOKEN_TTL_DAYS = 30          # fresh tokens issued for 30 days
KEY_ALPHABET   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# ── Database ──────────────────────────────────────────────────────────────────

def get_db_path() -> str:
    return DATABASE_PATH


def init_db() -> None:
    with sqlite3.connect(get_db_path()) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS license_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key        TEXT    UNIQUE NOT NULL,
                type       TEXT    NOT NULL DEFAULT 'annual',
                seats      INTEGER NOT NULL DEFAULT 1,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                notes      TEXT,
                revoked    INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS activations (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id       INTEGER NOT NULL REFERENCES license_keys(id),
                machine_id   TEXT    NOT NULL,
                activated_at INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                UNIQUE(key_id, machine_id)
            );
        """)


@contextmanager
def db():
    con = sqlite3.connect(get_db_path())
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


# ── Token helpers ─────────────────────────────────────────────────────────────

def _b64_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    # Re-add padding
    pad = (4 - len(s) % 4) % 4
    return urlsafe_b64decode(s + "=" * pad)


def _sign(payload_b64: str) -> str:
    return hmac.new(
        LICENSE_SECRET.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()


def _build_token(key: str, mid: str, type_: str, seats: int, expires_at: Optional[int]) -> str:
    now = int(time.time())
    payload = {
        "key":   key,
        "mid":   mid,
        "iat":   now,
        "type":  type_,
        "seats": seats,
    }
    if expires_at is not None:
        payload["exp"] = expires_at

    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _sign(payload_b64)
    return f"{payload_b64}.{sig}"


def _verify_token(token: str) -> Optional[dict]:
    """Verify HMAC and return decoded payload, or None on failure."""
    if not token or "." not in token:
        return None
    dot = token.rfind(".")
    payload_b64 = token[:dot]
    sig = token[dot + 1:]

    expected = _sign(payload_b64)
    # Constant-time compare
    if not hmac.compare_digest(sig.encode(), expected.encode()):
        return None

    try:
        return json.loads(_b64_decode(payload_b64).decode())
    except Exception:
        return None


# ── Key generation ────────────────────────────────────────────────────────────

def generate_key() -> str:
    """Generate a new HRFL-XXXX-XXXX-XXXX license key."""
    part = lambda: "".join(secrets.choice(KEY_ALPHABET) for _ in range(4))
    return f"HRFL-{part()}-{part()}-{part()}"


# ── Rate limiting (in-memory) ─────────────────────────────────────────────────

_rate_buckets: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(key: str, max_calls: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = time.monotonic()
    q = _rate_buckets[key]
    # Purge old timestamps
    while q and now - q[0] > window_seconds:
        q.popleft()
    if len(q) >= max_calls:
        return False
    q.append(now)
    return True


def rate_limit_activate(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"activate:{ip}", max_calls=10, window_seconds=600):
        raise HTTPException(status_code=429, detail="Too many activation attempts. Try again later.")


def rate_limit_verify(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"verify:{ip}", max_calls=30, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests.")


# ── Admin auth ────────────────────────────────────────────────────────────────

def require_admin(request: Request):
    provided = request.headers.get("X-Admin-Key", "")
    if not hmac.compare_digest(provided.encode(), ADMIN_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid admin key.")


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(title="HRFlow License Server", docs_url=None, redoc_url=None)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/admin")
def admin_ui():
    return FileResponse(os.path.join(os.path.dirname(__file__), "admin.html"))


# ── Request / Response models ─────────────────────────────────────────────────

class ActivateRequest(BaseModel):
    key: str
    mid: str


class VerifyRequest(BaseModel):
    token: str
    mid: str


class DeactivateRequest(BaseModel):
    token: str
    mid: str


class CreateKeyRequest(BaseModel):
    seats:       int            = 1
    type:        str            = "annual"
    expires_days: Optional[int] = 365
    notes:       Optional[str]  = None


class RenewRequest(BaseModel):
    expires_days: int = 365


# ── /activate ─────────────────────────────────────────────────────────────────

@app.post("/activate")
def activate(body: ActivateRequest, _=Depends(rate_limit_activate)):
    key = body.key.strip().upper()
    mid = body.mid.strip()

    with db() as con:
        row = con.execute(
            "SELECT * FROM license_keys WHERE key = ?", (key,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")
        if row["revoked"]:
            raise HTTPException(status_code=403, detail="License key has been revoked.")
        if row["expires_at"] and int(time.time()) > row["expires_at"]:
            raise HTTPException(status_code=403, detail="License key has expired.")

        # Check if this machine is already activated (idempotent)
        existing = con.execute(
            "SELECT id FROM activations WHERE key_id = ? AND machine_id = ?",
            (row["id"], mid),
        ).fetchone()

        if not existing:
            # Count active seats
            seat_count = con.execute(
                "SELECT COUNT(*) FROM activations WHERE key_id = ?", (row["id"],)
            ).fetchone()[0]
            if seat_count >= row["seats"]:
                raise HTTPException(status_code=403, detail="Seat limit reached.")

            now = int(time.time())
            con.execute(
                "INSERT INTO activations (key_id, machine_id, activated_at, last_seen) VALUES (?, ?, ?, ?)",
                (row["id"], mid, now, now),
            )
        else:
            con.execute(
                "UPDATE activations SET last_seen = ? WHERE key_id = ? AND machine_id = ?",
                (int(time.time()), row["id"], mid),
            )

        token = _build_token(key, mid, row["type"], row["seats"], row["expires_at"])

    return {
        "token":      token,
        "key":        key,
        "type":       row["type"],
        "seats":      row["seats"],
        "expires_at": row["expires_at"],
    }


# ── /verify ───────────────────────────────────────────────────────────────────

@app.post("/verify")
def verify(body: VerifyRequest, _=Depends(rate_limit_verify)):
    payload = _verify_token(body.token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token signature.")
    if payload.get("mid") != body.mid:
        raise HTTPException(status_code=401, detail="Machine ID mismatch.")

    key = payload.get("key", "")

    with db() as con:
        row = con.execute(
            "SELECT * FROM license_keys WHERE key = ?", (key,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")
        if row["revoked"]:
            raise HTTPException(status_code=403, detail="License key has been revoked.")
        if row["expires_at"] and int(time.time()) > row["expires_at"]:
            raise HTTPException(status_code=403, detail="License key has expired.")

        # Ensure activation record still exists
        existing = con.execute(
            "SELECT id FROM activations WHERE key_id = ? AND machine_id = ?",
            (row["id"], body.mid),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=403, detail="Machine not activated.")

        con.execute(
            "UPDATE activations SET last_seen = ? WHERE key_id = ? AND machine_id = ?",
            (int(time.time()), row["id"], body.mid),
        )

        # Issue fresh token (picks up any renewals)
        token = _build_token(key, body.mid, row["type"], row["seats"], row["expires_at"])

    return {"token": token}


# ── /deactivate ───────────────────────────────────────────────────────────────

@app.post("/deactivate")
def deactivate(body: DeactivateRequest):
    payload = _verify_token(body.token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token signature.")
    if payload.get("mid") != body.mid:
        raise HTTPException(status_code=401, detail="Machine ID mismatch.")

    key = payload.get("key", "")

    with db() as con:
        row = con.execute(
            "SELECT id FROM license_keys WHERE key = ?", (key,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")

        con.execute(
            "DELETE FROM activations WHERE key_id = ? AND machine_id = ?",
            (row["id"], body.mid),
        )

    return {"ok": True}


# ── /admin/keys (POST) — create key ──────────────────────────────────────────

@app.post("/admin/keys", dependencies=[Depends(require_admin)])
def admin_create_key(body: CreateKeyRequest):
    key = generate_key()
    now = int(time.time())
    expires_at = now + body.expires_days * 86400 if body.expires_days else None

    with db() as con:
        # Retry on the tiny chance of collision
        for _ in range(5):
            try:
                con.execute(
                    "INSERT INTO license_keys (key, type, seats, expires_at, created_at, notes, revoked) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (key, body.type, body.seats, expires_at, now, body.notes),
                )
                break
            except sqlite3.IntegrityError:
                key = generate_key()
        else:
            raise HTTPException(status_code=500, detail="Failed to generate unique key.")

    return {
        "key":        key,
        "type":       body.type,
        "seats":      body.seats,
        "expires_at": expires_at,
        "notes":      body.notes,
    }


# ── /admin/keys (GET) — list keys ────────────────────────────────────────────

@app.get("/admin/keys", dependencies=[Depends(require_admin)])
def admin_list_keys():
    with db() as con:
        rows = con.execute(
            """
            SELECT k.*, COUNT(a.id) AS active_seats
            FROM license_keys k
            LEFT JOIN activations a ON a.key_id = k.id
            GROUP BY k.id
            ORDER BY k.created_at DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]


# ── /admin/keys/{key}/activations (GET) ──────────────────────────────────────

@app.get("/admin/keys/{key}/activations", dependencies=[Depends(require_admin)])
def admin_list_activations(key: str):
    with db() as con:
        row = con.execute(
            "SELECT id FROM license_keys WHERE key = ?", (key.upper(),)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")
        acts = con.execute(
            "SELECT machine_id, activated_at, last_seen FROM activations WHERE key_id = ?",
            (row["id"],),
        ).fetchall()
    return [dict(a) for a in acts]


# ── /admin/keys/{key}/activations/{mid} (DELETE) ─────────────────────────────

@app.delete("/admin/keys/{key}/activations/{mid}", dependencies=[Depends(require_admin)])
def admin_remove_activation(key: str, mid: str):
    with db() as con:
        row = con.execute(
            "SELECT id FROM license_keys WHERE key = ?", (key.upper(),)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")
        con.execute(
            "DELETE FROM activations WHERE key_id = ? AND machine_id = ?",
            (row["id"], mid),
        )
    return {"ok": True}


# ── /admin/keys/{key}/revoke (POST) ──────────────────────────────────────────

@app.post("/admin/keys/{key}/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_key(key: str):
    with db() as con:
        result = con.execute(
            "UPDATE license_keys SET revoked = 1 WHERE key = ?", (key.upper(),)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found.")
    return {"ok": True}


# ── /admin/keys/{key}/unrevoke (POST) ────────────────────────────────────────

@app.post("/admin/keys/{key}/unrevoke", dependencies=[Depends(require_admin)])
def admin_unrevoke_key(key: str):
    with db() as con:
        result = con.execute(
            "UPDATE license_keys SET revoked = 0 WHERE key = ?", (key.upper(),)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found.")
    return {"ok": True}


# ── /admin/keys/{key}/renew (POST) ───────────────────────────────────────────

@app.post("/admin/keys/{key}/renew", dependencies=[Depends(require_admin)])
def admin_renew_key(key: str, body: RenewRequest):
    with db() as con:
        row = con.execute(
            "SELECT expires_at FROM license_keys WHERE key = ?", (key.upper(),)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")

        now = int(time.time())
        # Extend from today if already expired, otherwise extend from current expiry
        base = max(row["expires_at"] or now, now)
        new_expiry = base + body.expires_days * 86400

        con.execute(
            "UPDATE license_keys SET expires_at = ?, revoked = 0 WHERE key = ?",
            (new_expiry, key.upper()),
        )
    return {"ok": True, "expires_at": new_expiry}


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

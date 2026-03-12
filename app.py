'use strict' if False else None  # noqa: E701 - this is Python, not Node

"""
HRFlow License Server
=====================
FastAPI server for license key activation, verification, and management.

Environment variables:
  LICENSE_SECRET     Required. HMAC-SHA256 signing secret
  ADMIN_KEY          Required. Token for /admin/* endpoints
  DATABASE_URL       Required. Postgres connection string
  LEGACY_SQLITE_PATH Optional. SQLite file to import once during cutover
  DATABASE_PATH      Legacy alias for LEGACY_SQLITE_PATH
  PORT               Optional. Listen port (default: 9000)

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
from pathlib import Path
from typing import Optional

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from psycopg.rows import dict_row
from pydantic import BaseModel


LICENSE_SECRET: str = os.environ.get("LICENSE_SECRET", "")
ADMIN_KEY: str = os.environ.get("ADMIN_KEY", "")
DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
LEGACY_SQLITE_PATH: Optional[str] = os.environ.get("LEGACY_SQLITE_PATH") or os.environ.get("DATABASE_PATH")

if not LICENSE_SECRET:
    raise RuntimeError("LICENSE_SECRET environment variable is required")
if not ADMIN_KEY:
    raise RuntimeError("ADMIN_KEY environment variable is required")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

TOKEN_TTL_DAYS = 30
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with _connect() as con:
        with con.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS license_keys (
                    id BIGSERIAL PRIMARY KEY,
                    key TEXT UNIQUE NOT NULL,
                    type TEXT NOT NULL DEFAULT 'annual',
                    seats INTEGER NOT NULL DEFAULT 1 CHECK (seats > 0),
                    expires_at BIGINT,
                    created_at BIGINT NOT NULL,
                    updated_at BIGINT NOT NULL,
                    notes TEXT,
                    revoked BOOLEAN NOT NULL DEFAULT FALSE
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS activations (
                    id BIGSERIAL PRIMARY KEY,
                    key_id BIGINT NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
                    machine_id TEXT NOT NULL,
                    activated_at BIGINT NOT NULL,
                    last_seen BIGINT NOT NULL,
                    UNIQUE (key_id, machine_id)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_license_keys_created_at ON license_keys (created_at DESC)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_activations_key_id ON activations (key_id)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_activations_machine_id ON activations (machine_id)"
            )


def _sync_sequences(con) -> None:
    con.execute(
        """
        SELECT setval(
            pg_get_serial_sequence('license_keys', 'id'),
            COALESCE((SELECT MAX(id) FROM license_keys), 1),
            (SELECT COUNT(*) > 0 FROM license_keys)
        )
        """
    )
    con.execute(
        """
        SELECT setval(
            pg_get_serial_sequence('activations', 'id'),
            COALESCE((SELECT MAX(id) FROM activations), 1),
            (SELECT COUNT(*) > 0 FROM activations)
        )
        """
    )


def migrate_legacy_sqlite() -> None:
    if not LEGACY_SQLITE_PATH:
        return

    sqlite_path = Path(LEGACY_SQLITE_PATH)
    if not sqlite_path.exists() or not sqlite_path.is_file():
        return

    with _connect() as con:
        existing = con.execute("SELECT COUNT(*) AS count FROM license_keys").fetchone()
        if existing and existing["count"] > 0:
            return

        src = sqlite3.connect(str(sqlite_path))
        src.row_factory = sqlite3.Row
        try:
            tables = {
                row["name"]
                for row in src.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if "license_keys" not in tables:
                return

            license_rows = src.execute(
                """
                SELECT id, key, type, seats, expires_at, created_at, notes, revoked
                FROM license_keys
                ORDER BY id
                """
            ).fetchall()
            for row in license_rows:
                now = int(time.time())
                con.execute(
                    """
                    INSERT INTO license_keys (
                        id, key, type, seats, expires_at, created_at, updated_at, notes, revoked
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (key) DO NOTHING
                    """,
                    (
                        row["id"],
                        row["key"],
                        row["type"],
                        row["seats"],
                        row["expires_at"],
                        row["created_at"],
                        now,
                        row["notes"],
                        bool(row["revoked"]),
                    ),
                )

            if "activations" in tables:
                activation_rows = src.execute(
                    """
                    SELECT id, key_id, machine_id, activated_at, last_seen
                    FROM activations
                    ORDER BY id
                    """
                ).fetchall()
                for row in activation_rows:
                    con.execute(
                        """
                        INSERT INTO activations (
                            id, key_id, machine_id, activated_at, last_seen
                        ) VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (key_id, machine_id) DO NOTHING
                        """,
                        (
                            row["id"],
                            row["key_id"],
                            row["machine_id"],
                            row["activated_at"],
                            row["last_seen"],
                        ),
                    )

            _sync_sequences(con)
        finally:
            src.close()


@contextmanager
def db():
    con = _connect()
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _b64_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(value: str) -> bytes:
    pad = (4 - len(value) % 4) % 4
    return urlsafe_b64decode(value + "=" * pad)


def _sign(payload_b64: str) -> str:
    return hmac.new(
        LICENSE_SECRET.encode(),
        payload_b64.encode(),
        hashlib.sha256,
    ).hexdigest()


def _build_token(key: str, mid: str, type_: str, seats: int, expires_at: Optional[int]) -> str:
    now = int(time.time())
    payload = {
        "key": key,
        "mid": mid,
        "iat": now,
        "type": type_,
        "seats": seats,
    }
    if expires_at is not None:
        payload["exp"] = expires_at

    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{payload_b64}.{_sign(payload_b64)}"


def _verify_token(token: str) -> Optional[dict]:
    if not token or "." not in token:
        return None
    dot = token.rfind(".")
    payload_b64 = token[:dot]
    sig = token[dot + 1 :]

    expected = _sign(payload_b64)
    if not hmac.compare_digest(sig.encode(), expected.encode()):
        return None

    try:
        return json.loads(_b64_decode(payload_b64).decode())
    except Exception:
        return None


def generate_key() -> str:
    part = lambda: "".join(secrets.choice(KEY_ALPHABET) for _ in range(4))
    return f"HRFL-{part()}-{part()}-{part()}"


_rate_buckets: dict[str, deque] = defaultdict(deque)


def _check_rate_limit(key: str, max_calls: int, window_seconds: int) -> bool:
    now = time.monotonic()
    queue = _rate_buckets[key]
    while queue and now - queue[0] > window_seconds:
        queue.popleft()
    if len(queue) >= max_calls:
        return False
    queue.append(now)
    return True


def rate_limit_activate(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"activate:{ip}", max_calls=10, window_seconds=600):
        raise HTTPException(status_code=429, detail="Too many activation attempts. Try again later.")


def rate_limit_verify(request: Request):
    ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(f"verify:{ip}", max_calls=30, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many requests.")


def require_admin(request: Request):
    # Prefer header, but also allow ?admin=... for simple browser testing
    provided = request.headers.get("X-Admin-Key", "") or request.query_params.get("admin", "")
    if not hmac.compare_digest(provided.encode(), ADMIN_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid admin key.")


app = FastAPI(title="HRFlow License Server", docs_url=None, redoc_url=None)


@app.on_event("startup")
def on_startup():
    init_db()
    migrate_legacy_sqlite()


@app.get("/admin")
def admin_ui():
    return FileResponse(os.path.join(os.path.dirname(__file__), "admin.html"))


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
    seats: int = 1
    type: str = "annual"
    expires_days: Optional[int] = 365
    notes: Optional[str] = None


class RenewRequest(BaseModel):
    expires_days: int = 365


@app.post("/activate")
def activate(body: ActivateRequest, _=Depends(rate_limit_activate)):
    key = body.key.strip().upper()
    mid = body.mid.strip()

    with db() as con:
        row = con.execute(
            "SELECT * FROM license_keys WHERE key = %s",
            (key,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")
        if row["revoked"]:
            raise HTTPException(status_code=403, detail="License key has been revoked.")
        if row["expires_at"] and int(time.time()) > row["expires_at"]:
            raise HTTPException(status_code=403, detail="License key has expired.")

        existing = con.execute(
            "SELECT id FROM activations WHERE key_id = %s AND machine_id = %s",
            (row["id"], mid),
        ).fetchone()

        now = int(time.time())
        if not existing:
            seat_count = con.execute(
                "SELECT COUNT(*) AS count FROM activations WHERE key_id = %s",
                (row["id"],),
            ).fetchone()["count"]
            if seat_count >= row["seats"]:
                raise HTTPException(status_code=403, detail="Seat limit reached.")

            con.execute(
                """
                INSERT INTO activations (key_id, machine_id, activated_at, last_seen)
                VALUES (%s, %s, %s, %s)
                """,
                (row["id"], mid, now, now),
            )
        else:
            con.execute(
                "UPDATE activations SET last_seen = %s WHERE key_id = %s AND machine_id = %s",
                (now, row["id"], mid),
            )

        token = _build_token(key, mid, row["type"], row["seats"], row["expires_at"])

    return {
        "token": token,
        "key": key,
        "type": row["type"],
        "seats": row["seats"],
        "expires_at": row["expires_at"],
    }


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
            "SELECT * FROM license_keys WHERE key = %s",
            (key,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")
        if row["revoked"]:
            raise HTTPException(status_code=403, detail="License key has been revoked.")
        if row["expires_at"] and int(time.time()) > row["expires_at"]:
            raise HTTPException(status_code=403, detail="License key has expired.")

        existing = con.execute(
            "SELECT id FROM activations WHERE key_id = %s AND machine_id = %s",
            (row["id"], body.mid),
        ).fetchone()
        if not existing:
            raise HTTPException(status_code=403, detail="Machine not activated.")

        con.execute(
            "UPDATE activations SET last_seen = %s WHERE key_id = %s AND machine_id = %s",
            (int(time.time()), row["id"], body.mid),
        )

        token = _build_token(key, body.mid, row["type"], row["seats"], row["expires_at"])

    return {"token": token}


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
            "SELECT id FROM license_keys WHERE key = %s",
            (key,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="License key not found.")

        con.execute(
            "DELETE FROM activations WHERE key_id = %s AND machine_id = %s",
            (row["id"], body.mid),
        )

    return {"ok": True}


@app.post("/admin/keys", dependencies=[Depends(require_admin)])
def admin_create_key(body: CreateKeyRequest):
    now = int(time.time())
    expires_at = now + body.expires_days * 86400 if body.expires_days else None

    with db() as con:
        for _ in range(10):
            key = generate_key()
            created = con.execute(
                """
                INSERT INTO license_keys (
                    key, type, seats, expires_at, created_at, updated_at, notes, revoked
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, FALSE)
                ON CONFLICT (key) DO NOTHING
                RETURNING key
                """,
                (key, body.type, body.seats, expires_at, now, now, body.notes),
            ).fetchone()
            if created:
                break
        else:
            raise HTTPException(status_code=500, detail="Failed to generate unique key.")

    return {
        "key": key,
        "type": body.type,
        "seats": body.seats,
        "expires_at": expires_at,
        "notes": body.notes,
    }


@app.get("/admin/keys", dependencies=[Depends(require_admin)])
def admin_list_keys():
    with db() as con:
        rows = con.execute(
            """
            SELECT
                k.id,
                k.key,
                k.type,
                k.seats,
                k.expires_at,
                k.created_at,
                k.updated_at,
                k.notes,
                k.revoked,
                COUNT(a.id)::INTEGER AS active_seats
            FROM license_keys k
            LEFT JOIN activations a ON a.key_id = k.id
            GROUP BY k.id
            ORDER BY k.created_at DESC
            """
        ).fetchall()
    return rows


@app.get("/admin/keys/{key}/activations", dependencies=[Depends(require_admin)])
def admin_list_activations(key: str):
    with db() as con:
        row = con.execute(
            "SELECT id FROM license_keys WHERE key = %s",
            (key.upper(),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")
        acts = con.execute(
            """
            SELECT machine_id, activated_at, last_seen
            FROM activations
            WHERE key_id = %s
            ORDER BY activated_at DESC
            """,
            (row["id"],),
        ).fetchall()
    return acts


@app.get("/admin/debug-db", dependencies=[Depends(require_admin)])
def admin_debug_db():
    """
    Diagnostics endpoint to confirm which database the server is using
    and how many license keys currently exist.
    """
    with db() as con:
        meta = con.execute(
            "SELECT current_database() AS database, current_schema() AS schema"
        ).fetchone()
        counts = con.execute(
            "SELECT COUNT(*) AS license_keys FROM license_keys"
        ).fetchone()
    return {
        "database": meta["database"],
        "schema": meta["schema"],
        "license_keys": counts["license_keys"],
    }


@app.delete("/admin/keys/{key}/activations/{mid}", dependencies=[Depends(require_admin)])
def admin_remove_activation(key: str, mid: str):
    with db() as con:
        row = con.execute(
            "SELECT id FROM license_keys WHERE key = %s",
            (key.upper(),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")
        con.execute(
            "DELETE FROM activations WHERE key_id = %s AND machine_id = %s",
            (row["id"], mid),
        )
    return {"ok": True}


@app.post("/admin/keys/{key}/revoke", dependencies=[Depends(require_admin)])
def admin_revoke_key(key: str):
    with db() as con:
        result = con.execute(
            "UPDATE license_keys SET revoked = TRUE, updated_at = %s WHERE key = %s",
            (int(time.time()), key.upper()),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found.")
    return {"ok": True}


@app.post("/admin/keys/{key}/unrevoke", dependencies=[Depends(require_admin)])
def admin_unrevoke_key(key: str):
    with db() as con:
        result = con.execute(
            "UPDATE license_keys SET revoked = FALSE, updated_at = %s WHERE key = %s",
            (int(time.time()), key.upper()),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Key not found.")
    return {"ok": True}


@app.post("/admin/keys/{key}/renew", dependencies=[Depends(require_admin)])
def admin_renew_key(key: str, body: RenewRequest):
    with db() as con:
        row = con.execute(
            "SELECT expires_at FROM license_keys WHERE key = %s",
            (key.upper(),),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Key not found.")

        now = int(time.time())
        base = max(row["expires_at"] or now, now)
        new_expiry = base + body.expires_days * 86400

        con.execute(
            """
            UPDATE license_keys
            SET expires_at = %s, revoked = FALSE, updated_at = %s
            WHERE key = %s
            """,
            (new_expiry, now, key.upper()),
        )
    return {"ok": True, "expires_at": new_expiry}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

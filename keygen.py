#!/usr/bin/env python3
"""
HRFlow License Admin CLI
========================
Manage license keys from the command line.

Usage:
  python keygen.py new   [--seats N] [--type annual] [--expires-days N] [--notes "text"]
  python keygen.py list  [--show-revoked]
  python keygen.py show  HRFL-XXXX-XXXX-XXXX
  python keygen.py revoke   HRFL-XXXX-XXXX-XXXX
  python keygen.py unrevoke HRFL-XXXX-XXXX-XXXX
  python keygen.py renew HRFL-XXXX-XXXX-XXXX [--expires-days N]
  python keygen.py deactivate-machine HRFL-XXXX-XXXX-XXXX <machine_id>
  python keygen.py activations HRFL-XXXX-XXXX-XXXX

Environment:
  ADMIN_KEY      Required. Must match the server's ADMIN_KEY.
  SERVER_URL     Optional. Default: http://localhost:9000
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Optional

SERVER_URL: str = os.environ.get("SERVER_URL", "http://localhost:9000").rstrip("/")
ADMIN_KEY:  str = os.environ.get("ADMIN_KEY", "")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Optional[dict] = None) -> Any:
    if not ADMIN_KEY:
        _die("ADMIN_KEY environment variable is not set.")

    url = SERVER_URL + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "X-Admin-Key":   ADMIN_KEY,
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = body
        _die(f"HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        _die(f"Cannot reach server at {SERVER_URL}: {e.reason}")


def _get(path: str) -> Any:
    return _request("GET", path)


def _post(path: str, body: Optional[dict] = None) -> Any:
    return _request("POST", path, body or {})


def _delete(path: str) -> Any:
    return _request("DELETE", path)


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _die(msg: str) -> None:
    print(f"Error: {msg}", file=sys.stderr)
    sys.exit(1)


def _fmt_ts(ts: Optional[int]) -> str:
    if ts is None:
        return "never"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _fmt_days_left(expires_at: Optional[int]) -> str:
    if expires_at is None:
        return "perpetual"
    now = int(__import__("time").time())
    days = (expires_at - now) // 86400
    if days < 0:
        return f"EXPIRED {abs(days)}d ago"
    return f"{days}d left"


def _print_key(row: dict) -> None:
    print(f"  Key:        {row.get('key', '?')}")
    print(f"  Type:       {row.get('type', '?')}")
    print(f"  Seats:      {row.get('active_seats', '?')}/{row.get('seats', '?')} used")
    print(f"  Expires:    {_fmt_ts(row.get('expires_at'))}  ({_fmt_days_left(row.get('expires_at'))})")
    print(f"  Revoked:    {'YES' if row.get('revoked') else 'no'}")
    print(f"  Created:    {_fmt_ts(row.get('created_at'))}")
    if row.get("notes"):
        print(f"  Notes:      {row['notes']}")


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_new(args: argparse.Namespace) -> None:
    body: dict = {
        "seats":        args.seats,
        "type":         args.type,
        "expires_days": args.expires_days,
        "notes":        args.notes,
    }
    result = _post("/admin/keys", body)
    print(f"\nNew license key created:")
    print(f"  Key:        {result['key']}")
    print(f"  Type:       {result['type']}")
    print(f"  Seats:      {result['seats']}")
    print(f"  Expires:    {_fmt_ts(result.get('expires_at'))}  ({_fmt_days_left(result.get('expires_at'))})")
    if result.get("notes"):
        print(f"  Notes:      {result['notes']}")
    print()


def cmd_list(args: argparse.Namespace) -> None:
    rows = _get("/admin/keys")
    if not rows:
        print("No keys found.")
        return

    active = [r for r in rows if not r.get("revoked")]
    revoked = [r for r in rows if r.get("revoked")]

    print(f"\n{'─'*60}")
    print(f"  {'KEY':<22}  {'SEATS':>5}  {'EXPIRES':>12}  NOTES")
    print(f"{'─'*60}")
    for r in active:
        expiry = _fmt_days_left(r.get("expires_at"))
        seats  = f"{r.get('active_seats', 0)}/{r.get('seats', 0)}"
        notes  = (r.get("notes") or "")[:20]
        print(f"  {r['key']:<22}  {seats:>5}  {expiry:>12}  {notes}")

    if revoked and getattr(args, "show_revoked", False):
        print(f"\n  REVOKED ({len(revoked)}):")
        for r in revoked:
            print(f"  {r['key']}  — {r.get('notes') or ''}")

    print(f"{'─'*60}")
    print(f"  Total: {len(active)} active, {len(revoked)} revoked\n")


def cmd_show(args: argparse.Namespace) -> None:
    key = args.key.upper()
    # Pull from list (server has no single-key GET; filter client-side)
    rows = _get("/admin/keys")
    row = next((r for r in rows if r["key"] == key), None)
    if not row:
        _die(f"Key {key} not found.")
    print(f"\n{'─'*40}")
    _print_key(row)
    print(f"{'─'*40}\n")


def cmd_revoke(args: argparse.Namespace) -> None:
    key = args.key.upper()
    _post(f"/admin/keys/{key}/revoke")
    print(f"Key {key} has been revoked.")
    print("All machines will be locked within 7 days (next revalidation).")


def cmd_unrevoke(args: argparse.Namespace) -> None:
    key = args.key.upper()
    _post(f"/admin/keys/{key}/unrevoke")
    print(f"Key {key} is now active again.")


def cmd_renew(args: argparse.Namespace) -> None:
    key = args.key.upper()
    result = _post(f"/admin/keys/{key}/renew", {"expires_days": args.expires_days})
    new_exp = result.get("expires_at")
    print(f"Key {key} renewed.")
    print(f"New expiry: {_fmt_ts(new_exp)}  ({_fmt_days_left(new_exp)})")


def cmd_activations(args: argparse.Namespace) -> None:
    key = args.key.upper()
    acts = _get(f"/admin/keys/{key}/activations")
    if not acts:
        print(f"No active machines for {key}.")
        return
    print(f"\nActive machines for {key}:")
    print(f"  {'MACHINE ID':<20}  {'ACTIVATED':>22}  {'LAST SEEN':>22}")
    print(f"  {'─'*20}  {'─'*22}  {'─'*22}")
    for a in acts:
        print(
            f"  {a['machine_id']:<20}  "
            f"{_fmt_ts(a.get('activated_at')):>22}  "
            f"{_fmt_ts(a.get('last_seen')):>22}"
        )
    print()


def cmd_deactivate_machine(args: argparse.Namespace) -> None:
    key = args.key.upper()
    mid = args.machine_id
    _delete(f"/admin/keys/{key}/activations/{mid}")
    print(f"Machine {mid} removed from key {key}. Seat freed.")


# ── Arg parsing ────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HRFlow License Admin CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # new
    p_new = sub.add_parser("new", help="Generate a new license key")
    p_new.add_argument("--seats",        type=int, default=1,     help="Number of machines (default: 1)")
    p_new.add_argument("--type",         default="annual",         help="License type (default: annual)")
    p_new.add_argument("--expires-days", type=int, default=365,    dest="expires_days",
                       help="Days until expiry (default: 365; 0 = perpetual)")
    p_new.add_argument("--notes",        default=None,             help="Optional notes (org name, etc.)")

    # list
    p_list = sub.add_parser("list", help="List all license keys")
    p_list.add_argument("--show-revoked", action="store_true", help="Include revoked keys")

    # show
    p_show = sub.add_parser("show", help="Show details for a specific key")
    p_show.add_argument("key", help="License key (HRFL-XXXX-XXXX-XXXX)")

    # revoke
    p_rev = sub.add_parser("revoke", help="Revoke a license key")
    p_rev.add_argument("key")

    # unrevoke
    p_unrev = sub.add_parser("unrevoke", help="Un-revoke a license key")
    p_unrev.add_argument("key")

    # renew
    p_renew = sub.add_parser("renew", help="Extend a license key's expiry")
    p_renew.add_argument("key")
    p_renew.add_argument("--expires-days", type=int, default=365, dest="expires_days",
                         help="Days to extend from today/current expiry (default: 365)")

    # activations
    p_acts = sub.add_parser("activations", help="List machines activated on a key")
    p_acts.add_argument("key")

    # deactivate-machine
    p_dm = sub.add_parser("deactivate-machine", help="Remove a specific machine from a key")
    p_dm.add_argument("key",        help="License key")
    p_dm.add_argument("machine_id", help="Machine ID to remove")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "new":                  cmd_new,
        "list":                 cmd_list,
        "show":                 cmd_show,
        "revoke":               cmd_revoke,
        "unrevoke":             cmd_unrevoke,
        "renew":                cmd_renew,
        "activations":          cmd_activations,
        "deactivate-machine":   cmd_deactivate_machine,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Signed approval line signer/verifier for the Errow -> Vendetta feedback loop.

Traces: CONTRACT §6 (live actions need ERROW_FEEDBACK_LIVE=true AND a signed approval line in
errow/feedback-loop/APPROVALS.md matching finding fingerprint + approver + ISO expiry); G9 offensive safety.
Stdlib only. The format is documented in APPROVALS.md.

  approval.py keygen --approver A [--keys-dir D] [--force]
  approval.py sign   --fingerprint F --approver A [--ttl-hours N | --expires ISO] [--key-file K] [--keys-dir D]
  approval.py verify --fingerprint F [--file APPROVALS.md] [--keys-dir D] [--key-file K] [--approvers a,b] [--threshold N]

Authority is per approver: a line is valid only if `sig` verifies with *that approver's* key
(`<keys-dir>/<approver>.key`), so one person's key cannot sign for another. Threshold N distinct approvers
(default `ERROW_FEEDBACK_APPROVAL_THRESHOLD`, 2) are required for one fingerprint. A deployment that still has
only the single shared key (`ERROW_FEEDBACK_APPROVAL_KEY_FILE`) keeps working: the threshold is clamped to the
number of distinct authority sources (per-approver keys plus the shared key), so a lone shared key means one
signature.

Exit codes: 0 approved / signed / created, 1 not approved or threshold unmet (reason on stderr),
2 usage or configuration error (no usable key, key too short, unreadable ledger, threshold < 1).
Any non-zero exit means "no approval"; callers must fail closed.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

DOMAIN = "errow-feedback-approval-v1"
DEFAULT_KEY_FILE = "/run/secrets/feedback_approval_key"
MIN_KEY_CHARS = 32
MAX_SIGN_TTL_HOURS = 168
DEFAULT_THRESHOLD = 2
KEY_SUFFIX = ".key"
LINE_RE = re.compile(
    r"^APPROVAL fingerprint=(?P<fp>[0-9a-f]{64}) approver=(?P<approver>[A-Za-z0-9._@-]{1,64})"
    r" expires=(?P<exp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z) sig=(?P<sig>[0-9a-f]{64})$"
)
FP_RE = re.compile(r"^[0-9a-f]{64}$")
APPROVER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


class UsageError(Exception):
    pass


def parse_iso(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise UsageError(f"not an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ): {value!r}") from exc


def fmt_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_key(path: str) -> bytes:
    try:
        key = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise UsageError(f"approval key file unreadable: {path}: {exc.strerror}") from exc
    if len(key) < MIN_KEY_CHARS:
        raise UsageError(f"approval key in {path} is shorter than {MIN_KEY_CHARS} characters")
    return key.encode("utf-8")


def keys_dir_for(keys_dir: str, key_file: str) -> str:
    """Per-approver keys live next to the shared key unless a directory is given."""
    if keys_dir:
        return keys_dir
    return str(Path(key_file).parent / "keys")


def approver_keys(keys_dir: str, key_file: str, approvers: set[str] | None = None) -> dict[str, bytes]:
    """Readable per-approver keys: {approver: key}. Unreadable or short files are skipped, not fatal."""
    found: dict[str, bytes] = {}
    try:
        entries = sorted(Path(keys_dir).iterdir())
    except OSError:
        return found
    for entry in entries:
        if not entry.name.endswith(KEY_SUFFIX) or not entry.is_file():
            continue
        approver = entry.name[: -len(KEY_SUFFIX)]
        if not APPROVER_RE.match(approver) or (approvers and approver not in approvers):
            continue
        try:
            found[approver] = read_key(str(entry))
        except UsageError:
            continue
    return found


def usable_keys(keys_dir: str, key_file: str, approvers: set[str] | None = None) -> tuple[dict[str, bytes], bytes | None]:
    """(per-approver keys, shared key or None). Raises UsageError when no key is usable at all."""
    per_approver = approver_keys(keys_dir, key_file, approvers)
    shared = None
    try:
        shared = read_key(key_file)
    except UsageError:
        shared = None
    if not per_approver and shared is None:
        raise UsageError(
            f"no usable approval key: neither {keys_dir}/<approver>{KEY_SUFFIX} nor {key_file} is readable "
            f"(generate one with 'approval.py keygen --approver NAME')"
        )
    return per_approver, shared


def resolve_threshold(requested: int, keys: dict[str, bytes], shared: bytes | None) -> int:
    """Clamp the threshold to the number of distinct authority sources, so a lone shared key is not unsatisfiable."""
    if requested < 1:
        raise UsageError(f"threshold must be >= 1 (got {requested})")
    authorities = len(keys) + (1 if shared is not None else 0)
    return max(1, min(requested, authorities))


def signature(key: bytes, fingerprint: str, approver: str, expires: str) -> str:
    message = f"{DOMAIN}\nfingerprint={fingerprint}\napprover={approver}\nexpires={expires}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def approval_lines(text: str):
    """Yield candidate lines, skipping fenced code blocks so documentation examples never count."""
    fenced = False
    for raw in text.splitlines():
        if raw.startswith("```"):
            fenced = not fenced
            continue
        if not fenced and raw.startswith("APPROVAL "):
            yield raw.rstrip("\r")


def verify(
    text: str,
    keys: dict[str, bytes],
    shared: bytes | None,
    fingerprint: str,
    now: datetime,
    approvers: set[str],
    max_days: int,
    threshold: int,
):
    """Return [(approver, expires)] once `threshold` distinct approvers agree; raise LookupError(reason) otherwise."""
    reasons: list[str] = []
    valid: dict[str, str] = {}
    for line in approval_lines(text):
        match = LINE_RE.match(line)
        if not match:
            reasons.append("malformed approval line ignored")
            continue
        if match["fp"] != fingerprint:
            continue
        approver = match["approver"]
        if approver in valid:
            reasons.append(f"duplicate approval line for approver {approver} ignored")
            continue
        if approvers and approver not in approvers:
            reasons.append(f"approver {approver} is not in the allowed approver list")
            continue
        expected_candidates = [k for k in (keys.get(approver), shared) if k is not None]
        if not expected_candidates:
            reasons.append(f"no key for approver {approver}")
            continue
        if not any(hmac.compare_digest(signature(k, match["fp"], approver, match["exp"]), match["sig"]) for k in expected_candidates):
            reasons.append(f"bad signature for approver {approver}")
            continue
        expires = parse_iso(match["exp"])
        if expires <= now:
            reasons.append(f"approval by {approver} expired at {match['exp']}")
            continue
        if expires - now > timedelta(days=max_days):
            reasons.append(f"approval by {approver} expires more than {max_days} days ahead")
            continue
        valid[approver] = match["exp"]
        if len(valid) >= threshold:
            return list(valid.items())
    if valid:
        raise LookupError(
            f"only {len(valid)} of {threshold} required approvers signed this fingerprint "
            f"({', '.join(sorted(valid))})"
        )
    raise LookupError("; ".join(dict.fromkeys(reasons)) or "no approval line for this fingerprint")


def cmd_keygen(args: argparse.Namespace) -> int:
    if not APPROVER_RE.match(args.approver):
        raise UsageError("approver must match [A-Za-z0-9._@-]{1,64}")
    keys_dir = keys_dir_for(args.keys_dir, args.key_file)
    path = Path(keys_dir) / f"{args.approver}{KEY_SUFFIX}"
    if path.exists() and not args.force:
        raise UsageError(f"{path} already exists (use --force to overwrite — this invalidates existing lines)")
    created = not Path(keys_dir).is_dir()
    Path(keys_dir).mkdir(parents=True, exist_ok=True)
    if created:
        os.chmod(keys_dir, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(f"{secrets.token_hex(32)}\n")
    os.chmod(path, 0o600)
    print(path)
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    if not FP_RE.match(args.fingerprint):
        raise UsageError("fingerprint must be 64 lowercase hex characters")
    if not APPROVER_RE.match(args.approver):
        raise UsageError("approver must match [A-Za-z0-9._@-]{1,64}")
    now = datetime.now(timezone.utc)
    if args.expires:
        expires = args.expires
        parse_iso(expires)
    else:
        if not 1 <= args.ttl_hours <= MAX_SIGN_TTL_HOURS:
            raise UsageError(f"--ttl-hours must be 1..{MAX_SIGN_TTL_HOURS}")
        expires = fmt_iso(now + timedelta(hours=args.ttl_hours))
    key_file = args.key_file
    if key_file is None:
        per_approver = Path(keys_dir_for(args.keys_dir, default_key_file())) / f"{args.approver}{KEY_SUFFIX}"
        key_file = str(per_approver) if per_approver.exists() else default_key_file()
    key = read_key(key_file)
    sig = signature(key, args.fingerprint, args.approver, expires)
    print(f"APPROVAL fingerprint={args.fingerprint} approver={args.approver} expires={expires} sig={sig}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    if not FP_RE.match(args.fingerprint):
        raise UsageError("fingerprint must be 64 lowercase hex characters")
    try:
        text = Path(args.file).read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageError(f"approvals file unreadable: {args.file}: {exc.strerror}") from exc
    key_file = args.key_file or default_key_file()
    approvers = {a.strip() for a in args.approvers.split(",") if a.strip()}
    keys, shared = usable_keys(keys_dir_for(args.keys_dir, key_file), key_file, approvers)
    threshold = resolve_threshold(args.threshold, keys, shared)
    now = parse_iso(args.now) if args.now else datetime.now(timezone.utc)
    try:
        valid = verify(text, keys, shared, args.fingerprint, now, approvers, args.max_days, threshold)
    except LookupError as exc:
        print(f"not approved: {exc}", file=sys.stderr)
        return 1
    print(f"approved approvers={','.join(a for a, _ in valid)} expiry={min(e for _, e in valid)} threshold={threshold}")
    return 0


def default_key_file() -> str:
    return os.environ.get("ERROW_FEEDBACK_APPROVAL_KEY_FILE", DEFAULT_KEY_FILE)


def default_threshold() -> int:
    try:
        return int(os.environ.get("ERROW_FEEDBACK_APPROVAL_THRESHOLD", str(DEFAULT_THRESHOLD)))
    except ValueError:
        return DEFAULT_THRESHOLD


def build_parser() -> argparse.ArgumentParser:
    here = Path(__file__).resolve().parent
    key_default = default_key_file()
    parser = argparse.ArgumentParser(prog="approval.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("keygen", help="create a per-approver 0600 key file")
    gen.add_argument("--approver", required=True)
    gen.add_argument("--keys-dir", default=os.environ.get("ERROW_FEEDBACK_APPROVAL_KEYS_DIR"))
    gen.add_argument("--key-file", default=key_default, help="only used to derive the default keys directory")
    gen.add_argument("--force", action="store_true", help="overwrite an existing key (invalidates its lines)")
    gen.set_defaults(func=cmd_keygen)

    sign = sub.add_parser("sign", help="print a signed APPROVAL line for APPROVALS.md")
    sign.add_argument("--fingerprint", required=True)
    sign.add_argument("--approver", required=True)
    sign.add_argument("--ttl-hours", type=int, default=24)
    sign.add_argument("--expires", help="explicit ISO-8601 UTC expiry (YYYY-MM-DDTHH:MM:SSZ)")
    sign.add_argument("--keys-dir", default=os.environ.get("ERROW_FEEDBACK_APPROVAL_KEYS_DIR"))
    sign.add_argument("--key-file", default=None, help=f"default <keys-dir>/<approver>.key, else {key_default}")
    sign.set_defaults(func=cmd_sign)

    ver = sub.add_parser("verify", help="exit 0 only when the threshold of valid approvals is met")
    ver.add_argument("--fingerprint", required=True)
    ver.add_argument("--file", default=os.environ.get("ERROW_FEEDBACK_APPROVALS_FILE", str(here / "APPROVALS.md")))
    ver.add_argument("--keys-dir", default=os.environ.get("ERROW_FEEDBACK_APPROVAL_KEYS_DIR"))
    ver.add_argument("--key-file", default=None, help=f"shared fallback key (default {key_default})")
    ver.add_argument("--approvers", default=os.environ.get("ERROW_FEEDBACK_APPROVERS", ""))
    ver.add_argument("--threshold", type=int, default=default_threshold())
    ver.add_argument("--max-days", type=int, default=int(os.environ.get("ERROW_FEEDBACK_APPROVAL_MAX_DAYS", "30")))
    ver.add_argument("--now", help="override the current time (tests)")
    ver.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return args.func(args)
    except UsageError as exc:
        print(f"approval.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Rate-limited load generator for the capacity test plan (docs/capacity.md).

Posts synthetic records to a Fluent Bit HTTP test hook (POST /<tag>, Content-Type: application/json) or to the
llm-gateway /triage endpoint, at a fixed rate for a fixed time, and prints a JSON summary (sent, ok, errors,
achieved rate, latency percentiles). stdlib only; no external target is ever contacted unless you pass it.

  # 500 events/s of Vendetta alerts for 120 s through Fluent Bit (smoke network):
  python3 tests/loadgen.py fluentbit --url http://fluent-bit:9880 --tag vendetta.alerts --rate 500 --seconds 120
  # 2 triage requests/s against the gateway (token from a secret file, CA bundle for TLS):
  python3 tests/loadgen.py triage --url https://llm-gateway:9101 --token-file /run/secrets/llm_gateway_token \
      --cafile /pki/ca.crt --rate 2 --seconds 60
"""
from __future__ import annotations

import argparse
import json
import pathlib
import queue
import ssl
import statistics
import threading
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "synthetic-logs"


def load_template(name: str) -> dict:
    with (FIXTURES / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def build_record(kind: str, tag: str, seq: int) -> bytes:
    if kind == "fluentbit":
        fixture = "vendetta-fim.json" if tag.endswith("fim") else "vendetta-alert.json"
        rec = load_template(fixture)
        rec["id"] = f"loadgen-{seq}-{time.time_ns()}"
        rec["full_log"] = f"{rec.get('full_log', 'loadgen')} seq={seq}"
        return json.dumps(rec).encode()
    rec = load_template("vendetta-alert.json")
    rec["id"] = f"loadgen-{seq}-{time.time_ns()}"
    return json.dumps(rec).encode()


def worker(q: queue.Queue[int | None], args: argparse.Namespace, ctx, headers: dict, results: list, lock) -> None:
    path = f"/{args.tag}" if args.mode == "fluentbit" else "/triage"
    url = args.url.rstrip("/") + path
    while True:
        seq = q.get()
        if seq is None:
            return
        body = build_record(args.mode, args.tag, seq)
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        t0 = time.perf_counter()
        ok = False
        try:
            with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as resp:
                resp.read()
                ok = 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            ok = False
        with lock:
            results.append((ok, time.perf_counter() - t0))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["fluentbit", "triage"])
    ap.add_argument("--url", required=True)
    ap.add_argument("--tag", default="vendetta.alerts", help="Fluent Bit HTTP hook tag (fluentbit mode)")
    ap.add_argument("--rate", type=float, required=True, help="requests per second")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--token-file", help="bearer token file (triage mode)")
    ap.add_argument("--cafile", help="CA bundle for https")
    args = ap.parse_args()
    if args.rate <= 0 or args.seconds <= 0:
        ap.error("--rate and --seconds must be positive")

    headers = {"Content-Type": "application/json"}
    if args.token_file:
        headers["Authorization"] = "Bearer " + pathlib.Path(args.token_file).read_text(encoding="utf-8").strip()
    ctx = ssl.create_default_context(cafile=args.cafile) if args.url.startswith("https") else None

    q: queue.Queue[int | None] = queue.Queue(maxsize=int(args.rate * 5) + args.workers)
    results: list[tuple[bool, float]] = []
    lock = threading.Lock()
    threads = [threading.Thread(target=worker, args=(q, args, ctx, headers, results, lock), daemon=True)
               for _ in range(args.workers)]
    for t in threads:
        t.start()

    start = time.perf_counter()
    interval = 1.0 / args.rate
    seq = dropped = 0
    while (now := time.perf_counter()) - start < args.seconds:
        target = start + seq * interval
        if target > now:
            time.sleep(target - now)
        try:
            q.put_nowait(seq)
        except queue.Full:
            dropped += 1
        seq += 1
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join(timeout=args.timeout + 5)

    elapsed = time.perf_counter() - start
    lat = sorted(d for _, d in results)

    def pct(p: float) -> float | None:
        return round(lat[min(len(lat) - 1, int(len(lat) * p))] * 1000, 1) if lat else None

    summary = {
        "mode": args.mode, "target_rate": args.rate, "seconds": round(elapsed, 1), "scheduled": seq,
        "completed": len(results), "ok": sum(1 for ok, _ in results if ok),
        "errors": sum(1 for ok, _ in results if not ok), "client_dropped": dropped,
        "achieved_rate": round(len(results) / elapsed, 1),
        "latency_ms": {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99),
                       "mean": round(statistics.fmean(lat) * 1000, 1) if lat else None},
    }
    print(json.dumps(summary, indent=2))
    return 0 if summary["errors"] == 0 and dropped == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

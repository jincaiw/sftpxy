#!/usr/bin/env python3
"""Minimal HTTP load tester with no third-party dependencies.

Prints p50/p95/p99/max latency, throughput and the error count, then exits
non-zero when the run misses the thresholds you pass. Useful as a smoke load
check before a release, not as a benchmark suite.

Usage:
  scripts/loadtest.py URL --requests 500 --concurrency 50 \
      --max-error-rate 0 --max-p95-ms 500 [--header 'Authorization: Bearer x']
"""
import argparse
import http.client
import statistics
import threading
import time
import urllib.parse


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("url")
    p.add_argument("--requests", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--max-error-rate", type=float, default=0.0,
                   help="fraction, e.g. 0.01 for 1%%")
    p.add_argument("--max-p95-ms", type=float, default=1000.0)
    p.add_argument("--header", action="append", default=[])
    return p.parse_args()


def main():
    args = parse_args()
    u = urllib.parse.urlsplit(args.url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    headers = {"Connection": "keep-alive"}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    latencies = []
    errors = 0
    lock = threading.Lock()
    counter = {"n": 0}

    def worker():
        nonlocal errors
        conn = None
        while True:
            with lock:
                if counter["n"] >= args.requests:
                    break
                counter["n"] += 1
            start = time.perf_counter()
            ok = False
            try:
                if conn is None:
                    conn = http.client.HTTPConnection(host, port, timeout=10)
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                resp.read()
                ok = 200 <= resp.status < 400
            except Exception:
                ok = False
                conn = None
            elapsed = (time.perf_counter() - start) * 1000.0
            with lock:
                latencies.append(elapsed)
                if not ok:
                    errors += 1
        if conn is not None:
            conn.close()

    threads = [threading.Thread(target=worker) for _ in range(args.concurrency)]
    t0 = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total = time.perf_counter() - t0

    if not latencies:
        print("no requests completed")
        return 2
    latencies.sort()

    def pct(p):
        idx = min(len(latencies) - 1, int(round((p / 100.0) * len(latencies) + 0.5)) - 1)
        return latencies[max(0, idx)]

    n = len(latencies)
    error_rate = errors / n
    rps = n / total if total > 0 else 0
    print(f"url={args.url}")
    print(f"requests={n} concurrency={args.concurrency} duration={total:.2f}s rps={rps:.1f}")
    print(f"latency_ms p50={pct(50):.1f} p95={pct(95):.1f} p99={pct(99):.1f} "
          f"max={latencies[-1]:.1f} mean={statistics.mean(latencies):.1f}")
    print(f"errors={errors} error_rate={error_rate:.4%}")

    failed = False
    if error_rate > args.max_error_rate:
        print(f"FAIL: error_rate {error_rate:.4%} > {args.max_error_rate:.4%}")
        failed = True
    if pct(95) > args.max_p95_ms:
        print(f"FAIL: p95 {pct(95):.1f}ms > {args.max_p95_ms}ms")
        failed = True
    if failed:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

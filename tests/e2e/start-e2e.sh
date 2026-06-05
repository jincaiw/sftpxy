#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

mkdir -p data/e2e
rm -f data/e2e/sftpxy.db data/e2e/sftpxy.db-* data/e2e/sftpxy.log
rm -rf data/e2e/home data/e2e/tmp
mkdir -p data/e2e/home data/e2e/tmp

./bin/sftpxy --config config.e2e.yaml &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

python3 - <<'PY'
import sqlite3
import time
from pathlib import Path

db_path = Path("data/e2e/sftpxy.db")
deadline = time.time() + 30

while time.time() < deadline:
    if not db_path.exists():
        time.sleep(0.2)
        continue
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("select name from sqlite_master where type='table' and name in ('admins', 'users')")
        names = {row[0] for row in cur.fetchall()}
        conn.close()
        if {"admins", "users"}.issubset(names):
            break
    except sqlite3.Error:
        pass
    time.sleep(0.2)
else:
    raise SystemExit("timed out waiting for e2e database schema")
PY

go run ./tests/e2e/seed.go

wait "$SERVER_PID"

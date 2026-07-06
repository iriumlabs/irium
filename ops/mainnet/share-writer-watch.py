#!/usr/bin/env python3
"""Share-persistence freshness watchdog (external, independent of the stratum).

Detects the exact silent-loss failure that went unnoticed for six weeks: the
share-DB writer stopping while miners are still connected. Prints SILENT when
healthy, or an ALERT block when the writer looks stalled -- designed to be run
from a cron and relayed like the activation-watch, so a dead writer surfaces in
minutes, not weeks.

Alert condition: miners ARE connected to the stratum port, but the share DB's
last write is older than the staleness threshold (so it is not merely idle).

Env:
  SHARE_DB          default /opt/irium-pool/data/stratum_shares.sqlite3
  STRATUM_PORT      default 3333 (ASIC/strict miner-facing port; 3334 is metrics)
  STALE_SECS        default 900 (15 min)
  MIN_MINERS        default 1 (only alarm if at least this many ESTAB conns)
Exit code: 0 always (the printed line is the signal; matches relay pattern).
"""
import os
import sqlite3
import subprocess
import sys
import time

DB = os.environ.get("SHARE_DB", "/opt/irium-pool/data/stratum_shares.sqlite3")
PORT = os.environ.get("STRATUM_PORT", "3333")
STALE = int(os.environ.get("STALE_SECS", "900"))
MIN_MINERS = int(os.environ.get("MIN_MINERS", "1"))


def established_conns(port):
    try:
        out = subprocess.run(
            ["ss", "-tnH", "state", "established"],
            capture_output=True, text=True, timeout=6,
        ).stdout
        n = 0
        suffix = f":{port}"
        for line in out.splitlines():
            parts = line.split()
            # columns (no header): Recv-Q Send-Q Local:Port Peer:Port
            if len(parts) >= 4 and parts[-2].endswith(suffix):
                n += 1
        return n
    except Exception:
        return -1  # unknown


def last_write_wall(db):
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        row = c.execute(
            "SELECT value FROM accounting_state WHERE key='last_write_wall'"
        ).fetchone()
        if row and row[0]:
            return int(row[0])
        # fallback: newest share ts
        row = c.execute("SELECT max(ts) FROM shares").fetchone()
        return int(row[0]) if row and row[0] else 0
    except Exception as e:
        return -1  # DB unreadable / missing tables


def main():
    now = int(time.time())
    miners = established_conns(PORT)
    lw = last_write_wall(DB)

    # DB missing/unreadable while miners are connected -> alert.
    if lw == -1:
        if miners >= MIN_MINERS or miners == -1:
            print("ALERT: share-writer watchdog: share DB unreadable or missing "
                  f"accounting_state at {DB} (miners_connected={miners}). "
                  "The durable share writer may not be running.")
            return
        print("SILENT")
        return

    age = now - lw
    if miners >= MIN_MINERS and age > STALE:
        mins = age // 60
        print("ALERT: share-writer STALLED: no share persisted for "
              f"{mins} min (age={age}s > {STALE}s) while {miners} miner(s) "
              f"connected on port {PORT}. Last write wall={lw}. "
              f"DB={DB}. The share-DB writer appears to have stopped -- "
              "check the stratum accounting thread / IRIUM_STRATUM_ACCOUNTING_ENABLED.")
        return

    print("SILENT")


if __name__ == "__main__":
    main()

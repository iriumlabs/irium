//! Durable, git-tracked share persistence for the stratum pool.
//!
//! Background: the pool previously had an *untracked* `accounting.rs` (share +
//! block persistence, a PPLNS payout engine, and alerting). It was lost on a
//! rebuild-from-git on 2026-05-23 and share persistence silently stopped for six
//! weeks -- journald share-logging (a separate path) masked the loss. This module
//! restores durable, diff-weighted share persistence and is COMMITTED to git so
//! it cannot be silently dropped again.
//!
//! Design goals:
//!   - Non-blocking: share handling enqueues to a bounded channel and never waits
//!     on disk. A single background thread owns the SQLite connection (WAL mode)
//!     and batches inserts. On a full channel, events are dropped (and counted)
//!     rather than stalling mining.
//!   - Compatible: writes the SAME schema + path the dashboard/stats-proxy read.
//!   - Diff-weighted: the `diff` column carries each share's difficulty (the
//!     correct basis for proportional accounting, not raw counts).
//!   - Observable: maintains `accounting_state` (last_share_ts / last_write_wall)
//!     so an EXTERNAL watchdog can detect a stalled writer within minutes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

use once_cell::sync::OnceCell;

const DEFAULT_DB_PATH: &str = "/opt/irium-pool/data/stratum_shares.sqlite3";
const CHANNEL_CAP: usize = 16_384;
const FLUSH_ROWS: usize = 256;
const FLUSH_INTERVAL_MS: u64 = 1_000;

struct ShareEvent {
    ts: i64,
    worker: String,
    address: String,
    diff: f64,
    accepted: bool,
    reject_reason: Option<String>,
}

static SENDER: OnceCell<SyncSender<ShareEvent>> = OnceCell::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// True when accounting persistence is enabled (`IRIUM_STRATUM_ACCOUNTING_ENABLED=1`).
pub fn enabled() -> bool {
    std::env::var("IRIUM_STRATUM_ACCOUNTING_ENABLED")
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn db_path() -> String {
    std::env::var("IRIUM_STRATUM_SHARE_DB").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string())
}

/// Initialise the share-persistence writer. Idempotent; a no-op when disabled.
/// A failure to open the DB is logged and non-fatal -- mining continues without
/// persistence rather than crashing.
pub fn init() {
    if !enabled() {
        tracing::info!(
            "[accounting] disabled (set IRIUM_STRATUM_ACCOUNTING_ENABLED=1 to persist shares)"
        );
        return;
    }
    if SENDER.get().is_some() {
        return;
    }
    let path = db_path();
    // Create + checkpoint the schema SYNCHRONOUSLY here, so it is durable before
    // the stratum run loop starts. Doing it on the detached writer thread risks a
    // fast early exit tearing the thread down mid-CREATE TABLE (leaving a stale
    // rollback journal + empty db). The writer thread then re-opens (idempotent).
    if let Err(e) = open_db(&path) {
        tracing::error!("[accounting] init db {path} failed: {e}; shares NOT persisted");
        return;
    }
    let (tx, rx) = sync_channel::<ShareEvent>(CHANNEL_CAP);
    let path_for_thread = path.clone();
    match std::thread::Builder::new()
        .name("share-accounting".into())
        .spawn(move || writer_loop(path_for_thread, rx))
    {
        Ok(_) => {
            let _ = SENDER.set(tx);
            tracing::info!("[accounting] enabled db={} channel_cap={}", path, CHANNEL_CAP);
        }
        Err(e) => {
            tracing::error!("[accounting] failed to spawn writer thread: {e}; shares NOT persisted");
        }
    }
}

/// Enqueue a share for durable persistence. Non-blocking: drops (and counts) on a
/// full channel so share handling never stalls on disk I/O. No-op when disabled.
pub fn record_share(
    worker: &str,
    address: &str,
    diff: f64,
    accepted: bool,
    reject_reason: Option<&str>,
) {
    let tx = match SENDER.get() {
        Some(t) => t,
        None => return,
    };
    let ev = ShareEvent {
        ts: unix_now(),
        worker: worker.to_string(),
        address: address.to_string(),
        diff,
        accepted,
        reject_reason: reject_reason.map(|s| s.to_string()),
    };
    if tx.try_send(ev).is_err() {
        let n = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 1000 == 1 {
            tracing::warn!(
                "[accounting] share write channel full; dropped {} shares total (writer stalled?)",
                n
            );
        }
    }
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn writer_loop(path: String, rx: Receiver<ShareEvent>) {
    let conn = match open_db(&path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("[accounting] open db {path} failed: {e}; shares NOT persisted");
            // Drain so senders never block; without a DB we cannot persist.
            while rx.recv().is_ok() {}
            return;
        }
    };
    let mut batch: Vec<ShareEvent> = Vec::with_capacity(FLUSH_ROWS);
    let mut last_flush = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(FLUSH_INTERVAL_MS)) {
            Ok(ev) => {
                batch.push(ev);
                if batch.len() >= FLUSH_ROWS {
                    flush(&conn, &mut batch);
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if !batch.is_empty() {
                    flush(&conn, &mut batch);
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                if !batch.is_empty() {
                    flush(&conn, &mut batch);
                }
                break;
            }
        }
        if !batch.is_empty() && last_flush.elapsed() >= Duration::from_millis(FLUSH_INTERVAL_MS) {
            flush(&conn, &mut batch);
            last_flush = Instant::now();
        }
    }
}

fn open_db(path: &str) -> Result<rusqlite::Connection, rusqlite::Error> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = rusqlite::Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            worker TEXT NOT NULL,
            address TEXT NOT NULL,
            job_id TEXT NOT NULL,
            diff REAL NOT NULL,
            share_hash TEXT NOT NULL,
            accepted INTEGER NOT NULL,
            reject_reason TEXT,
            is_candidate INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_shares_ts ON shares(ts);
         CREATE INDEX IF NOT EXISTS idx_shares_address ON shares(address);
         CREATE TABLE IF NOT EXISTS accounting_state (key TEXT PRIMARY KEY, value TEXT);
         PRAGMA wal_checkpoint(TRUNCATE);",
    )?;
    Ok(conn)
}

fn flush(conn: &rusqlite::Connection, batch: &mut Vec<ShareEvent>) {
    if batch.is_empty() {
        return;
    }
    let mut max_ts: i64 = 0;
    let res = (|| -> Result<(), rusqlite::Error> {
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO shares (ts, worker, address, job_id, diff, share_hash, accepted, reject_reason, is_candidate)
                 VALUES (?1, ?2, ?3, '', ?4, '', ?5, ?6, 0)",
            )?;
            for ev in batch.iter() {
                if ev.ts > max_ts {
                    max_ts = ev.ts;
                }
                stmt.execute(rusqlite::params![
                    ev.ts,
                    ev.worker,
                    ev.address,
                    ev.diff,
                    if ev.accepted { 1 } else { 0 },
                    ev.reject_reason,
                ])?;
            }
        }
        // Watchdog watermarks: newest share ts + wall-clock time of this write.
        tx.execute(
            "INSERT INTO accounting_state (key, value) VALUES ('last_share_ts', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![max_ts.to_string()],
        )?;
        tx.execute(
            "INSERT INTO accounting_state (key, value) VALUES ('last_write_wall', ?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            rusqlite::params![unix_now().to_string()],
        )?;
        tx.commit()?;
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!("[accounting] flush of {} shares failed: {e}", batch.len());
    }
    batch.clear();
}


#[cfg(test)]
mod tests {
    use super::*;

    // Verifies: diff-weighted persistence, accepted vs rejected + reason, the
    // watchdog watermark, and restart-durability (rows survive a fresh open) --
    // the properties that were silently lost for six weeks.
    #[test]
    fn shares_persist_diff_weighted_and_survive_reopen() {
        let path = std::env::temp_dir().join(format!("acct_test_{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap().to_string();
        {
            let conn = open_db(&p).expect("open db");
            let mut batch = vec![
                ShareEvent { ts: 100, worker: "QAAA.r1".into(), address: "QAAA".into(), diff: 16.0, accepted: true, reject_reason: None },
                ShareEvent { ts: 101, worker: "QAAA.r2".into(), address: "QAAA".into(), diff: 32.0, accepted: true, reject_reason: None },
                ShareEvent { ts: 102, worker: "QBBB.r1".into(), address: "QBBB".into(), diff: 8.0, accepted: true, reject_reason: None },
                ShareEvent { ts: 103, worker: "QBBB.r1".into(), address: "QBBB".into(), diff: 0.0, accepted: false, reject_reason: Some("stale".into()) },
            ];
            flush(&conn, &mut batch);
            assert!(batch.is_empty(), "batch drained after flush");
        }
        // Fresh open simulates a stratum restart: everything must persist.
        let conn = rusqlite::Connection::open(&p).unwrap();
        let total: i64 = conn.query_row("SELECT count(*) FROM shares", [], |r| r.get(0)).unwrap();
        assert_eq!(total, 4, "all 4 shares persisted across reopen");
        let qaaa: f64 = conn.query_row("SELECT sum(diff) FROM shares WHERE address='QAAA' AND accepted=1", [], |r| r.get(0)).unwrap();
        assert_eq!(qaaa, 48.0, "QAAA diff-weighted (16+32)");
        let qbbb: f64 = conn.query_row("SELECT sum(diff) FROM shares WHERE address='QBBB' AND accepted=1", [], |r| r.get(0)).unwrap();
        assert_eq!(qbbb, 8.0, "QBBB diff-weighted");
        let rejected: i64 = conn.query_row("SELECT count(*) FROM shares WHERE accepted=0", [], |r| r.get(0)).unwrap();
        assert_eq!(rejected, 1);
        let reason: String = conn.query_row("SELECT reject_reason FROM shares WHERE accepted=0", [], |r| r.get(0)).unwrap();
        assert_eq!(reason, "stale");
        let wm: String = conn.query_row("SELECT value FROM accounting_state WHERE key='last_share_ts'", [], |r| r.get(0)).unwrap();
        assert_eq!(wm, "103", "watchdog watermark = newest share ts");
        let _ = std::fs::remove_file(&path);
        println!("ACCT: 4 shares persisted; QAAA weight=48 QBBB weight=8; 1 rejected(stale); watermark=103; survived reopen");
    }
}

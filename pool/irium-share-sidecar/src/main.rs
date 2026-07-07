//! irium-share-sidecar: external, read-only durable share persistence for the
//! Irium stratum pool.
//!
//! SAFETY MODEL: this process NEVER touches the pool binary. It only:
//!   - reads systemd's journal via `journalctl -u <unit> -o json -f` (the pool
//!     writes to journald; journald is owned by systemd, not the pool process), and
//!   - optionally issues read-only HTTP GETs to the pool's /metrics loopback endpoint
//!     for reconciliation.
//! It writes only to its OWN SQLite database. It does not link against, restart,
//! signal, or share writable state with the pool. It therefore cannot affect
//! coinbase construction, block submission, or consensus in any way.
//!
//! Primary source: the pool's `[sharecheck] ... assigned_diff=` lines carry each
//! share's exact difficulty; the following `[share] accepted worker=` line confirms
//! acceptance. We record a diff-weighted row per accepted share. Rejected shares
//! (`[SHARE_REJECTED] ... reason=`) are recorded with diff 0. A journald cursor is
//! persisted so a sidecar restart resumes without losing shares.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::Connection;

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// journald `-o json` encodes MESSAGE as a byte array whenever the text contains
/// non-printable bytes (the pool colorizes its logs with ANSI escapes, so this is
/// always the case here). Decode either representation to text.
fn message_text(v: &serde_json::Value) -> String {
    match v.get("MESSAGE") {
        Some(serde_json::Value::String(s)) => strip_ansi(s),
        Some(serde_json::Value::Array(a)) => {
            let bytes: Vec<u8> = a.iter().filter_map(|x| x.as_u64().map(|n| n as u8)).collect();
            strip_ansi(&String::from_utf8_lossy(&bytes))
        }
        _ => String::new(),
    }
}

/// Remove ANSI CSI escape sequences (ESC '[' ... letter) so field parsing is clean.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
            }
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Extract `key=value` (value = up to next whitespace) from a log message.
fn field(msg: &str, key: &str) -> Option<String> {
    let i = msg.find(key)? + key.len();
    let rest = &msg[i..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Payout address is the worker name up to the first '.' (rig separator).
fn address_of(worker: &str) -> String {
    worker.split('.').next().unwrap_or(worker).to_string()
}

fn open_db(path: &str) -> Result<Connection> {
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = Connection::open(path)?;
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
         CREATE TABLE IF NOT EXISTS sidecar_reconciliation (
            ts INTEGER NOT NULL,
            pool_accepted_total INTEGER,
            pool_rejected_total INTEGER,
            sidecar_accepted_total INTEGER,
            sidecar_rejected_total INTEGER,
            note TEXT
         );
         PRAGMA wal_checkpoint(TRUNCATE);",
    )?;
    Ok(conn)
}

fn insert_share(
    conn: &Connection,
    ts: i64,
    worker: &str,
    addr: &str,
    diff: f64,
    accepted: bool,
    reason: Option<&str>,
) {
    let r = conn.execute(
        "INSERT INTO shares (ts, worker, address, job_id, diff, share_hash, accepted, reject_reason, is_candidate)
         VALUES (?1, ?2, ?3, '', ?4, '', ?5, ?6, 0)",
        rusqlite::params![ts, worker, addr, diff, if accepted { 1 } else { 0 }, reason],
    );
    if let Err(e) = r {
        eprintln!("[sidecar] insert failed: {e}");
    }
}

fn set_state(conn: &Connection, key: &str, val: &str) {
    let _ = conn.execute(
        "INSERT INTO accounting_state (key,value) VALUES (?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![key, val],
    );
}

fn http_get_json(host: &str, port: u16, path: &str) -> Result<serde_json::Value> {
    let mut s = TcpStream::connect((host, port)).context("connect metrics")?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    let body = buf.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").trim();
    Ok(serde_json::from_str(body)?)
}

/// Cross-check the sidecar's cumulative counts against the pool's /metrics totals.
/// NOTE: the pool's counters reset to 0 when the pool process restarts, while the
/// sidecar total is cumulative across restarts -- so this is a liveness/no-gap
/// sanity check, not an exact equality.
fn reconcile(conn: &Connection, host: &str, port: u16) {
    let (sc_acc, sc_rej): (i64, i64) = conn
        .query_row(
            "SELECT COALESCE(SUM(accepted),0), COUNT(*)-COALESCE(SUM(accepted),0) FROM shares",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap_or((0, 0));
    let (pool_acc, pool_rej, note) = match http_get_json(host, port, "/metrics") {
        Ok(v) => (
            v.get("accepted_shares").and_then(|x| x.as_i64()),
            v.get("rejected_shares").and_then(|x| x.as_i64()),
            "ok".to_string(),
        ),
        Err(e) => (None, None, format!("metrics_unreachable: {e}")),
    };
    let _ = conn.execute(
        "INSERT INTO sidecar_reconciliation
         (ts,pool_accepted_total,pool_rejected_total,sidecar_accepted_total,sidecar_rejected_total,note)
         VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![unix_now(), pool_acc, pool_rej, sc_acc, sc_rej, note],
    );
    eprintln!(
        "[sidecar] reconcile sidecar_accepted={sc_acc} sidecar_rejected={sc_rej} pool_accepted={:?} pool_rejected={:?} ({})",
        pool_acc, pool_rej, note
    );
}

fn main() -> Result<()> {
    let db_path = env_or("SIDECAR_DB", "/opt/irium-pool/data/sidecar_shares.sqlite3");
    let cursor_path = env_or("SIDECAR_CURSOR", "/opt/irium-pool/data/sidecar.cursor");
    let unit = env_or("SIDECAR_UNIT", "irium-stratum.service");
    let metrics_host = env_or("SIDECAR_METRICS_HOST", "127.0.0.1");
    let metrics_port: u16 = env_or("SIDECAR_METRICS_PORT", "3334").parse().unwrap_or(3334);

    let conn = open_db(&db_path).context("open sidecar db")?;
    eprintln!("[sidecar] started db={db_path} unit={unit} metrics={metrics_host}:{metrics_port}");

    let saved_cursor = std::fs::read_to_string(&cursor_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut cmd = Command::new("journalctl");
    cmd.args(["-u", &unit, "-o", "json", "-f", "--no-pager"]);
    match &saved_cursor {
        Some(c) => {
            cmd.arg(format!("--after-cursor={c}"));
            eprintln!("[sidecar] resuming after saved journald cursor");
        }
        None => {
            cmd.args(["-n", "0"]);
            eprintln!("[sidecar] no saved cursor; following from now");
        }
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .context("spawn journalctl")?;
    let stdout = child.stdout.take().context("journalctl stdout")?;

    let (tx, rx) = sync_channel::<String>(8192);
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut diffs: HashMap<String, f64> = HashMap::new();
    let mut last_cursor = String::new();
    let mut last_cursor_save = Instant::now();
    let mut last_reconcile = Instant::now();

    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => {
                let v: serde_json::Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(c) = v.get("__CURSOR").and_then(|c| c.as_str()) {
                    last_cursor = c.to_string();
                }
                let ts = v
                    .get("__REALTIME_TIMESTAMP")
                    .and_then(|t| t.as_str())
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|us| us / 1_000_000)
                    .unwrap_or_else(unix_now);
                let msg = message_text(&v);
                let msg = msg.as_str();

                if msg.contains("[sharecheck]") {
                    if let (Some(w), Some(d)) = (field(msg, "worker="), field(msg, "assigned_diff=")) {
                        if let Ok(dv) = d.parse::<f64>() {
                            diffs.insert(w, dv);
                        }
                    }
                } else if msg.contains("[share] accepted") {
                    if let Some(w) = field(msg, "worker=") {
                        let d = *diffs.get(&w).unwrap_or(&0.0);
                        let a = address_of(&w);
                        insert_share(&conn, ts, &w, &a, d, true, None);
                        set_state(&conn, "last_share_ts", &ts.to_string());
                        set_state(&conn, "last_write_wall", &unix_now().to_string());
                    }
                } else if msg.contains("[SHARE_REJECTED]") {
                    if let Some(w) = field(msg, "worker=") {
                        let reason = field(msg, "reason=").unwrap_or_else(|| "unknown".to_string());
                        let a = address_of(&w);
                        insert_share(&conn, ts, &w, &a, 0.0, false, Some(&reason));
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[sidecar] journalctl stream ended; exiting for systemd restart (resumes from cursor)");
                break;
            }
        }

        if last_cursor_save.elapsed() >= Duration::from_secs(5) && !last_cursor.is_empty() {
            let _ = std::fs::write(&cursor_path, &last_cursor);
            last_cursor_save = Instant::now();
        }
        if last_reconcile.elapsed() >= Duration::from_secs(60) {
            reconcile(&conn, &metrics_host, metrics_port);
            last_reconcile = Instant::now();
        }
    }

    if !last_cursor.is_empty() {
        let _ = std::fs::write(&cursor_path, &last_cursor);
    }
    let _ = child.wait();
    Ok(())
}

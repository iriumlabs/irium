//! v1.9.66 — Bitcoin/LTC P2P wire-format primitives.
//!
//! All three chains speak the same wire protocol with different magic
//! bytes and ports. This module owns the shared format (message
//! framing, varint, sha256d checksum, version + getheaders + headers
//! payloads, async TCP read/write with timeout). Each per-chain module
//! (btc_p2p, ltc_p2p) supplies only its magic + port +
//! DNS seeds and calls into this module.
//!
//! Issue #60 — replaces the external HTTP block-explorer APIs that
//! were the only source of BTC/LTC headers before v1.9.66.

use std::io;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Per-message read deadline. Bitcoin Core sends a ping every ~2 min; a
/// 10s read deadline is well below that and gives us fast failover when
/// a peer is slow or dead.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Protocol version we advertise. 70015 was current circa Bitcoin Core
/// 0.13 (2016) and is still accepted by every Bitcoin / LTC node
/// in the wild. Higher versions add feature negotiation we do not use.
pub const PROTOCOL_VERSION: i32 = 70015;

/// User agent string. Bitcoin convention is `/Name:Version/` with
/// leading and trailing slash so multi-implementation chains can stack
/// their own UAs. Kept short to leave room under the 256-byte ceiling
/// some legacy peers enforce.
pub const USER_AGENT: &str = "/iriumd:1.9.66/";

/// Max payload size we will allocate from a single message header.
/// Standard Bitcoin caps individual P2P messages at 32 MiB; reject
/// anything above so a malicious peer cannot OOM us by claiming a huge
/// payload then never sending the body.
pub const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

/// Bitcoin double-SHA256: `sha256(sha256(data))`. Used for the 4-byte
/// message checksum (first 4 bytes of the result) and for block-hash
/// derivation in some peer chains.
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(bytes);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// Bitcoin compact-size integer (`var_int`). 1, 3, 5, or 9 bytes
/// depending on magnitude.
pub fn put_varint(v: u64, out: &mut Vec<u8>) {
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else if v <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&v.to_le_bytes());
    }
}

/// Read a compact-size integer from the front of a byte slice. Returns
/// the value and the number of bytes consumed. Errors when the slice is
/// truncated before the full encoding could be read.
pub fn read_varint_slice(s: &[u8]) -> Result<(u64, usize), String> {
    if s.is_empty() {
        return Err("varint: empty input".to_string());
    }
    match s[0] {
        0xff => {
            if s.len() < 9 {
                return Err("varint: truncated 0xff (need 9 bytes)".to_string());
            }
            Ok((u64::from_le_bytes(s[1..9].try_into().unwrap()), 9))
        }
        0xfe => {
            if s.len() < 5 {
                return Err("varint: truncated 0xfe (need 5 bytes)".to_string());
            }
            Ok((u32::from_le_bytes(s[1..5].try_into().unwrap()) as u64, 5))
        }
        0xfd => {
            if s.len() < 3 {
                return Err("varint: truncated 0xfd (need 3 bytes)".to_string());
            }
            Ok((u16::from_le_bytes(s[1..3].try_into().unwrap()) as u64, 3))
        }
        n => Ok((n as u64, 1)),
    }
}

/// One parsed P2P message: the command name (e.g. "version", "verack",
/// "headers") and the raw payload bytes. The 24-byte wire header is
/// consumed and discarded by `read_message`.
pub struct P2PMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

/// Build a full P2P message: 24-byte header + payload.
///
/// Header layout: `magic(4 LE) | command(12, NUL-padded) | length(4 LE)
/// | checksum(4)`. Checksum is the first 4 bytes of `sha256d(payload)`.
pub fn make_message(magic: u32, command: &str, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(24 + payload.len());
    msg.extend_from_slice(&magic.to_le_bytes());
    let mut cmd_buf = [0u8; 12];
    let cmd_bytes = command.as_bytes();
    let n = cmd_bytes.len().min(12);
    cmd_buf[..n].copy_from_slice(&cmd_bytes[..n]);
    msg.extend_from_slice(&cmd_buf);
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let cs = sha256d(payload);
    msg.extend_from_slice(&cs[..4]);
    msg.extend_from_slice(payload);
    msg
}

/// Write a full P2P message to the stream. v1.9.82 of issue #68:
/// always flush after write_all. tokio's `AsyncWriteExt::write_all`
/// can leave bytes in the internal buffer; small messages like a
/// 37-byte `getdata` for one block hash got delayed long enough that
/// peers timed us out or dropped the request before transmission.
/// Bitcoin Core's reference uses TCP with `MSG_DONTWAIT` plus
/// equivalent flushing; this matches that behavior on the tokio side.
pub async fn write_message(
    stream: &mut TcpStream,
    magic: u32,
    command: &str,
    payload: &[u8],
) -> io::Result<()> {
    let msg = make_message(magic, command, payload);
    stream.write_all(&msg).await?;
    stream.flush().await
}

/// Read one full P2P message off the stream, with per-read timeout.
/// Validates magic + checksum; errors fast on anything malformed so
/// the caller can rotate to a new peer instead of hanging.
pub async fn read_message(
    stream: &mut TcpStream,
    expected_magic: u32,
) -> io::Result<P2PMessage> {
    let mut header = [0u8; 24];
    timeout(READ_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read header timeout"))??;

    let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    if magic != expected_magic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("magic mismatch: got 0x{magic:08x}, expected 0x{expected_magic:08x}"),
        ));
    }

    let cmd_bytes: [u8; 12] = header[4..16].try_into().unwrap();
    let cmd_end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(12);
    let command = String::from_utf8_lossy(&cmd_bytes[..cmd_end]).to_string();

    let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("payload too large: {payload_len} > {MAX_PAYLOAD}"),
        ));
    }

    let expected_cs: [u8; 4] = header[20..24].try_into().unwrap();
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        timeout(READ_TIMEOUT, stream.read_exact(&mut payload))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "read payload timeout"))??;
        let actual_cs = sha256d(&payload);
        if actual_cs[..4] != expected_cs {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "checksum mismatch for command {command:?}: \
                     expected {expected_cs:02x?}, got {:02x?}",
                    &actual_cs[..4]
                ),
            ));
        }
    } else {
        // Empty payload commands (verack, sendaddrv2, etc.). Their
        // canonical checksum is sha256d(&[])[..4] = 0x5d, 0xf6, 0xe0, 0xe2.
        let empty_cs = sha256d(&[]);
        if expected_cs != empty_cs[..4] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("empty payload bad checksum for {command:?}"),
            ));
        }
    }

    Ok(P2PMessage { command, payload })
}

/// Build the version-message payload our handshake sends. We claim
/// `services = 0` (we serve nothing — we are an SPV header-only
/// client). `relay = 0` tells the peer we do not want any transaction
/// inv announcements: this dramatically cuts incoming chatter so the
/// post-handshake read loop stays focused on the headers we asked for.
pub fn build_version_payload(start_height: i32, port: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(110);
    p.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    p.extend_from_slice(&0u64.to_le_bytes()); // services = 0
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    p.extend_from_slice(&now.to_le_bytes()); // timestamp (i64 LE)
    push_netaddr(&mut p, port); // addr_recv
    push_netaddr(&mut p, port); // addr_from
    p.extend_from_slice(&rand_nonce().to_le_bytes()); // nonce
    let ua = USER_AGENT.as_bytes();
    put_varint(ua.len() as u64, &mut p);
    p.extend_from_slice(ua);
    p.extend_from_slice(&start_height.to_le_bytes());
    p.push(0); // relay = false (we do not want tx inv)
    p
}

/// 26-byte NetAddr (services + ipv4-mapped-ipv6 + port). Bitcoin uses
/// the same byte layout for both `addr_recv` and `addr_from` in the
/// version message. We zero the IP (peers do not require accuracy from
/// pre-verack version messages) and use the chain's standard P2P port.
fn push_netaddr(out: &mut Vec<u8>, port: u16) {
    out.extend_from_slice(&0u64.to_le_bytes()); // services
    out.extend_from_slice(&[0u8; 10]); // ipv4-mapped ipv6 prefix
    out.extend_from_slice(&[0xff, 0xff]);
    out.extend_from_slice(&[0u8; 4]); // ip = 0.0.0.0
    out.extend_from_slice(&port.to_be_bytes()); // port is BIG-ENDIAN here
}

/// Per-connection nonce. Bitcoin uses this to detect connecting back
/// to oneself (peer sees its own nonce echoed). We do not host inbound
/// so collision is harmless; any value works. PID-XOR-nanos is fine and
/// avoids pulling in `rand`.
fn rand_nonce() -> u64 {
    let pid = std::process::id() as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    pid.wrapping_mul(0x100_0000_0001).wrapping_add(nanos) ^ 0xa5a5_a5a5_a5a5_a5a5
}

/// Build a getheaders payload. `locator` is the list of hashes we know,
/// most-recent first; the peer walks it and starts streaming from the
/// first hash it also knows. `hash_stop = [0u8; 32]` means "send up to
/// 2000 headers", which is what we always want.
/// PR-6 of issue #68: INV type for full blocks (Bitcoin protocol).
pub const MSG_BLOCK: u32 = 2;

/// PR-6 of issue #68: peer-payload size cap for a single `block` message.
/// 4 MB gives headroom for SegWit-style parent coinbases without inviting OOM.
pub const MAX_BLOCK_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// PR-6 of issue #68: build a `getdata` payload for one or more
/// inventory entries. Standard Bitcoin format:
///   varint(count) || (4-byte inv_type LE || 32-byte hash) * count
pub fn build_getdata_payload(invs: &[(u32, [u8; 32])]) -> Vec<u8> {
    let mut p = Vec::with_capacity(9 + invs.len() * 36);
    put_varint(invs.len() as u64, &mut p);
    for (inv_type, hash) in invs {
        p.extend_from_slice(&inv_type.to_le_bytes());
        p.extend_from_slice(hash);
    }
    p
}

pub fn build_getheaders_payload(locator: &[[u8; 32]], hash_stop: [u8; 32]) -> Vec<u8> {
    let mut p = Vec::with_capacity(4 + 9 + locator.len() * 32 + 32);
    p.extend_from_slice(&(PROTOCOL_VERSION as u32).to_le_bytes());
    put_varint(locator.len() as u64, &mut p);
    for h in locator {
        p.extend_from_slice(h);
    }
    p.extend_from_slice(&hash_stop);
    p
}

/// Parse a headers payload into raw 80-byte headers. The wire format
/// for each entry is the 80-byte header followed by a varint tx_count
/// that is always 0 in a getheaders response — we read and discard it.
pub fn parse_headers_payload(
    payload: &[u8],
) -> Result<Vec<[u8; 80]>, String> {
    let (count, used) = read_varint_slice(payload)?;
    let mut cur = used;
    let mut out: Vec<[u8; 80]> = Vec::with_capacity(count as usize);
    for i in 0..count {
        if cur + 80 > payload.len() {
            return Err(format!(
                "headers: truncated at entry {i}/{count} (need 80 bytes at offset {cur})"
            ));
        }
        let mut h = [0u8; 80];
        h.copy_from_slice(&payload[cur..cur + 80]);
        cur += 80;
        out.push(h);
        let (_tx_count, used) = read_varint_slice(&payload[cur..])?;
        cur += used;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_known_vector() {
        // sha256d("hello") = 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
        let h = sha256d(b"hello");
        assert_eq!(
            hex::encode(h),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn varint_round_trip() {
        for v in [
            0u64,
            1,
            0xfc,
            0xfd,
            0xff,
            0x100,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            put_varint(v, &mut buf);
            let (decoded, used) = read_varint_slice(&buf).expect("decode");
            assert_eq!(decoded, v, "value {v}");
            assert_eq!(used, buf.len(), "consumed bytes for {v}");
        }
    }

    #[test]
    fn message_header_round_trip() {
        let magic = 0xC0C0C0C0u32;
        let payload = b"hello-world";
        let msg = make_message(magic, "ping", payload);
        // 24-byte header + 11-byte payload = 35 bytes total
        assert_eq!(msg.len(), 24 + payload.len());
        assert_eq!(&msg[..4], &magic.to_le_bytes());
        // command is "ping" then 8 NULs
        assert_eq!(&msg[4..8], b"ping");
        assert_eq!(&msg[8..16], &[0u8; 8]);
        // payload length LE
        assert_eq!(
            u32::from_le_bytes(msg[16..20].try_into().unwrap()),
            payload.len() as u32
        );
        // checksum is sha256d(payload)[..4]
        let expected_cs = sha256d(payload);
        assert_eq!(&msg[20..24], &expected_cs[..4]);
        // payload bytes follow
        assert_eq!(&msg[24..], payload);
    }

    #[test]
    fn build_version_payload_minimum_size() {
        // Bitcoin's minimum version-message payload is 86 bytes
        // (4+8+8+26+26+8+var_int(0)+4+1 = 86). Adding our user agent
        // bumps it past that. The exact value is fine to drift but
        // must always exceed Bitcoin's MIN_VERSION_PAYLOAD = 86.
        let p = build_version_payload(0, 22556);
        assert!(p.len() >= 86, "version payload {} bytes < 86", p.len());
        // Protocol version is at offset 0
        assert_eq!(&p[..4], &PROTOCOL_VERSION.to_le_bytes());
        // services must be zero (we are an SPV client)
        assert_eq!(&p[4..12], &[0u8; 8]);
        // relay byte (last byte) must be 0
        assert_eq!(*p.last().unwrap(), 0);
    }

    #[test]
    fn parse_headers_payload_round_trip() {
        // Construct a synthetic 2-entry headers payload.
        let mut payload = Vec::new();
        put_varint(2, &mut payload);
        let h1 = [0x11u8; 80];
        let h2 = [0x22u8; 80];
        payload.extend_from_slice(&h1);
        put_varint(0, &mut payload); // tx_count = 0
        payload.extend_from_slice(&h2);
        put_varint(0, &mut payload);

        let parsed = parse_headers_payload(&payload).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], h1);
        assert_eq!(parsed[1], h2);
    }

    #[test]
    fn parse_headers_payload_truncated_errors() {
        // Claim 3 headers but only supply 1's worth of bytes.
        let mut payload = Vec::new();
        put_varint(3, &mut payload);
        payload.extend_from_slice(&[0xaau8; 80]);
        put_varint(0, &mut payload);
        // Now the 2nd entry's bytes are missing.
        let result = parse_headers_payload(&payload);
        assert!(result.is_err(), "expected truncation error");
    }

    #[test]
    fn pr6_build_getdata_payload_single_inv() {
        let invs = vec![(MSG_BLOCK, [0x11u8; 32])];
        let p = build_getdata_payload(&invs);
        // varint(1) = 1 byte; 1 inv = 4 + 32 = 36; total = 37
        assert_eq!(p.len(), 37);
        assert_eq!(p[0], 1); // varint count = 1
        assert_eq!(&p[1..5], &MSG_BLOCK.to_le_bytes());
        assert_eq!(&p[5..37], &[0x11u8; 32]);
    }

    #[test]
    fn pr6_build_getdata_payload_multi_inv() {
        let invs: Vec<(u32, [u8; 32])> = (0..3u32).map(|i| (MSG_BLOCK, [i as u8; 32])).collect();
        let p = build_getdata_payload(&invs);
        // varint(3) = 1 byte; 3 invs = 3 * 36 = 108; total = 109
        assert_eq!(p.len(), 109);
        assert_eq!(p[0], 3);
    }
}

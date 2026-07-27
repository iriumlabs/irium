//! NAT-PMP (RFC 6886) port mapping — dependency-free NAT traversal for P2P reachability.
//!
//! WHY THIS EXISTS. A node behind a home router can dial out but nobody can dial IN, so it
//! can never serve as a bootstrap peer no matter how long it runs. Measured on mainnet
//! 2026-07-27: of six independent nodes on the network, only two accepted inbound
//! connections. That is why the compiled-in seed list still has to name the project's own
//! hosts — there is almost nothing else dialable to name.
//!
//! Asking the router to forward the P2P port turns an ordinary follower into a dialable
//! peer, so the seed pool grows from the network itself instead of from a curated list.
//! The conversation is with the user's OWN router over UDP on the local link: no DNS, no
//! external service, no third party — which is the only kind of help Irium accepts.
//!
//! Deliberately implemented by hand rather than pulling in a UPnP/IGD crate: NAT-PMP is a
//! small binary protocol, and this is a consensus-critical binary where a new dependency is
//! a bigger cost than a hundred lines of parsing. The wire codec below is pure and unit
//! tested; only `request_mapping` touches the network.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// NAT-PMP always listens on this UDP port on the gateway (RFC 6886 §3).
pub const NAT_PMP_PORT: u16 = 5351;
/// Requested lifetime for a mapping. Renewed well before it lapses.
pub const DEFAULT_MAPPING_LIFETIME_SECS: u32 = 3600;

const OP_MAP_TCP: u8 = 2;
const RESP_FLAG: u8 = 128;

/// A mapping the gateway confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime_secs: u32,
}

/// Build a NAT-PMP TCP mapping request (RFC 6886 §3.3).
///
/// Layout: version(1)=0, opcode(1)=2, reserved(2)=0, internal(2), suggested external(2),
/// lifetime(4) — all big-endian.
pub fn encode_map_request(internal_port: u16, suggested_external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = 0; // version
    b[1] = OP_MAP_TCP;
    // b[2..4] reserved, already zero
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// Parse a NAT-PMP mapping response (RFC 6886 §3.3).
///
/// Layout: version(1), opcode(1)=130, result(2), epoch(4), internal(2), external(2),
/// lifetime(4). Fails closed on anything unexpected — a malformed or error reply must not
/// be mistaken for a working mapping, or the node would advertise an address nobody can
/// reach and poison the peer set.
pub fn decode_map_response(buf: &[u8], expect_internal: u16) -> Result<PortMapping, String> {
    if buf.len() < 16 {
        return Err(format!("nat-pmp: short response ({} bytes)", buf.len()));
    }
    if buf[0] != 0 {
        return Err(format!("nat-pmp: unsupported version {}", buf[0]));
    }
    if buf[1] != OP_MAP_TCP + RESP_FLAG {
        return Err(format!("nat-pmp: unexpected opcode {}", buf[1]));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(format!("nat-pmp: gateway result code {result}"));
    }
    let internal = u16::from_be_bytes([buf[8], buf[9]]);
    if internal != expect_internal {
        return Err(format!(
            "nat-pmp: response for port {internal}, expected {expect_internal}"
        ));
    }
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    if external == 0 {
        return Err("nat-pmp: gateway returned external port 0".to_string());
    }
    let lifetime = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if lifetime == 0 {
        return Err("nat-pmp: gateway returned zero lifetime".to_string());
    }
    Ok(PortMapping {
        internal_port: internal,
        external_port: external,
        lifetime_secs: lifetime,
    })
}

/// Build a NAT-PMP external-address request (RFC 6886 §3.2): version(1)=0, opcode(1)=0.
///
/// The mapping response carries the external PORT but not the external ADDRESS, so this is
/// the other half of building a dialable `host:port` to advertise.
pub fn encode_external_address_request() -> [u8; 2] {
    [0, 0]
}

/// Parse a NAT-PMP external-address response (RFC 6886 §3.2): version(1), opcode(1)=128,
/// result(2), epoch(4), external IPv4(4).
///
/// Rejects addresses that are not publicly dialable. A router that hands back an RFC1918
/// address is itself behind another NAT (carrier-grade NAT), and advertising that address
/// would send every peer to a dead end.
pub fn decode_external_address_response(buf: &[u8]) -> Result<Ipv4Addr, String> {
    if buf.len() < 12 {
        return Err(format!("nat-pmp: short address response ({} bytes)", buf.len()));
    }
    if buf[0] != 0 {
        return Err(format!("nat-pmp: unsupported version {}", buf[0]));
    }
    if buf[1] != RESP_FLAG {
        return Err(format!("nat-pmp: unexpected opcode {}", buf[1]));
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        return Err(format!("nat-pmp: gateway result code {result}"));
    }
    let ip = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
    if !is_publicly_dialable(&ip) {
        return Err(format!("nat-pmp: gateway reported non-public address {ip} (CGNAT?)"));
    }
    Ok(ip)
}

/// Whether an address is worth telling other peers about.
pub fn is_publicly_dialable(ip: &Ipv4Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 100.64.0.0/10 — carrier-grade NAT, reachable by nobody outside the carrier.
        || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1])))
}

/// Ask the gateway for our public IPv4. Best-effort, same contract as `request_mapping`.
pub fn request_external_address(gateway: Ipv4Addr, timeout: Duration) -> Result<Ipv4Addr, String> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("nat-pmp: bind failed: {e}"))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("nat-pmp: set timeout failed: {e}"))?;
    sock.send_to(
        &encode_external_address_request(),
        SocketAddrV4::new(gateway, NAT_PMP_PORT),
    )
    .map_err(|e| format!("nat-pmp: send failed: {e}"))?;
    let mut buf = [0u8; 32];
    let (n, from) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("nat-pmp: no reply from gateway: {e}"))?;
    match from {
        std::net::SocketAddr::V4(v4) if *v4.ip() == gateway => {}
        other => return Err(format!("nat-pmp: reply from unexpected source {other}")),
    }
    decode_external_address_response(&buf[..n])
}

/// Parse the IPv4 default gateway out of `/proc/net/route` (Linux).
///
/// Kept separate from file IO so the hex/endianness handling is testable: the Gateway
/// column is little-endian hex, which is easy to get backwards.
pub fn parse_default_gateway_v4(proc_net_route: &str) -> Option<Ipv4Addr> {
    for line in proc_net_route.lines().skip(1) {
        let mut f = line.split_whitespace();
        let _iface = f.next()?;
        let dest = f.next()?;
        let gw = f.next()?;
        // Default route only.
        if dest != "00000000" {
            continue;
        }
        let raw = u32::from_str_radix(gw, 16).ok()?;
        // /proc stores the address little-endian relative to network byte order.
        let ip = Ipv4Addr::from(raw.swap_bytes());
        if ip.is_unspecified() {
            continue;
        }
        return Some(ip);
    }
    None
}

/// Read the host's IPv4 default gateway, or `None` when it cannot be determined
/// (non-Linux, unusual routing, container without a default route).
pub fn default_gateway_v4() -> Option<Ipv4Addr> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_gateway_v4(&contents)
}

/// Ask the gateway to forward `internal_port` (TCP) to us.
///
/// Bounded and best-effort: one request, short timeout, no retries. A router that does not
/// speak NAT-PMP simply never answers, and the node carries on exactly as before — port
/// mapping is an optimisation, never a requirement for participating.
pub fn request_mapping(
    gateway: Ipv4Addr,
    internal_port: u16,
    lifetime_secs: u32,
    timeout: Duration,
) -> Result<PortMapping, String> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("nat-pmp: bind failed: {e}"))?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("nat-pmp: set timeout failed: {e}"))?;
    let req = encode_map_request(internal_port, internal_port, lifetime_secs);
    sock.send_to(&req, SocketAddrV4::new(gateway, NAT_PMP_PORT))
        .map_err(|e| format!("nat-pmp: send failed: {e}"))?;
    let mut buf = [0u8; 32];
    let (n, from) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("nat-pmp: no reply from gateway: {e}"))?;
    // Only trust the gateway we asked.
    match from {
        std::net::SocketAddr::V4(v4) if *v4.ip() == gateway => {}
        other => return Err(format!("nat-pmp: reply from unexpected source {other}")),
    }
    decode_map_response(&buf[..n], internal_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_request_matches_rfc6886_layout() {
        let req = encode_map_request(38291, 38291, 3600);
        assert_eq!(req[0], 0, "version 0");
        assert_eq!(req[1], 2, "opcode 2 = map TCP");
        assert_eq!(&req[2..4], &[0, 0], "reserved must be zero");
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 38291, "internal port");
        assert_eq!(u16::from_be_bytes([req[6], req[7]]), 38291, "suggested external");
        assert_eq!(
            u32::from_be_bytes([req[8], req[9], req[10], req[11]]),
            3600,
            "lifetime"
        );
    }

    fn ok_response(internal: u16, external: u16, lifetime: u32) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[1] = OP_MAP_TCP + RESP_FLAG;
        b[8..10].copy_from_slice(&internal.to_be_bytes());
        b[10..12].copy_from_slice(&external.to_be_bytes());
        b[12..16].copy_from_slice(&lifetime.to_be_bytes());
        b
    }

    #[test]
    fn decodes_a_successful_mapping() {
        let m = decode_map_response(&ok_response(38291, 40000, 3600), 38291).unwrap();
        assert_eq!(
            m,
            PortMapping {
                internal_port: 38291,
                external_port: 40000,
                lifetime_secs: 3600
            }
        );
    }

    /// A bad reply must never be read as a working mapping: the node would advertise an
    /// address nobody can dial, which is worse than not advertising at all.
    #[test]
    fn rejects_every_malformed_or_error_response() {
        // truncated
        assert!(decode_map_response(&[0u8; 8], 38291).is_err());
        // wrong version
        let mut r = ok_response(38291, 40000, 3600);
        r[0] = 1;
        assert!(decode_map_response(&r, 38291).is_err(), "wrong version");
        // wrong opcode
        let mut r = ok_response(38291, 40000, 3600);
        r[1] = 129;
        assert!(decode_map_response(&r, 38291).is_err(), "wrong opcode");
        // gateway error result
        let mut r = ok_response(38291, 40000, 3600);
        r[2..4].copy_from_slice(&2u16.to_be_bytes());
        assert!(decode_map_response(&r, 38291).is_err(), "error result code");
        // mapping for a port we did not ask about
        assert!(
            decode_map_response(&ok_response(1234, 40000, 3600), 38291).is_err(),
            "port mismatch"
        );
        // zero external port / zero lifetime are refusals, not mappings
        assert!(decode_map_response(&ok_response(38291, 0, 3600), 38291).is_err());
        assert!(decode_map_response(&ok_response(38291, 40000, 0), 38291).is_err());
    }

    fn addr_response(ip: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0u8; 12];
        b[1] = RESP_FLAG;
        b[8..12].copy_from_slice(&ip);
        b
    }

    #[test]
    fn decodes_a_public_external_address() {
        assert_eq!(
            decode_external_address_response(&addr_response([203, 0, 113, 5])).ok(),
            None,
            "documentation range is not dialable"
        );
        assert_eq!(
            decode_external_address_response(&addr_response([9, 9, 9, 9])).unwrap(),
            Ipv4Addr::new(9, 9, 9, 9)
        );
    }

    /// A router behind carrier-grade NAT reports an address no peer can reach. Advertising
    /// it would send the whole network to a dead end, so it must be refused outright.
    #[test]
    fn refuses_non_public_external_addresses_including_cgnat() {
        for bad in [
            [192, 168, 1, 1],
            [10, 0, 0, 1],
            [127, 0, 0, 1],
            [169, 254, 0, 1],
            [0, 0, 0, 0],
            [100, 64, 0, 1],   // CGNAT 100.64.0.0/10
            [100, 127, 255, 1] // upper edge of CGNAT
        ] {
            assert!(
                decode_external_address_response(&addr_response(bad)).is_err(),
                "must refuse non-public external address {bad:?}"
            );
        }
        // Just outside CGNAT is fine.
        assert!(decode_external_address_response(&addr_response([100, 128, 0, 1])).is_ok());
        assert!(decode_external_address_response(&addr_response([100, 63, 255, 1])).is_ok());
    }

    #[test]
    fn parses_the_default_gateway_with_correct_endianness() {
        // Gateway column is little-endian hex: 0100A8C0 => 192.168.0.1
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            parse_default_gateway_v4(table),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
    }

    #[test]
    fn ignores_non_default_routes_and_null_gateways() {
        let only_subnet = "Iface\tDestination\tGateway\n\
                           eth0\t0000A8C0\t0100A8C0\n";
        assert_eq!(parse_default_gateway_v4(only_subnet), None, "not a default route");

        let null_gw = "Iface\tDestination\tGateway\n\
                       eth0\t00000000\t00000000\n";
        assert_eq!(parse_default_gateway_v4(null_gw), None, "0.0.0.0 is not a gateway");
    }
}

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Protocol version for Irium P2P.
pub const PROTOCOL_VERSION: u8 = 1;
/// 32 MB max message size.
pub const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;
/// 4 MB max block size.
pub const MAX_BLOCK_SIZE: u32 = 4 * 1024 * 1024;
/// Max headers per getheaders request.
pub const MAX_HEADERS_PER_REQUEST: u32 = 2000;
/// Max blocks per getblocks request.
pub const MAX_BLOCKS_PER_REQUEST: u32 = 512;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Forward-compat sentinel for message-type bytes the local build does
    /// not know about. Receivers replace the unknown byte with this variant
    /// during `Message::deserialize` so the read loop can silently drop the
    /// message instead of disconnecting the peer. This is what makes adding
    /// new MessageType variants (e.g., OfferTakeNotification = 20) safe to
    /// roll out across a mixed-version network.
    Unknown = 0,
    Handshake = 1,
    Ping = 2,
    Pong = 3,
    GetPeers = 4,
    Peers = 5,
    GetBlocks = 6,
    Block = 7,
    GetHeaders = 8,
    Headers = 9,
    Tx = 10,
    Mempool = 11,
    SybilChallenge = 12,
    SybilProof = 13,
    RelayAddress = 14,
    Inv = 15,
    GetData = 16,
    UptimeChallenge = 17,
    UptimeProof = 18,
    ProofGossip = 19,
    /// Buyer-broadcast notification that a remote offer has been taken.
    /// Payload: UTF-8 JSON with offer_id, buyer_address, agreement_id,
    /// agreement_hash, taken_at, seller_pubkey. The seller's iriumd uses
    /// the payload to flip the matching local offer file from "open" to
    /// "taken" so /offers/feed stops advertising it to other peers. See
    /// the `OfferTakeNotificationPayload` struct below for the exact
    /// wire format and the iriumd handler for receive-side validation.
    ///
    /// TODO(security follow-up): no cryptographic signature is required
    /// today — structural validation (matching seller_pubkey + offer_id
    /// + status=="open" on receiver) is the only check. Add an ed25519
    /// signature over the payload by the buyer's wallet key in a later
    /// iteration so a third party can't spoof-take an offer to grief
    /// the seller.
    OfferTakeNotification = 20,
    DisputeRaisedNotification = 21,
    DisputeEvidenceNotification = 22,
    DisputeResolvedNotification = 23,
    DisputeEscalatedNotification = 24,
    /// Seller-broadcast announcement of a new (or republished) offer.
    /// Payload: UTF-8 JSON of the full offer object (same shape that
    /// `/offers/feed` exposes — id, seller_address, amount_sats,
    /// description, payment_method, payment_instructions, status="open",
    /// created_at, timeout_height, seller_pubkey, …). Receivers write
    /// the JSON to ~/.irium/offers/<id>.json so `/offers/feed` serves it
    /// locally, then re-broadcast to every peer EXCEPT the source so
    /// the offer propagates via gossip flood. Dedup is per-receiver via
    /// a bounded LRU of recently-seen offer IDs (see p2p.rs).
    ///
    /// Replaces the legacy `IRIUM_MARKETPLACE_FEED_URL` env-var-based
    /// discovery for new installs. Old peers without this variant ignore
    /// the message via the `Unknown = 0` sentinel; mixed-version networks
    /// degrade gracefully (offers only propagate among upgraded peers).
    ///
    /// TODO(security follow-up): no cryptographic signature is required
    /// today — same gap as OfferTakeNotification. Add an ed25519
    /// signature over the payload by the seller's wallet key so a third
    /// party can't flood the network with fake offers attributed to
    /// other sellers.
    OfferBroadcast = 25,
    Disconnect = 99,
}

impl TryFrom<u8> for MessageType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use MessageType::*;
        let mt = match value {
            0 => Unknown,
            1 => Handshake,
            2 => Ping,
            3 => Pong,
            4 => GetPeers,
            5 => Peers,
            6 => GetBlocks,
            7 => Block,
            8 => GetHeaders,
            9 => Headers,
            10 => Tx,
            11 => Mempool,
            12 => SybilChallenge,
            13 => SybilProof,
            14 => RelayAddress,
            15 => Inv,
            16 => GetData,
            17 => UptimeChallenge,
            18 => UptimeProof,
            19 => ProofGossip,
            20 => OfferTakeNotification,
            21 => DisputeRaisedNotification,
            22 => DisputeEvidenceNotification,
            23 => DisputeResolvedNotification,
            24 => DisputeEscalatedNotification,
            25 => OfferBroadcast,
            99 => Disconnect,
            other => return Err(format!("Unknown message type: {}", other)),
        };
        Ok(mt)
    }
}

/// Base P2P message: [version:1][type:1][length:4][payload]
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.payload.len());
        out.push(PROTOCOL_VERSION);
        out.push(self.msg_type as u8);
        let len = self.payload.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 6 {
            return Err("Message too short".to_string());
        }
        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(format!("Unsupported protocol version: {}", version));
        }
        let msg_type_byte = data[1];
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[2..6]);
        let length = u32::from_be_bytes(len_bytes);
        if length > MAX_MESSAGE_SIZE {
            return Err("Message too large".to_string());
        }
        if data.len() < 6 + length as usize {
            return Err("Incomplete message".to_string());
        }
        let payload = data[6..6 + length as usize].to_vec();
        // Forward-compat: an unknown msg_type byte is mapped to
        // MessageType::Unknown rather than propagating an error up to the
        // read loop (where it would close the peer connection). All
        // receive-side match blocks have a `_ => {}` catch-all, so an
        // Unknown message is silently dropped while the peer stays
        // connected. Lets newer peers introduce additional MessageType
        // variants without forcing a coordinated upgrade.
        let msg_type = MessageType::try_from(msg_type_byte)
            .unwrap_or(MessageType::Unknown);
        Ok(Message { msg_type, payload })
    }
}

/// Handshake message with minimal fields (JSON payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    pub version: u32,
    pub agent: String,
    pub height: u64,
    pub timestamp: i64,
    pub port: u16,
    pub checkpoint_height: Option<u64>,
    pub checkpoint_hash: Option<String>,
    #[serde(default)]
    pub relay_address: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub tip_hash: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
/// Optional URL of this node's marketplace offer feed (e.g. http://host:port/offers/feed).
    /// Propagated via P2P handshake so peers can discover feeds without manual configuration.
    #[serde(default)]
    pub marketplace_feed: Option<String>,
    /// Optional self-advertised external endpoint in "host:port" form.
    /// When present, public and routable, peers should prefer this over the
    /// TCP source IP when recording us as a dialable peer. Allows nodes
    /// behind NAT to publish their UPnP-mapped or operator-set public
    /// address, instead of relying on the receiver's observed TCP IP
    /// (which is wrong under CGNAT). Older peers silently ignore the field.
    #[serde(default)]
    pub external_endpoint: Option<String>,
}

impl HandshakePayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::Handshake,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Handshake {
            return Err("Not a handshake message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Ping message with 8-byte nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingPayload {
    pub nonce: u64,
}
/// Gossip payload for settlement proofs. Raw JSON bytes of a SettlementProof.
pub struct ProofGossipPayload {
    pub proof_json: Vec<u8>,
}

impl ProofGossipPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::ProofGossip,
            payload: self.proof_json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::ProofGossip {
            return Err("Not a proof gossip message".to_string());
        }
        Ok(ProofGossipPayload {
            proof_json: msg.payload.clone(),
        })
    }
}

/// Wire payload for MessageType::OfferTakeNotification. UTF-8 JSON with the
/// minimum fields the seller's iriumd needs to mark the offer taken:
///   { "offer_id", "buyer_address", "agreement_id", "agreement_hash",
///     "taken_at", "seller_pubkey" }
/// The seller's iriumd filters by matching its own offer's seller_pubkey
/// against the payload before mutating anything.
pub struct OfferTakeNotificationPayload {
    pub take_json: Vec<u8>,
}

impl OfferTakeNotificationPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::OfferTakeNotification,
            payload: self.take_json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::OfferTakeNotification {
            return Err("Not an offer-take notification".to_string());
        }
        Ok(OfferTakeNotificationPayload {
            take_json: msg.payload.clone(),
        })
    }
}


impl PingPayload {
    pub fn to_message(&self) -> Message {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&self.nonce.to_be_bytes());
        Message {
            msg_type: MessageType::Ping,
            payload,
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Ping {
            return Err("Not a ping message".to_string());
        }
        if msg.payload.len() != 8 {
            return Err("Invalid ping payload length".to_string());
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&msg.payload);
        Ok(PingPayload {
            nonce: u64::from_be_bytes(bytes),
        })
    }
}

/// Pong message reuses PingPayload format.
pub type PongPayload = PingPayload;

/// Uptime challenge payload: nonce + timestamp.
#[derive(Debug, Clone)]
pub struct UptimeChallengePayload {
    pub nonce: [u8; 32],
    pub timestamp: u64,
}

impl UptimeChallengePayload {
    pub fn to_message(&self) -> Message {
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        Message {
            msg_type: MessageType::UptimeChallenge,
            payload,
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::UptimeChallenge {
            return Err("Not an uptime challenge message".to_string());
        }
        if msg.payload.len() != 40 {
            return Err("Invalid uptime challenge payload length".to_string());
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&msg.payload[0..32]);
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&msg.payload[32..40]);
        let timestamp = u64::from_be_bytes(ts_bytes);
        Ok(UptimeChallengePayload { nonce, timestamp })
    }
}

/// Uptime proof payload: nonce + timestamp + HMAC.
#[derive(Debug, Clone)]
pub struct UptimeProofPayload {
    pub nonce: [u8; 32],
    pub timestamp: u64,
    pub hmac: [u8; 32],
}

impl UptimeProofPayload {
    pub fn to_message(&self) -> Message {
        let mut payload = Vec::with_capacity(72);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.timestamp.to_be_bytes());
        payload.extend_from_slice(&self.hmac);
        Message {
            msg_type: MessageType::UptimeProof,
            payload,
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::UptimeProof {
            return Err("Not an uptime proof message".to_string());
        }
        if msg.payload.len() != 72 {
            return Err("Invalid uptime proof payload length".to_string());
        }
        let nonce: [u8; 32] = msg.payload[0..32]
            .try_into()
            .map_err(|_| "Invalid uptime proof payload length".to_string())?;
        let ts_bytes: [u8; 8] = msg.payload[32..40]
            .try_into()
            .map_err(|_| "Invalid uptime proof payload length".to_string())?;
        let timestamp = u64::from_be_bytes(ts_bytes);
        let hmac: [u8; 32] = msg.payload[40..72]
            .try_into()
            .map_err(|_| "Invalid uptime proof payload length".to_string())?;
        Ok(UptimeProofPayload {
            nonce,
            timestamp,
            hmac,
        })
    }
}

/// Block message: raw block bytes.
#[derive(Debug, Clone)]
pub struct BlockPayload {
    pub block_data: Vec<u8>,
}

impl BlockPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::Block,
            payload: self.block_data.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Block {
            return Err("Not a block message".to_string());
        }
        if msg.payload.len() as u32 > MAX_BLOCK_SIZE {
            return Err("Block payload too large".to_string());
        }
        Ok(BlockPayload {
            block_data: msg.payload.clone(),
        })
    }
}

/// Tx message: raw transaction bytes.
#[derive(Debug, Clone)]
pub struct TxPayload {
    pub tx_data: Vec<u8>,
}

impl TxPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::Tx,
            payload: self.tx_data.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Tx {
            return Err("Not a tx message".to_string());
        }
        Ok(TxPayload {
            tx_data: msg.payload.clone(),
        })
    }
}

/// Empty payload helper for messages without a body.
#[derive(Debug, Clone)]
pub struct EmptyPayload;

impl EmptyPayload {
    pub fn to_message(msg_type: MessageType) -> Result<Message, String> {
        Ok(Message {
            msg_type,
            payload: Vec::new(),
        })
    }
}

/// Peers message: JSON list of multiaddrs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersPayload {
    pub peers: Vec<String>,
}

impl PeersPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::Peers,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Peers {
            return Err("Not a peers message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Request block bodies starting from a given hash.
#[derive(Debug, Clone)]
pub struct GetBlocksPayload {
    pub start_hash: Vec<u8>,
    pub count: u32,
}

impl GetBlocksPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let mut payload = Vec::with_capacity(4 + self.start_hash.len());
        payload.extend_from_slice(&self.count.to_be_bytes());
        payload.extend_from_slice(&self.start_hash);
        Ok(Message {
            msg_type: MessageType::GetBlocks,
            payload,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::GetBlocks {
            return Err("Not a get_blocks message".to_string());
        }
        if msg.payload.len() < 4 {
            return Err("get_blocks payload too short".to_string());
        }
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&msg.payload[0..4]);
        let count = u32::from_be_bytes(count_bytes);
        let start_hash = msg.payload[4..].to_vec();
        if !start_hash.is_empty() && start_hash.len() != 32 {
            return Err("get_blocks start_hash invalid".to_string());
        }
        if count == 0 || count > MAX_BLOCKS_PER_REQUEST {
            return Err("get_blocks count out of range".to_string());
        }
        Ok(GetBlocksPayload { start_hash, count })
    }
}

/// Request block headers (SPV/light clients).
#[derive(Debug, Clone)]
pub struct GetHeadersPayload {
    pub start_hash: Vec<u8>,
    pub count: u32,
}

impl GetHeadersPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let mut payload = Vec::with_capacity(4 + self.start_hash.len());
        payload.extend_from_slice(&self.count.to_be_bytes());
        payload.extend_from_slice(&self.start_hash);
        Ok(Message {
            msg_type: MessageType::GetHeaders,
            payload,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::GetHeaders {
            return Err("Not a get_headers message".to_string());
        }
        if msg.payload.len() < 4 {
            return Err("get_headers payload too short".to_string());
        }
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&msg.payload[0..4]);
        let count = u32::from_be_bytes(count_bytes);
        let start_hash = msg.payload[4..].to_vec();
        if !start_hash.is_empty() && start_hash.len() != 32 {
            return Err("get_headers start_hash invalid".to_string());
        }
        if count == 0 || count > MAX_HEADERS_PER_REQUEST {
            return Err("get_headers count out of range".to_string());
        }
        Ok(GetHeadersPayload { start_hash, count })
    }
}

/// Headers message: raw concatenated headers.
#[derive(Debug, Clone)]
pub struct HeadersPayload {
    pub headers: Vec<u8>,
}

impl HeadersPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::Headers,
            payload: self.headers.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Headers {
            return Err("Not a headers message".to_string());
        }
        Ok(HeadersPayload {
            headers: msg.payload.clone(),
        })
    }
}

/// Mempool message: JSON list of tx hashes in hex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolPayload {
    pub tx_hashes: Vec<String>,
}

impl MempoolPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::Mempool,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Mempool {
            return Err("Not a mempool message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Optional relay address announcement for a transaction: peer can share
/// a payout address to be considered for relay rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAddressPayload {
    pub txid: String,
    pub address: String,
}

impl RelayAddressPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::RelayAddress,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::RelayAddress {
            return Err("Not a relay address message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Inventory announcement (txids only for now).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvPayload {
    pub txids: Vec<String>,
}

impl InvPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::Inv,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Inv {
            return Err("Not an inv message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Request specific data by txid (txids only for now).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDataPayload {
    pub txids: Vec<String>,
}

impl GetDataPayload {
    pub fn to_message(&self) -> Result<Message, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(Message {
            msg_type: MessageType::GetData,
            payload: json,
        })
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::GetData {
            return Err("Not a getdata message".to_string());
        }
        serde_json::from_slice(&msg.payload).map_err(|e| e.to_string())
    }
}

/// Disconnect message with UTF-8 reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisconnectPayload {
    pub reason: String,
}

impl DisconnectPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::Disconnect,
            payload: self.reason.as_bytes().to_vec(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::Disconnect {
            return Err("Not a disconnect message".to_string());
        }
        let reason = String::from_utf8(msg.payload.clone()).map_err(|e| e.to_string())?;
        Ok(DisconnectPayload { reason })
    }
}


/// Gossip payload for a raised dispute. Raw JSON bytes of a DisputeRaise.
pub struct DisputeRaisedNotificationPayload {
    pub json: Vec<u8>,
}

impl DisputeRaisedNotificationPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::DisputeRaisedNotification,
            payload: self.json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::DisputeRaisedNotification {
            return Err("Not a dispute raised notification".to_string());
        }
        Ok(DisputeRaisedNotificationPayload {
            json: msg.payload.clone(),
        })
    }
}

/// Gossip payload for a submitted dispute evidence. Raw JSON bytes of a DisputeEvidence.
pub struct DisputeEvidenceNotificationPayload {
    pub json: Vec<u8>,
}

impl DisputeEvidenceNotificationPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::DisputeEvidenceNotification,
            payload: self.json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::DisputeEvidenceNotification {
            return Err("Not a dispute evidence notification".to_string());
        }
        Ok(DisputeEvidenceNotificationPayload {
            json: msg.payload.clone(),
        })
    }
}

/// Gossip payload for a resolved dispute. Raw JSON bytes of a DisputeResolution.
pub struct DisputeResolvedNotificationPayload {
    pub json: Vec<u8>,
}

impl DisputeResolvedNotificationPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::DisputeResolvedNotification,
            payload: self.json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::DisputeResolvedNotification {
            return Err("Not a dispute resolved notification".to_string());
        }
        Ok(DisputeResolvedNotificationPayload {
            json: msg.payload.clone(),
        })
    }
}

/// Gossip payload announcing an automatic escalation of a dispute to its
/// fallback resolver. JSON shape: {"agreement_hash": "...", "escalated_at_height": N}
pub struct DisputeEscalatedNotificationPayload {
    pub json: Vec<u8>,
}

impl DisputeEscalatedNotificationPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::DisputeEscalatedNotification,
            payload: self.json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::DisputeEscalatedNotification {
            return Err("Not a dispute escalated notification".to_string());
        }
        Ok(DisputeEscalatedNotificationPayload {
            json: msg.payload.clone(),
        })
    }
}

/// Wire payload for MessageType::OfferBroadcast. UTF-8 JSON of the full
/// offer object (same shape `/offers/feed` exposes). The seller's iriumd
/// emits one of these per newly-created local offer; every receiving peer
/// writes the JSON to ~/.irium/offers/<id>.json and re-broadcasts to its
/// other peers (the gossip flood). Anti-spam (per-peer rate limit + max
/// payload size + LRU dedup) lives in p2p.rs to keep this struct minimal.
pub struct OfferBroadcastPayload {
    pub offer_json: Vec<u8>,
}

impl OfferBroadcastPayload {
    pub fn to_message(&self) -> Message {
        Message {
            msg_type: MessageType::OfferBroadcast,
            payload: self.offer_json.clone(),
        }
    }

    pub fn from_message(msg: &Message) -> Result<Self, String> {
        if msg.msg_type != MessageType::OfferBroadcast {
            return Err("Not an offer broadcast".to_string());
        }
        Ok(OfferBroadcastPayload {
            offer_json: msg.payload.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_try_from_offer_broadcast_25() {
        // Forward-compat: byte 25 maps to OfferBroadcast.
        assert_eq!(MessageType::try_from(25u8).unwrap(), MessageType::OfferBroadcast);
    }

    #[test]
    fn message_type_try_from_unknown_byte_errors() {
        // Sanity: a byte we don't know about returns an error (the read-loop
        // wraps this with .unwrap_or(Unknown) for graceful degradation).
        assert!(MessageType::try_from(200u8).is_err());
    }

    #[test]
    fn offer_broadcast_payload_roundtrip() {
        let json = br#"{"id":"abc","status":"open","amount_sats":1000}"#.to_vec();
        let payload = OfferBroadcastPayload { offer_json: json.clone() };
        let msg = payload.to_message();
        assert_eq!(msg.msg_type, MessageType::OfferBroadcast);
        assert_eq!(msg.payload, json);

        let parsed = OfferBroadcastPayload::from_message(&msg).expect("parse ok");
        assert_eq!(parsed.offer_json, json);
    }

    #[test]
    fn offer_broadcast_payload_rejects_wrong_message_type() {
        // from_message must refuse a message tagged with a different variant —
        // protects callers that match on msg_type before dispatching.
        let msg = Message { msg_type: MessageType::Tx, payload: vec![1, 2, 3] };
        assert!(OfferBroadcastPayload::from_message(&msg).is_err());
    }

    #[test]
    fn offer_broadcast_wire_serialization_roundtrip() {
        // End-to-end: payload → Message → serialized bytes → deserialized
        // Message → parsed payload. Catches breakage in the framing layer.
        let json = br#"{"id":"x","status":"open"}"#.to_vec();
        let msg = OfferBroadcastPayload { offer_json: json.clone() }.to_message();
        let bytes = msg.serialize();
        let parsed_msg = Message::deserialize(&bytes).expect("deserialize ok");
        assert_eq!(parsed_msg.msg_type, MessageType::OfferBroadcast);
        let parsed_payload = OfferBroadcastPayload::from_message(&parsed_msg).expect("parse ok");
        assert_eq!(parsed_payload.offer_json, json);
    }
}

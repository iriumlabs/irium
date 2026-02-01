import { getPublicKey, sign, utils } from './assets/vendor/noble-secp256k1.js';

const WALLET_KEY = 'irium_wallet_v1';
const NODE_KEY = 'irium_wallet_node_v1';
const DEFAULT_NODE = 'http://127.0.0.1:38300';
const SATS_PER_IRM = 100000000n;
const COINBASE_MATURITY = 100n;
const P2PKH_VERSION = 0x39;
const PBKDF2_ITERS = 200000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const ui = {
  nodeUrl: document.getElementById('nodeUrl'),
  rpcToken: document.getElementById('rpcToken'),
  saveNode: document.getElementById('saveNode'),
  useDefaultNode: document.getElementById('useDefaultNode'),
  nodeStatus: document.getElementById('nodeStatus'),
  createPassword: document.getElementById('createPassword'),
  createPasswordConfirm: document.getElementById('createPasswordConfirm'),
  createWallet: document.getElementById('createWallet'),
  importPrivkey: document.getElementById('importPrivkey'),
  importPassword: document.getElementById('importPassword'),
  importWallet: document.getElementById('importWallet'),
  walletEmpty: document.getElementById('walletEmpty'),
  walletLocked: document.getElementById('walletLocked'),
  walletUnlocked: document.getElementById('walletUnlocked'),
  unlockPassword: document.getElementById('unlockPassword'),
  unlockWallet: document.getElementById('unlockWallet'),
  resetWallet: document.getElementById('resetWallet'),
  walletAddress: document.getElementById('walletAddress'),
  walletPubkey: document.getElementById('walletPubkey'),
  copyAddress: document.getElementById('copyAddress'),
  exportWallet: document.getElementById('exportWallet'),
  lockWallet: document.getElementById('lockWallet'),
  balanceValue: document.getElementById('balanceValue'),
  refreshBalance: document.getElementById('refreshBalance'),
  utxoList: document.getElementById('utxoList'),
  sendForm: document.getElementById('sendForm'),
  sendTo: document.getElementById('sendTo'),
  sendAmount: document.getElementById('sendAmount'),
  feeOverride: document.getElementById('feeOverride'),
  coinSelect: document.getElementById('coinSelect'),
  previewTx: document.getElementById('previewTx'),
  sendStatus: document.getElementById('sendStatus'),
  rawTx: document.getElementById('rawTx'),
};

const state = {
  node: {
    url: DEFAULT_NODE,
    token: '',
  },
  wallet: {
    unlocked: false,
    privkeyHex: '',
    pubkeyHex: '',
    address: '',
    pkhHex: '',
  },
};

function setStatus(el, msg, kind) {
  el.textContent = msg;
  el.className = `wallet-status${kind ? ` status-${kind}` : ''}`;
}

function normalizeNodeUrl(raw) {
  let url = raw.trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }
  return url.replace(/\/+$/, '');
}

function saveNodeSettings() {
  const url = normalizeNodeUrl(ui.nodeUrl.value || '');
  const token = ui.rpcToken.value.trim();
  state.node.url = url || DEFAULT_NODE;
  state.node.token = token;
  localStorage.setItem(NODE_KEY, JSON.stringify({ url: state.node.url, token }));
}

function loadNodeSettings() {
  const raw = localStorage.getItem(NODE_KEY);
  if (!raw) {
    ui.nodeUrl.value = DEFAULT_NODE;
    ui.rpcToken.value = '';
    return;
  }
  try {
    const data = JSON.parse(raw);
    state.node.url = normalizeNodeUrl(data.url || DEFAULT_NODE) || DEFAULT_NODE;
    state.node.token = data.token || '';
  } catch (err) {
    state.node.url = DEFAULT_NODE;
    state.node.token = '';
  }
  ui.nodeUrl.value = state.node.url;
  ui.rpcToken.value = state.node.token;
}

async function rpcFetch(path, options = {}) {
  if (!state.node.url) {
    throw new Error('Node URL not set');
  }
  const base = normalizeNodeUrl(state.node.url);
  const url = `${base}${path}`;
  const headers = Object.assign({}, options.headers || {});
  if (options.json) {
    headers['Content-Type'] = 'application/json';
  }
  if (state.node.token) {
    headers['Authorization'] = `Bearer ${state.node.token}`;
  }
  const resp = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.json ? JSON.stringify(options.json) : options.body,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text || resp.statusText}`);
  }
  return resp.json();
}

async function testNodeConnection() {
  try {
    setStatus(ui.nodeStatus, 'Connecting...', 'warn');
    const status = await rpcFetch('/status');
    setStatus(ui.nodeStatus, `Connected (height ${status.height})`, 'ok');
  } catch (err) {
    setStatus(ui.nodeStatus, err.message, 'error');
  }
}

function walletRecord() {
  const raw = localStorage.getItem(WALLET_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (err) {
    return null;
  }
}

function setWalletRecord(record) {
  localStorage.setItem(WALLET_KEY, JSON.stringify(record));
}

function clearWalletRecord() {
  localStorage.removeItem(WALLET_KEY);
}

function showPanel(panel) {
  ui.walletEmpty.classList.add('is-hidden');
  ui.walletLocked.classList.add('is-hidden');
  ui.walletUnlocked.classList.add('is-hidden');
  panel.classList.remove('is-hidden');
}

function updateWalletUI() {
  const record = walletRecord();
  if (!record) {
    showPanel(ui.walletEmpty);
    ui.walletAddress.textContent = '-';
    ui.walletPubkey.textContent = '-';
    return;
  }
  if (!state.wallet.unlocked) {
    showPanel(ui.walletLocked);
    return;
  }
  showPanel(ui.walletUnlocked);
  ui.walletAddress.textContent = state.wallet.address || record.address || '-';
  ui.walletPubkey.textContent = state.wallet.pubkeyHex || record.pubkey || '-';
}

async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function toBase64(bytes) {
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function fromBase64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

async function encryptPrivkey(privkeyHex, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(privkeyHex)
  );
  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(new Uint8Array(ciphertext)),
    iter: PBKDF2_ITERS,
  };
}

async function decryptPrivkey(cipher, password) {
  const salt = fromBase64(cipher.salt);
  const iv = fromBase64(cipher.iv);
  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    fromBase64(cipher.ct)
  );
  return decoder.decode(plaintext);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const clean = hex.trim().replace(/^0x/i, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...chunks) {
  const size = chunks.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of chunks) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function sha256(data) {
  return crypto.subtle.digest('SHA-256', data).then((buf) => new Uint8Array(buf));
}

async function sha256d(data) {
  const first = await sha256(data);
  return sha256(first);
}

function ripemd160(data) {
  function rotl(x, n) {
    return (x << n) | (x >>> (32 - n));
  }
  function f1(x, y, z) {
    return x ^ y ^ z;
  }
  function f2(x, y, z) {
    return (x & y) | (~x & z);
  }
  function f3(x, y, z) {
    return (x | ~y) ^ z;
  }
  function f4(x, y, z) {
    return (x & z) | (y & ~z);
  }
  function f5(x, y, z) {
    return x ^ (y | ~z);
  }

  const r = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
  ];
  const rp = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
  ];
  const s = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
  ];
  const sp = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
  ];
  const K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const Kp = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  const msg = new Uint8Array(data);
  const msgLen = msg.length;
  const withOne = msgLen + 1;
  const padLen = withOne % 64 <= 56 ? 56 - (withOne % 64) : 56 + 64 - (withOne % 64);
  const totalLen = withOne + padLen + 8;
  const buffer = new Uint8Array(totalLen);
  buffer.set(msg);
  buffer[msgLen] = 0x80;
  const bitLen = BigInt(msgLen) * 8n;
  for (let i = 0; i < 8; i++) {
    buffer[totalLen - 8 + i] = Number((bitLen >> BigInt(8 * i)) & 0xffn);
  }

  const words = new Uint32Array(totalLen / 4);
  for (let i = 0; i < words.length; i++) {
    words[i] =
      buffer[i * 4] |
      (buffer[i * 4 + 1] << 8) |
      (buffer[i * 4 + 2] << 16) |
      (buffer[i * 4 + 3] << 24);
  }

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  for (let i = 0; i < words.length; i += 16) {
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;

    for (let j = 0; j < 80; j++) {
      const wl = words[i + r[j]];
      let tl;
      if (j < 16) tl = f1(bl, cl, dl);
      else if (j < 32) tl = f2(bl, cl, dl);
      else if (j < 48) tl = f3(bl, cl, dl);
      else if (j < 64) tl = f4(bl, cl, dl);
      else tl = f5(bl, cl, dl);
      tl = (al + tl + wl + K[Math.floor(j / 16)]) >>> 0;
      tl = rotl(tl, s[j]);
      tl = (tl + el) >>> 0;
      al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

      const wr = words[i + rp[j]];
      let tr;
      if (j < 16) tr = f5(br, cr, dr);
      else if (j < 32) tr = f4(br, cr, dr);
      else if (j < 48) tr = f3(br, cr, dr);
      else if (j < 64) tr = f2(br, cr, dr);
      else tr = f1(br, cr, dr);
      tr = (ar + tr + wr + Kp[Math.floor(j / 16)]) >>> 0;
      tr = rotl(tr, sp[j]);
      tr = (tr + er) >>> 0;
      ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    const t = (h1 + cl + dr) >>> 0;
    h1 = (h2 + dl + er) >>> 0;
    h2 = (h3 + el + ar) >>> 0;
    h3 = (h4 + al + br) >>> 0;
    h4 = (h0 + bl + cr) >>> 0;
    h0 = t;
  }

  const out = new Uint8Array(20);
  const wordsOut = [h0, h1, h2, h3, h4];
  for (let i = 0; i < wordsOut.length; i++) {
    const w = wordsOut[i];
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

async function hash160(data) {
  const sha = await sha256(data);
  return ripemd160(sha);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = Object.fromEntries(BASE58_ALPHABET.split('').map((c, i) => [c, i]));

function base58Encode(bytes) {
  let num = 0n;
  for (const b of bytes) {
    num = num * 256n + BigInt(b);
  }
  let out = '';
  while (num > 0n) {
    const rem = Number(num % 58n);
    num /= 58n;
    out = BASE58_ALPHABET[rem] + out;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out || '1';
}

function base58Decode(str) {
  let num = 0n;
  for (const c of str) {
    const val = BASE58_MAP[c];
    if (val === undefined) {
      throw new Error('Invalid base58 character');
    }
    num = num * 58n + BigInt(val);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.push(Number(num % 256n));
    num /= 256n;
  }
  bytes.reverse();
  for (const c of str) {
    if (c === '1') bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

async function addressFromPubkey(pubkey) {
  const pkh = await hash160(pubkey);
  const payload = new Uint8Array(1 + pkh.length);
  payload[0] = P2PKH_VERSION;
  payload.set(pkh, 1);
  const checksum = (await sha256d(payload)).slice(0, 4);
  return base58Encode(concatBytes(payload, checksum));
}

async function decodeAddress(addr) {
  let raw;
  try {
    raw = base58Decode(addr);
  } catch (err) {
    return null;
  }
  if (raw.length !== 25) return null;
  const body = raw.slice(0, -4);
  const checksum = raw.slice(-4);
  const check = (await sha256d(body)).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== check[i]) return null;
  }
  if (body[0] !== P2PKH_VERSION) return null;
  return body.slice(1);
}

async function createWallet() {
  const password = ui.createPassword.value.trim();
  const confirm = ui.createPasswordConfirm.value.trim();
  if (!password || password.length < 6) {
    setStatus(ui.nodeStatus, 'Password must be at least 6 characters', 'error');
    return;
  }
  if (password !== confirm) {
    setStatus(ui.nodeStatus, 'Passwords do not match', 'error');
    return;
  }
  const privkeyBytes = utils.randomPrivateKey();
  const privkeyHex = bytesToHex(privkeyBytes);
  const pubkeyBytes = getPublicKey(privkeyBytes, true);
  const pubkeyHex = bytesToHex(pubkeyBytes);
  const address = await addressFromPubkey(pubkeyBytes);
  const pkh = await decodeAddress(address);
  const pkhHex = pkh ? bytesToHex(pkh) : '';

  const cipher = await encryptPrivkey(privkeyHex, password);
  setWalletRecord({
    version: 1,
    address,
    pubkey: pubkeyHex,
    pkh: pkhHex,
    cipher,
  });
  ui.createPassword.value = '';
  ui.createPasswordConfirm.value = '';
  await unlockWithPassword(password);
}

async function importWallet() {
  const privkeyHex = ui.importPrivkey.value.trim().toLowerCase();
  const password = ui.importPassword.value.trim();
  if (!privkeyHex || privkeyHex.length !== 64) {
    setStatus(ui.nodeStatus, 'Private key must be 64 hex chars', 'error');
    return;
  }
  let privkeyBytes;
  try {
    privkeyBytes = hexToBytes(privkeyHex);
  } catch (err) {
    setStatus(ui.nodeStatus, 'Invalid private key hex', 'error');
    return;
  }
  if (!utils.isValidPrivateKey(privkeyBytes)) {
    setStatus(ui.nodeStatus, 'Invalid private key', 'error');
    return;
  }
  if (!password || password.length < 6) {
    setStatus(ui.nodeStatus, 'Password must be at least 6 characters', 'error');
    return;
  }
  const pubkeyBytes = getPublicKey(privkeyBytes, true);
  const pubkeyHex = bytesToHex(pubkeyBytes);
  const address = await addressFromPubkey(pubkeyBytes);
  const pkh = await decodeAddress(address);
  const pkhHex = pkh ? bytesToHex(pkh) : '';
  const cipher = await encryptPrivkey(privkeyHex, password);
  setWalletRecord({
    version: 1,
    address,
    pubkey: pubkeyHex,
    pkh: pkhHex,
    cipher,
  });
  ui.importPrivkey.value = '';
  ui.importPassword.value = '';
  await unlockWithPassword(password);
}

async function unlockWithPassword(password) {
  const record = walletRecord();
  if (!record) {
    setStatus(ui.nodeStatus, 'No wallet found', 'error');
    return;
  }
  try {
    const privkeyHex = await decryptPrivkey(record.cipher, password);
    const privkeyBytes = hexToBytes(privkeyHex);
    if (!utils.isValidPrivateKey(privkeyBytes)) {
      throw new Error('Invalid private key');
    }
    const pubkeyBytes = getPublicKey(privkeyBytes, true);
    const pubkeyHex = bytesToHex(pubkeyBytes);
    const address = await addressFromPubkey(pubkeyBytes);
    const pkh = await decodeAddress(address);
    state.wallet = {
      unlocked: true,
      privkeyHex,
      pubkeyHex,
      address,
      pkhHex: pkh ? bytesToHex(pkh) : '',
    };
    ui.unlockPassword.value = '';
    updateWalletUI();
    setStatus(ui.nodeStatus, 'Wallet unlocked', 'ok');
  } catch (err) {
    setStatus(ui.nodeStatus, 'Failed to unlock wallet', 'error');
  }
}

function lockWallet() {
  state.wallet = {
    unlocked: false,
    privkeyHex: '',
    pubkeyHex: '',
    address: '',
    pkhHex: '',
  };
  updateWalletUI();
}

function formatIrm(amount) {
  const value = BigInt(amount);
  const whole = value / SATS_PER_IRM;
  const frac = value % SATS_PER_IRM;
  if (frac === 0n) {
    return whole.toString();
  }
  return `${whole.toString()}.${frac.toString().padStart(8, '0')}`;
}

function parseIrm(raw) {
  const value = raw.trim();
  if (!value) throw new Error('Empty amount');
  const parts = value.split('.');
  if (parts.length > 2) throw new Error('Invalid amount');
  const whole = parts[0] ? BigInt(parts[0]) : 0n;
  let frac = 0n;
  if (parts.length === 2) {
    const fracStr = parts[1];
    if (fracStr.length > 8) throw new Error('Too many decimals');
    frac = BigInt(fracStr.padEnd(8, '0'));
  }
  return whole * SATS_PER_IRM + frac;
}

function estimateTxSize(inputs, outputs) {
  return 10 + inputs * 148 + outputs * 34;
}

function u8(value) {
  return new Uint8Array([value]);
}

function u32le(value) {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value >>> 0, true);
  return out;
}

function u64le(value) {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function serializeTx(tx) {
  const parts = [];
  parts.push(u32le(tx.version));
  parts.push(u8(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(u8(input.prev_txid.length));
    parts.push(input.prev_txid);
    parts.push(u32le(input.prev_index));
    parts.push(u8(input.script_sig.length));
    parts.push(input.script_sig);
    parts.push(u32le(input.sequence));
  }
  parts.push(u8(tx.outputs.length));
  for (const output of tx.outputs) {
    parts.push(u64le(output.value));
    parts.push(u8(output.script_pubkey.length));
    parts.push(output.script_pubkey);
  }
  parts.push(u32le(tx.locktime));
  return concatBytes(...parts);
}

async function signatureDigest(tx, inputIndex, scriptPubkey) {
  const cloned = {
    version: tx.version,
    inputs: tx.inputs.map((input, idx) => ({
      prev_txid: input.prev_txid,
      prev_index: input.prev_index,
      script_sig: idx === inputIndex ? scriptPubkey : new Uint8Array([]),
      sequence: input.sequence,
    })),
    outputs: tx.outputs,
    locktime: tx.locktime,
  };
  const raw = serializeTx(cloned);
  const withHashType = concatBytes(raw, u32le(1));
  return sha256d(withHashType);
}

function p2pkhScript(pkh) {
  return concatBytes(
    u8(0x76),
    u8(0xa9),
    u8(0x14),
    pkh,
    u8(0x88),
    u8(0xac)
  );
}

async function buildTransaction(options) {
  const { utxos, amount, feeOverride, feePerByte, toAddress, changeAddress, coinSelect, height } = options;
  const order = [...utxos];
  if (coinSelect === 'largest') {
    order.sort((a, b) => Number(BigInt(b.value) - BigInt(a.value)));
  } else {
    order.sort((a, b) => Number(BigInt(a.value) - BigInt(b.value)));
  }

  const toPkh = await decodeAddress(toAddress);
  if (!toPkh) throw new Error('Invalid recipient address');
  const changePkh = await decodeAddress(changeAddress);
  if (!changePkh) throw new Error('Invalid change address');

  let selected = [];
  let total = 0n;
  let fee = feeOverride || 0n;
  for (const utxo of order) {
    const confirmations = BigInt(height || 0) - BigInt(utxo.height || 0);
    if (utxo.is_coinbase && confirmations < COINBASE_MATURITY) {
      continue;
    }
    selected.push(utxo);
    total += BigInt(utxo.value);
    if (!feeOverride) {
      const outputs = total > amount ? 2 : 1;
      fee = BigInt(estimateTxSize(selected.length, outputs)) * feePerByte;
    }
    if (total >= amount + fee) {
      break;
    }
  }

  if (total < amount + fee) {
    throw new Error('Insufficient funds');
  }

  let change = total - amount - fee;
  const outputs = [
    {
      value: amount,
      script_pubkey: p2pkhScript(toPkh),
    },
  ];
  if (change > 0n) {
    outputs.push({
      value: change,
      script_pubkey: p2pkhScript(changePkh),
    });
  }

  const inputs = selected.map((utxo) => ({
    prev_txid: hexToBytes(utxo.txid),
    prev_index: utxo.index,
    script_sig: new Uint8Array([]),
    sequence: 0xffffffff,
  }));

  let tx = {
    version: 1,
    inputs,
    outputs,
    locktime: 0,
  };

  const privkeyBytes = hexToBytes(state.wallet.privkeyHex);
  const pubkeyBytes = hexToBytes(state.wallet.pubkeyHex);
  const changeScript = p2pkhScript(changePkh);

  for (let pass = 0; pass < 2; pass++) {
    for (let i = 0; i < selected.length; i++) {
      let scriptPubkey = changeScript;
      if (selected[i].script_pubkey) {
        try {
          scriptPubkey = hexToBytes(selected[i].script_pubkey);
        } catch (err) {
          scriptPubkey = changeScript;
        }
      }
      const digest = await signatureDigest(tx, i, scriptPubkey);
      const sig = await sign(digest, privkeyBytes, { canonical: true, der: true });
      const sigWithType = concatBytes(sig, u8(0x01));
      const scriptSig = concatBytes(
        u8(sigWithType.length),
        sigWithType,
        u8(pubkeyBytes.length),
        pubkeyBytes
      );
      tx.inputs[i].script_sig = scriptSig;
    }

    const size = serializeTx(tx).length;
    if (feeOverride) {
      break;
    }
    const neededFee = BigInt(size) * feePerByte;
    if (neededFee > fee) {
      const extra = neededFee - fee;
      if (change >= extra) {
        fee = neededFee;
        change -= extra;
        if (change > 0n) {
          if (tx.outputs.length > 1) {
            tx.outputs[1].value = change;
          } else {
            tx.outputs.push({
              value: change,
              script_pubkey: changeScript,
            });
          }
        } else {
          tx.outputs = [tx.outputs[0]];
        }
      } else {
        throw new Error('Insufficient funds for fee');
      }
    } else {
      break;
    }
  }

  return { tx, fee, change };
}

async function refreshBalance() {
  if (!state.wallet.unlocked) {
    setStatus(ui.sendStatus, 'Unlock wallet first', 'error');
    return;
  }
  try {
    const balance = await rpcFetch(`/rpc/balance?address=${state.wallet.address}`);
    ui.balanceValue.textContent = `${formatIrm(balance.balance)} IRM (height ${balance.height})`;
    const utxos = await rpcFetch(`/rpc/utxos?address=${state.wallet.address}`);
    renderUtxos(utxos);
    setStatus(ui.sendStatus, 'Balance refreshed', 'ok');
  } catch (err) {
    setStatus(ui.sendStatus, err.message, 'error');
  }
}

function renderUtxos(payload) {
  ui.utxoList.innerHTML = '';
  if (!payload.utxos || payload.utxos.length === 0) {
    const div = document.createElement('div');
    div.className = 'wallet-row';
    div.textContent = 'No UTXOs found.';
    ui.utxoList.appendChild(div);
    return;
  }
  payload.utxos.forEach((utxo) => {
    const row = document.createElement('div');
    row.className = 'wallet-row';
    const left = document.createElement('div');
    const label = document.createElement('div');
    label.className = 'wallet-label';
    label.textContent = `${utxo.txid.slice(0, 12)}...:${utxo.index}`;
    const value = document.createElement('div');
    value.className = 'wallet-value';
    const confirmations = payload.height - utxo.height;
    const maturity = utxo.is_coinbase && confirmations < Number(COINBASE_MATURITY);
    value.textContent = `${formatIrm(utxo.value)} IRM (h ${utxo.height})${maturity ? ' - immature' : ''}`;
    left.appendChild(label);
    left.appendChild(value);
    row.appendChild(left);
    ui.utxoList.appendChild(row);
  });
}

async function handleSend(previewOnly) {
  if (!state.wallet.unlocked) {
    setStatus(ui.sendStatus, 'Unlock wallet first', 'error');
    return;
  }
  const toAddress = ui.sendTo.value.trim();
  if (!toAddress) {
    setStatus(ui.sendStatus, 'Recipient address required', 'error');
    return;
  }
  let amount;
  try {
    amount = parseIrm(ui.sendAmount.value);
  } catch (err) {
    setStatus(ui.sendStatus, err.message, 'error');
    return;
  }
  let feeOverride = null;
  if (ui.feeOverride.value.trim()) {
    try {
      feeOverride = parseIrm(ui.feeOverride.value);
    } catch (err) {
      setStatus(ui.sendStatus, err.message, 'error');
      return;
    }
  }
  try {
    setStatus(ui.sendStatus, 'Building transaction...', 'warn');
    const utxos = await rpcFetch(`/rpc/utxos?address=${state.wallet.address}`);
    let feePerByte = 1n;
    if (!feeOverride) {
      try {
        const feeEst = await rpcFetch('/rpc/fee_estimate');
        const est = Math.ceil(feeEst.min_fee_per_byte);
        if (est > Number(feePerByte)) feePerByte = BigInt(est);
      } catch (err) {
        // ignore fee estimate failure
      }
    }
    const { tx } = await buildTransaction({
      utxos: utxos.utxos,
      height: utxos.height,
      amount,
      feeOverride,
      feePerByte,
      toAddress,
      changeAddress: state.wallet.address,
      coinSelect: ui.coinSelect.value,
    });
    const raw = serializeTx(tx);
    ui.rawTx.value = bytesToHex(raw);
    if (previewOnly) {
      setStatus(ui.sendStatus, 'Preview ready', 'ok');
      return;
    }
    await rpcFetch('/rpc/submit_tx', { method: 'POST', json: { tx_hex: bytesToHex(raw) } });
    setStatus(ui.sendStatus, 'Transaction broadcast', 'ok');
  } catch (err) {
    setStatus(ui.sendStatus, err.message, 'error');
  }
}

function setupEvents() {
  ui.saveNode.addEventListener('click', async () => {
    saveNodeSettings();
    await testNodeConnection();
  });
  ui.useDefaultNode.addEventListener('click', async () => {
    ui.nodeUrl.value = DEFAULT_NODE;
    ui.rpcToken.value = '';
    saveNodeSettings();
    await testNodeConnection();
  });
  ui.createWallet.addEventListener('click', createWallet);
  ui.importWallet.addEventListener('click', importWallet);
  ui.unlockWallet.addEventListener('click', async () => {
    await unlockWithPassword(ui.unlockPassword.value.trim());
  });
  ui.resetWallet.addEventListener('click', () => {
    if (confirm('Delete wallet from this browser?')) {
      clearWalletRecord();
      lockWallet();
    }
  });
  ui.lockWallet.addEventListener('click', lockWallet);
  ui.copyAddress.addEventListener('click', async () => {
    if (!state.wallet.address) return;
    await navigator.clipboard.writeText(state.wallet.address);
  });
  ui.exportWallet.addEventListener('click', () => {
    const record = walletRecord();
    if (!record) return;
    const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'irium-wallet.json';
    link.click();
    URL.revokeObjectURL(url);
  });
  ui.refreshBalance.addEventListener('click', refreshBalance);
  ui.sendForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    await handleSend(false);
  });
  ui.previewTx.addEventListener('click', async () => {
    await handleSend(true);
  });
}

function init() {
  loadNodeSettings();
  updateWalletUI();
  setupEvents();
}

init();

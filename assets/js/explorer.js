// Irium Block Explorer JavaScript with CORS Proxy
const DEFAULT_API_BASE = 'https://api.iriumlabs.org/api';
const CORS_PROXIES = ['', 'https://api.allorigins.win/raw?url='];
const FETCH_TIMEOUT_MS = 15000;

let __blocksCursor = null;
let __blocksLoading = false;

async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}


function getApiBases() {
  const bases = [];
  if (window.IRIUM_API_BASE) bases.push(window.IRIUM_API_BASE);
  const docBase = document.documentElement.dataset.apiBase || (document.body && document.body.dataset && document.body.dataset.apiBase);
  if (docBase) bases.push(docBase);
  bases.push(DEFAULT_API_BASE);
  if (location && location.origin) bases.push(location.origin + '/api');
  const deduped = [];
  for (const base of bases) {
    const norm = base.replace(/\/+$/, '');
    if (!deduped.includes(norm)) deduped.push(norm);
  }
  return deduped;
}

console.log('Explorer JS loaded');

function pick(obj, keys, def = undefined) {
  for (const k of keys) if (obj != null && obj[k] != null) return obj[k];
  return def;
}

function getHeader(block) {
  return (block && block.header) ? block.header : (block || {});
}

function blockRewardIrm(height) {
  if (!height) return 0;
  const halvingInterval = 210000;
  const initial = 50;
  const halvings = Math.floor((height - 1) / halvingInterval);
  if (halvings >= 64) return 0;
  return initial / Math.pow(2, halvings);
}


async function fetchJson(path) {
  const bases = getApiBases();
  const errors = [];
  for (const base of bases) {
    const url = base + path;
    for (const proxy of CORS_PROXIES) {
      const target = proxy ? proxy + encodeURIComponent(url) : url;
      try {
        const res = await fetchWithTimeout(target, { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } catch (err) {
        errors.push(err.message || String(err));
      }
    }
  }
  throw new Error(errors[0] || 'Fetch failed');
}

// Load statistics
async function loadStats() {
  try {
    console.log('Loading stats...');
    const data = await fetchJson('/stats');
    console.log('Stats loaded:', data);
    const heightEl = document.getElementById('current-height');
    const blocksEl = document.getElementById('total-blocks');
    const supplyEl = document.getElementById('total-supply');
    if (heightEl) heightEl.textContent = data.height ?? '0';
    if (blocksEl) blocksEl.textContent = data.total_blocks ?? (data.total ?? '0');
    if (supplyEl) supplyEl.textContent = ((data.supply_irm ?? 0)).toFixed(2) + ' IRM';
    const su = document.getElementById('stats-updated');
    if (su) su.textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (error) {
    console.error('Error loading stats:', error);
    for (const id of ['current-height','total-blocks','total-supply']) {
      const el = document.getElementById(id); if (el) el.textContent = 'Error';
    }
  }
}

function fmtNum(v, digits = 2) {
  const n = Number(v);
  if (!isFinite(n)) return 'N/A';
  return n.toFixed(digits);
}

function fmtDifficulty(d) {
  const n = Number(d);
  if (!isFinite(n)) return 'N/A';
  // show 2 decimals with grouping
  return n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}


function fmtPct(v) {
  const n = Number(v);
  if (!isFinite(n)) return 'N/A';
  const sign = n > 0 ? '+' : '';
  return sign + n.toFixed(2) + '%';
}

function fmtHashrate(hs) {
  const n = Number(hs);
  if (!isFinite(n) || n <= 0) return 'N/A';
  const units = ['H/s','KH/s','MH/s','GH/s','TH/s','PH/s','EH/s'];
  let v = n;
  let u = 0;
  while (v >= 1000 && u < units.length - 1) { v /= 1000; u++; }
  const digits = v >= 100 ? 0 : v >= 10 ? 1 : 2;
  return v.toFixed(digits) + ' ' + units[u];
}

// Load live mining metrics (hashrate + difficulty + difficulty change)
async function loadMiningMetrics() {
  const elHash = document.getElementById('net-hashrate');
  const elDiff = document.getElementById('net-difficulty');
  const elGrowth = document.getElementById('diff-growth');
  if (!elHash && !elDiff && !elGrowth) return;

  try {
    const m = await fetchJson('/mining?window=120&series=240');
    if (elHash) elHash.textContent = fmtHashrate(m.hashrate);
    if (elDiff) elDiff.textContent = fmtDifficulty(m.difficulty);

    const g1 = (m.difficulty_change_1h_pct != null) ? fmtPct(m.difficulty_change_1h_pct) : 'N/A';
    const g24 = (m.difficulty_change_24h_pct != null) ? fmtPct(m.difficulty_change_24h_pct) : 'N/A';
    const stable = (g1 === '+0.00%' || g1 === '0.00%') && (g24 === '+0.00%' || g24 === '0.00%');
    if (elGrowth) elGrowth.textContent = stable ? 'Stable' : (g1 + ' / ' + g24);
    const su = document.getElementById('stats-updated');
    if (su) su.textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (error) {
    console.error('Error loading mining metrics:', error);
    if (elHash) elHash.textContent = 'Error';
    if (elDiff) elDiff.textContent = 'Error';
    if (elGrowth) elGrowth.textContent = 'Error';
  }
}


function rowsToHtml(rows) {
  return rows.map(([k, v]) => (
    '<div style="display:flex; gap:12px; margin:6px 0;">' +
    '<div style="width:130px; color:rgba(255,255,255,0.7)">' + k + '</div>' +
    '<div style="font-family:monospace; word-break:break-all;">' + v + '</div>' +
    '</div>'
  )).join('');
}

function renderBlockDetails(height, raw) {
  const b = (raw && raw.block) ? raw.block : raw || {};
  const header = getHeader(b);
  const heightVal = (height !== undefined && height !== null) ? height : (b.height ?? 0);
  const hash = header.hash ?? b.hash ?? b.block_hash ?? 'N/A';
  const time = header.time ?? header.timestamp ?? b.time ?? b.timestamp ?? 0;
  const txs = Array.isArray(b.tx_hex) ? b.tx_hex.length : (b.transactions ?? b.tx_count ?? 0);
  const rewardSats = b.reward ?? b.subsidy ?? b.block_reward ?? 0;
  const rewardIrm = rewardSats ? (rewardSats / 1e8).toFixed(2) : blockRewardIrm(heightVal).toFixed(2);
  const prev = header.prev_hash ?? b.prev_hash ?? b.previous_block ?? 'N/A';
  const mr = header.merkle_root ?? b.merkle_root ?? 'N/A';
  const nonce = header.nonce ?? b.nonce ?? 'N/A';
  const bits = header.bits ?? b.bits ?? 'N/A';
  const miner = b.miner_address ?? b.miner ?? 'N/A';

  const rows = [
    ['Height', String(heightVal)],
    ['Hash', hash],
    ['Prev Hash', prev],
    ['Merkle Root', mr],
    ['Time', formatTime(time)],
    ['Reward', rewardIrm + ' IRM'],
    ['Transactions', String(txs)],
    ['Bits', String(bits)],
    ['Nonce', String(nonce)],
    ['Miner', miner]
  ];

  if (window.__showBlockModal) {
    window.__showBlockModal(rowsToHtml(rows));
  } else {
    alert(`Block ${heightVal}
Hash: ${hash}
Reward: ${rewardIrm} IRM`);
  }
}


// View block details
async function viewBlock(height) {
  try {
    console.log('Loading block details for height:', height);
    const raw = await fetchJson(`/block/${height}`);
    renderBlockDetails(height, raw);
  } catch (error) {
    console.error('Error loading block:', error);
    if (window.__showBlockError) {
      window.__showBlockError(error.message || 'Error loading block details');
    } else {
      alert('Error loading block details: ' + (error.message||'Unknown error'));
    }
  }
}

async function viewBlockByHash(hash) {
  try {
    console.log('Loading block details for hash:', hash);
    const raw = await fetchJson(`/blockhash/${hash}`);
    const heightVal = raw && raw.height ? raw.height : undefined;
    renderBlockDetails(heightVal, raw);
  } catch (error) {
    console.error('Error loading block by hash:', error);
    if (window.__showBlockError) {
      window.__showBlockError(error.message || 'Error loading block details');
    } else {
      alert('Error loading block details: ' + (error.message||'Unknown error'));
    }
  }
}

async function viewTx(txid) {
  try {
    console.log('Loading tx details for txid:', txid);
    const tx = await fetchJson(`/tx/${txid}`);
    const outputIrm = tx.output_value ? (tx.output_value / 1e8).toFixed(8) : '0.00000000';
    const rows = [
      ['TxID', tx.txid ?? txid],
      ['Block Height', String(tx.height ?? 'N/A')],
      ['Block Hash', tx.block_hash ?? 'N/A'],
      ['Index', String(tx.index ?? 'N/A')],
      ['Inputs', String(tx.inputs ?? 'N/A')],
      ['Outputs', String(tx.outputs ?? 'N/A')],
      ['Output Value', outputIrm + ' IRM'],
      ['Coinbase', String(tx.is_coinbase ?? false)],
      ['Raw Tx', tx.tx_hex ?? 'N/A']
    ];
    if (window.__showBlockModal) {
      window.__showBlockModal(rowsToHtml(rows));
    } else {
      alert(`Tx ${txid}
Height: ${tx.height ?? 'N/A'}`);
    }
  } catch (error) {
    console.error('Error loading tx:', error);
    if (window.__showBlockError) {
      window.__showBlockError(error.message || 'Error loading transaction');
    } else {
      alert('Error loading transaction: ' + (error.message||'Unknown error'));
    }
  }
}

async function viewAddress(address) {
  try {
    console.log('Loading address details:', address);
    const payload = await fetchJson(`/address/${address}`);
    const balance = payload.balance || {};
    const utxos = (payload.utxos && payload.utxos.utxos) ? payload.utxos.utxos : [];
    const history = (payload.history && payload.history.txs) ? payload.history.txs : [];
    const balIrm = balance.balance ? (balance.balance / 1e8).toFixed(8) : '0.00000000';
    const minedIrm = balance.mined_balance ? (balance.mined_balance / 1e8).toFixed(8) : '0.00000000';

    const rows = [
      ['Address', address],
      ['Balance', balIrm + ' IRM'],
      ['Mined Balance', minedIrm + ' IRM'],
      ['UTXOs', String(balance.utxo_count ?? utxos.length)],
      ['Mined Blocks', String(balance.mined_blocks ?? '0')],
      ['Height', String(balance.height ?? 'N/A')]
    ];

    let extra = '';
    if (history.length > 0) {
      const recent = history.slice(0, 6).map((tx) => {
        const netIrm = (tx.net ?? 0) / 1e8;
        const dir = netIrm >= 0 ? '+' : '';
        return '<div style="font-family:monospace; font-size:12px; margin:6px 0;">' +
          (tx.txid ?? 'N/A') + ' (' + dir + netIrm.toFixed(8) + ' IRM)</div>';
      }).join('');
      extra = '<div style="margin-top:12px; color:rgba(255,255,255,0.7);">Recent Activity</div>' + recent;
    }

    if (window.__showBlockModal) {
      window.__showBlockModal(rowsToHtml(rows) + extra);
    } else {
      alert(`Address ${address}
Balance: ${balIrm} IRM`);
    }
  } catch (error) {
    console.error('Error loading address:', error);
    if (window.__showBlockError) {
      window.__showBlockError(error.message || 'Error loading address');
    } else {
      alert('Error loading address: ' + (error.message||'Unknown error'));
    }
  }
}

// Search block

function searchBlock() {
  const input = document.getElementById('block-search-input');
  const query = input ? input.value.trim() : '';
  if (!query) return;
  if (/^\d+$/.test(query)) return viewBlock(parseInt(query, 10));
  if (/^[0-9a-fA-F]{64}$/.test(query)) return viewBlockByHash(query.toLowerCase());
  alert('Enter a block height or 64-character hash.');
}

function searchTx() {
  const input = document.getElementById('tx-search-input');
  const query = input ? input.value.trim() : '';
  if (!query) return;
  if (!/^[0-9a-fA-F]{64}$/.test(query)) {
    alert('Enter a 64-character transaction ID.');
    return;
  }
  viewTx(query.toLowerCase());
}

function searchAddress() {
  const input = document.getElementById('address-search-input');
  const query = input ? input.value.trim() : '';
  if (!query) return;
  viewAddress(query);
}

// Load blocks list - fetch all available blocks
async function loadBlocksPage(limit = 30, startHeight = null, append = false) {
  try {
    console.log('Loading blocks...');
    
    // First, get the current height from stats
    const statsData = await fetchJson('/stats');
    const currentHeight = statsData.height || 0;
    console.log('Current blockchain height:', currentHeight);
    
    // Get blocks from the /blocks endpoint
    let path = `/blocks?limit=${Math.min(limit, currentHeight + 1)}`;
    if (startHeight !== null && startHeight !== undefined) {
      path += `&start=${startHeight}`;
    }
    const data = await fetchJson(path);
    const list = data.blocks ?? data ?? [];
    console.log('Blocks from /blocks endpoint:', Array.isArray(list) ? list.length : 0);
    
    // Start with blocks from /blocks endpoint
    const allBlocks = [...list];
    
    // Try to fetch individual blocks that might be missing
    const missingHeights = [];
    
    // Check for missing blocks 0-3 (genesis and early blocks)
    for (let h = 0; h <= Math.min(3, currentHeight); h++) {
      if (!allBlocks.some(b => (b.height ?? 0) === h)) {
        missingHeights.push(h);
      }
    }
    
    console.log('Missing block heights to fetch individually:', missingHeights);
    
    // Fetch missing blocks individually
    for (const height of missingHeights) {
      try {
        console.log(`Fetching individual block ${height}...`);
        const blockData = await fetchJson(`/block/${height}`);
        console.log(`Block ${height} response:`, blockData);
        
        if (blockData && blockData.block && !blockData.error) {
          allBlocks.push(blockData.block);
          console.log(`Successfully fetched block ${height}:`, blockData.block.hash);
        } else if (blockData && !blockData.error) {
          allBlocks.push(blockData);
          console.log(`Successfully fetched block ${height} (flat structure):`, blockData.hash);
        } else {
          console.log(`Block ${height} not found:`, blockData.error || 'Unknown error');
        }
      } catch (error) {
        console.log(`Failed to fetch block ${height}:`, error.message);
      }
    }
    
    console.log('Total blocks after individual fetches:', allBlocks.length);
    
    if (Array.isArray(allBlocks) && allBlocks.length > 0) {
      const heights = allBlocks.map(b => b.height ?? 0).sort((a,b) => a - b);
      console.log('Available block heights:', heights);
      const missingBlocks = Array.from({length: currentHeight + 1}, (_, i) => i).filter(h => !heights.includes(h));
      console.log('Still missing blocks:', missingBlocks);
    }

    const blocksList = document.getElementById('blocks-list');
    if (!blocksList) { console.error('blocks-list element not found'); return; }

    if (Array.isArray(allBlocks) && allBlocks.length > 0) {
      // Sort by height descending (newest first for display)
      const sortedBlocks = allBlocks.slice().sort((a,b) => (b.height ?? 0) - (a.height ?? 0));

      if (sortedBlocks.length > 0) {
        const minH = sortedBlocks.reduce((m, b) => Math.min(m, (b.height ?? 0)), Number.POSITIVE_INFINITY);
        __blocksCursor = (isFinite(minH) && minH > 0) ? (minH - 1) : 0;
      }

      
      const html = sortedBlocks.map((blk) => {
        const header = getHeader(blk);
        const hash = header.hash ?? blk.hash ?? blk.block_hash ?? 'N/A';
        const time = header.time ?? header.timestamp ?? blk.time ?? blk.timestamp ?? 0;
        const rewardSats = blk.reward ?? blk.subsidy ?? blk.block_reward ?? 0;
        const heightVal = blk.height ?? 0;
        const reward = rewardSats ? (rewardSats / 1e8).toFixed(2) : blockRewardIrm(heightVal).toFixed(2);
        const txs = Array.isArray(blk.tx_hex) ? blk.tx_hex.length : (blk.transactions ?? blk.tx_count ?? 0);
        const miner = blk.miner_address ?? blk.miner ?? 'N/A';
return `
<div class="x-block" onclick="viewBlock(${heightVal})">
  <div class="x-block-top">
    <div class="x-block-h">Block ${heightVal}</div>
    <div class="x-block-time">${formatTime(time)}</div>
  </div>
  <div class="x-block-hash">${hash}</div>
  <div class="x-block-meta">
    <span>Reward: ${reward} IRM</span>
    <span>Tx: ${txs}</span>
    <span>Miner: <span class="x-block-hash">${miner}</span></span>
  </div>
</div>`;
      }).join('');

      if (append) {
        blocksList.insertAdjacentHTML('beforeend', html);
      } else {
        blocksList.innerHTML = html;
      }
      
      // Warn only for gaps within the displayed window.
      const windowSize = Math.min(limit, currentHeight + 1);
      const windowStart = Math.max(0, currentHeight - windowSize + 1);
      const expectedWindow = Array.from({length: windowSize}, (_, i) => windowStart + i);
      const missingWindow = expectedWindow.filter(h => !allBlocks.some(b => (b.height ?? 0) === h));
      if (missingWindow.length > 0) {
        const preview = missingWindow.slice(0, 20).join(", ");
        const suffix = missingWindow.length > 20 ? " … (+" + (missingWindow.length - 20) + " more)" : "";
        blocksList.innerHTML +=
          "<div style=\"background: rgba(255,165,0,0.1); padding: 15px; margin-top: 20px; border-radius: 8px; border-left: 4px solid #ffa500;\">" +
          "<div style=\"color: #ffa500; font-weight: bold; margin-bottom: 10px;\">⚠️ Missing Blocks</div>" +
          "<div style=\"color: rgba(255,255,255,0.8); font-size: 14px;\">Missing blocks in the latest window (" + windowStart + "-" + currentHeight + "): " + preview + suffix + "</div>" +
          "<div style=\"color: rgba(255,255,255,0.6); font-size: 12px; margin-top: 5px;\">This may be due to API pagination or indexing delay.</div>" +
          "</div>";
      }
    } else {
      blocksList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">No blocks found</p>';
    }
  } catch (error) {
    console.error('Error loading blocks:', error);
    const blocksList = document.getElementById('blocks-list');
    if (blocksList) blocksList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">Error loading blocks. Please try again later.</p>';
  }
}

// Initialize function


function ensureLoadMoreButton() {
  const list = document.getElementById('blocks-list');
  if (!list) return;
  if (document.getElementById('load-more-blocks')) return;

  const btn = document.createElement('button');
  btn.id = 'load-more-blocks';
  btn.className = 'search-btn';
  btn.style.width = '100%';
  btn.style.marginTop = '12px';
  btn.textContent = 'Load older blocks';
  btn.addEventListener('click', () => loadMoreBlocks());
  const parent = list.parentElement || list;
  parent.appendChild(btn);
}

async function loadMoreBlocks() {
  if (__blocksLoading) return;
  if (__blocksCursor === null) return;
  if (__blocksCursor <= 0) return;
  __blocksLoading = true;
  try {
    await loadBlocksPage(50, __blocksCursor, true);
  } finally {
    __blocksLoading = false;
  }
}
function initExplorer() {
  console.log('Initializing Explorer...');
  loadStats();
  loadMiningMetrics();
  loadBlocksPage(30, null, false);
  ensureLoadMoreButton();
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initExplorer);
} else {
  initExplorer();
}

// Auto-refresh every 30 seconds
setInterval(() => {
  console.log('Auto-refreshing...');
  loadStats();
  loadMiningMetrics();
  loadBlocksPage(30, null, false);
}, 30000);

// Format timestamp to readable date
function formatTime(timestamp) {
  const date = new Date((timestamp ?? 0) * 1000);
  return isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

// Irium Block Explorer JavaScript with CORS Proxy
const API_BASE = 'https://api.iriumlabs.org/api';
const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

console.log('Explorer JS loaded');

function pick(obj, keys, def = undefined) {
  for (const k of keys) if (obj != null && obj[k] != null) return obj[k];
  return def;
}

async function fetchJson(path) {
  const url = CORS_PROXY + encodeURIComponent(`${API_BASE}${path}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
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
  } catch (error) {
    console.error('Error loading stats:', error);
    // Fallback: derive basics from blocks endpoint
    try {
      const blocksData = await fetchJson('/blocks?limit=10');
      const list = blocksData.blocks ?? blocksData ?? [];
      const height = Array.isArray(list) && list.length ? (list[0].height ?? 0) : 0;
      const total = blocksData.total ?? (Array.isArray(list) ? list.length : 0);
      const estSupplyIrm = total * 50; // rough estimate, improves UX if stats is down
      const heightEl = document.getElementById('current-height');
      const blocksEl = document.getElementById('total-blocks');
      const supplyEl = document.getElementById('total-supply');
      if (heightEl) heightEl.textContent = String(height);
      if (blocksEl) blocksEl.textContent = String(total);
      if (supplyEl) supplyEl.textContent = estSupplyIrm.toFixed(2) + ' IRM';
    } catch (e2) {
      console.error('Fallback stats failed:', e2);
      for (const id of ['current-height','total-blocks','total-supply']) {
        const el = document.getElementById(id); if (el) el.textContent = 'Error';
      }
    }
  }
}

// View block details
async function viewBlock(height) {
  try {
    console.log('Loading block details for height:', height);
    const raw = await fetchJson(`/block/${height}`);
    const b = (raw && raw.block) ? raw.block : raw || {};
    const hash = b.hash ?? b.block_hash ?? 'N/A';
    const time = b.time ?? b.timestamp ?? 0;
    const txs  = b.transactions ?? b.tx_count ?? 0;
    const rewardSats = b.reward ?? b.subsidy ?? b.block_reward ?? 0;
    const rewardIrm = rewardSats ? (rewardSats/1e8).toFixed(2) : '0.00';
    const prev = b.prev_hash ?? b.previous_block ?? 'N/A';
    const mr   = b.merkle_root ?? 'N/A';
    const nonce = b.nonce ?? 'N/A';
    const bits  = b.bits ?? 'N/A';
    const miner = b.miner_address ?? b.miner ?? 'N/A';

    const rows = [
      ['Height', String(height)],
      ['Hash', hash],
      ['Prev Hash', prev],
      ['Merkle Root', mr],
      ['Time', formatTime(time)],
      ['Reward', rewardIrm + ' IRM'],
      ['Transactions', String(txs)],
      ['Bits', String(bits)],
      ['Nonce', String(nonce)],
      ['Miner', miner]
    ].map(([k,v])=>(
      '<div style="display:flex; gap:12px; margin:6px 0;">' +
      '<div style="width:130px; color:rgba(255,255,255,0.7)">' + k + '</div>' +
      '<div style="font-family:monospace; word-break:break-all;">' + v + '</div>' +
      '</div>'
    )).join('');

    if (window.__showBlockModal) {
      window.__showBlockModal(rows);
    } else {
      alert(`Block ${height}
Hash: ${hash}
Reward: ${rewardIrm} IRM`);
    }
  } catch (error) {
    console.error('Error loading block:', error);
    if (window.__showBlockError) {
      window.__showBlockError(error.message || 'Error loading block details');
    } else {
      alert('Error loading block details: ' + (error.message||'Unknown error'));
    }
  }
}

// Search block
function searchBlock() {
  const query = document.getElementById('search-input').value.trim();
  if (!query) return;
  if (/^\d+$/.test(query)) viewBlock(parseInt(query));
  else alert('Hash search coming soon!');
}

// Load blocks list
async function loadBlocks(limit = 20) {
  try {
    console.log('Loading blocks...');
    const data = await fetchJson(`/blocks?limit=${limit}`);
    const list = data.blocks ?? data;
    console.log('Blocks loaded:', Array.isArray(list) ? list.length : 0);

    const blocksList = document.getElementById('blocks-list');
    if (!blocksList) { console.error('blocks-list element not found'); return; }

    if (Array.isArray(list) && list.length > 0) {
      blocksList.innerHTML = list.map((blk) => {
        const hash = pick(blk, ['hash','block_hash'], 'N/A');
        const time = pick(blk, ['time','timestamp'], 0);
        const rewardSats = pick(blk, ['reward','subsidy','block_reward'], 0);
        const reward = rewardSats ? (rewardSats / 1e8).toFixed(2) : '0.00';
        const txs = pick(blk, ['transactions','tx_count'], 0);
        const height = pick(blk, ['height'], 0);
        return `
<div style="background: rgba(0,0,0,0.3); padding: 20px; margin-bottom: 15px; border-radius: 8px; cursor: pointer; transition: transform 0.2s;"
     onclick="viewBlock(${height})" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
  <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
    <span style="font-size: 18px; font-weight: bold; color: #0066cc;">Block ${height}</span>
    <span style="color: rgba(255,255,255,0.7);">${formatTime(time)}</span>
  </div>
  <div style="font-family: monospace; font-size: 14px; color: rgba(255,255,255,0.9); word-break: break-all; margin-bottom: 10px;">${hash}</div>
  <div style="display: flex; gap: 20px; color: rgba(255,255,255,0.7); font-size: 14px;">
    <span>Reward: ${reward} IRM</span>
    <span>Transactions: ${txs}</span>
  </div>
</div>`;
      }).join('');
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
function initExplorer() {
  console.log('Initializing Explorer...');
  loadStats();
  loadBlocks();
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
  loadBlocks();
}, 30000);

// Format timestamp to readable date
function formatTime(timestamp) {
  const date = new Date((timestamp ?? 0) * 1000);
  return isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

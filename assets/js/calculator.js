// Irium Mining Calculator
const BLOCK_REWARD = 50; // IRM per block
const BLOCK_TIME = 600; // seconds (10 minutes)
const DEFAULT_API_BASE = 'https://api.iriumlabs.org/api';
const CORS_PROXIES = ['', 'https://api.allorigins.win/raw?url='];

function getApiBases() {
  const bases = [];
  if (window.IRIUM_API_BASE) bases.push(window.IRIUM_API_BASE);
  const docBase = document.documentElement.dataset.apiBase || (document.body && document.body.dataset && document.body.dataset.apiBase);
  if (docBase) bases.push(docBase);
  if (location && location.origin) bases.push(location.origin + '/api');
  bases.push(DEFAULT_API_BASE);
  const deduped = [];
  for (const base of bases) {
    const norm = base.replace(/\/+$/, '');
    if (!deduped.includes(norm)) deduped.push(norm);
  }
  return deduped;
}

async function fetchJson(path) {
  const bases = getApiBases();
  const errors = [];
  for (const base of bases) {
    const url = base + path;
    for (const proxy of CORS_PROXIES) {
      const target = proxy ? proxy + encodeURIComponent(url) : url;
      try {
        const res = await fetch(target, { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } catch (err) {
        errors.push(err.message || String(err));
      }
    }
  }
  throw new Error(errors[0] || 'Fetch failed');
}

async function loadNetworkStats() {
  try {
    const data = await fetchJson('/stats');
    const hashrate = data.network_hashrate || data.hashrate || 1000000;
    document.getElementById('network-hashrate').value = String(hashrate);
  } catch (error) {
    console.error('Error loading network stats:', error);
    document.getElementById('network-hashrate').value = '1000000';
  }
}
function calculate() {
    const yourHashrate = parseFloat(document.getElementById('hashrate').value);
    const networkHashrate = parseFloat(document.getElementById('network-hashrate').value) || 1000000;
    
    if (!yourHashrate || yourHashrate <= 0) {
        alert('Please enter your hashrate');
        return;
    }
    
    const blocksPerDay = (24 * 60 * 60) / BLOCK_TIME; // ~144 blocks/day
    const yourShare = yourHashrate / networkHashrate;
    const yourBlocksPerDay = blocksPerDay * yourShare;
    const yourIRMPerDay = yourBlocksPerDay * BLOCK_REWARD;
    const yourIRMPerMonth = yourIRMPerDay * 30;
    
    document.getElementById('blocks-per-day').textContent = yourBlocksPerDay.toFixed(4);
    document.getElementById('irm-per-day').textContent = yourIRMPerDay.toFixed(2) + ' IRM';
    document.getElementById('irm-per-month').textContent = yourIRMPerMonth.toFixed(2) + ' IRM';
}

loadNetworkStats();

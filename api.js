// API Configuration - Using direct IP without CORS
const API_BASE = 'http://207.244.247.86:8082/api';
const UPDATE_INTERVAL = 10000;

// Fetch blockchain stats with error handling
async function fetchBlockchainStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`, {
            mode: 'cors',
            headers: { 'Accept': 'application/json' }
        });
        
        if (!response.ok) throw new Error('API unavailable');
        const data = await response.json();
        
        // Update all stat elements
        const updates = [
            { id: 'liveHeight', value: data.height || '0' },
            { id: 'exp-height', value: data.height || '0' },
            { id: 'liveSupply', value: `${((data.issued || 0) / 100000000).toFixed(0)} IRM` },
            { id: 'exp-supply', value: `${((data.issued || 0) / 100000000).toFixed(2)} IRM` },
            { id: 'liveDiff', value: parseFloat(data.difficulty || 1).toFixed(2) },
            { id: 'exp-difficulty', value: parseFloat(data.difficulty || 1).toFixed(2) }
        ];
        
        updates.forEach(({id, value}) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });
        
    } catch (error) {
        console.log('Stats API temporarily unavailable:', error);
        // Set fallback values instead of error
        const fallbacks = [
            { id: 'liveHeight', value: 'Syncing...' },
            { id: 'liveSupply', value: 'Loading...' },
            { id: 'liveDiff', value: '1.00' }
        ];
        fallbacks.forEach(({id, value}) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        });
    }
}

// Fetch latest blocks
async function fetchLatestBlocks() {
    try {
        const response = await fetch(`${API_BASE}/latest`, {
            mode: 'cors',
            headers: { 'Accept': 'application/json' }
        });
        
        if (!response.ok) throw new Error('API unavailable');
        const blocks = await response.json();
        
        const container = document.getElementById('latestBlocksPreview') || document.getElementById('blocksTable');
        if (!container || !blocks || blocks.length === 0) {
            if (container) container.innerHTML = '<div class="info-message">Blockchain is initializing. Blocks will appear as they are mined.</div>';
            return;
        }
        
        const blocksHTML = blocks.slice(0, 5).map(block => `
            <div class="block-item">
                <div class="block-header">
                    <span class="block-height">Block #${block.height}</span>
                    <span class="block-time">${timeAgo(block.timestamp)}</span>
                </div>
                <div class="block-hash">
                    <span class="hash-label">Hash:</span>
                    <code class="hash">${block.hash}</code>
                </div>
                <div class="block-meta">
                    <span>Transactions: ${block.tx_count || 1}</span>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = blocksHTML;
    } catch (error) {
        console.log('Blocks API temporarily unavailable');
        const container = document.getElementById('latestBlocksPreview') || document.getElementById('blocksTable');
        if (container) {
            container.innerHTML = '<div class="info-message">Connecting to blockchain node...</div>';
        }
    }
}

// Fetch mempool
async function fetchMempool() {
    try {
        const response = await fetch(`${API_BASE}/mempool`, {
            mode: 'cors',
            headers: { 'Accept': 'application/json' }
        });
        
        if (!response.ok) throw new Error('API unavailable');
        const mempool = await response.json();
        
        if (document.getElementById('exp-mempool')) {
            document.getElementById('exp-mempool').textContent = mempool.length || '0';
        }
        
        const container = document.getElementById('mempoolTable');
        if (!container) return;
        
        if (mempool && mempool.length > 0) {
            const mempoolHTML = mempool.slice(0, 10).map(tx => `
                <div class="mempool-item">
                    <div class="tx-hash"><code>${tx.txid}</code></div>
                    <div class="tx-meta">
                        <span>Fee: ${(tx.fee / 100000000).toFixed(8)} IRM</span>
                        <span>Size: ${tx.size} bytes</span>
                    </div>
                </div>
            `).join('');
            container.innerHTML = mempoolHTML;
        } else {
            container.innerHTML = '<div class="info-message">Mempool is empty - no pending transactions</div>';
        }
    } catch (error) {
        console.log('Mempool API temporarily unavailable');
    }
}

function timeAgo(timestamp) {
    const seconds = Math.floor(Date.now() / 1000 - timestamp);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

document.addEventListener('DOMContentLoaded', () => {
    fetchBlockchainStats();
    fetchLatestBlocks();
    if (document.getElementById('mempoolTable')) fetchMempool();
    
    setInterval(fetchBlockchainStats, UPDATE_INTERVAL);
    setInterval(fetchLatestBlocks, UPDATE_INTERVAL);
    if (document.getElementById('mempoolTable')) setInterval(fetchMempool, UPDATE_INTERVAL);
});

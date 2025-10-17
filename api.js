// API Configuration
const API_BASE = 'http://207.244.247.86:8082/api';
const UPDATE_INTERVAL = 10000; // 10 seconds

// Fetch blockchain stats
async function fetchBlockchainStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        if (!response.ok) throw new Error('API unavailable');
        
        const data = await response.json();
        
        // Update live stats
        if (document.getElementById('liveHeight')) {
            document.getElementById('liveHeight').textContent = data.height || '0';
        }
        
        if (document.getElementById('liveSupply')) {
            const supply = (data.issued / 100000000).toFixed(0);
            document.getElementById('liveSupply').textContent = `${supply.toLocaleString()} IRM`;
        }
        
        if (document.getElementById('liveDiff')) {
            const diff = parseFloat(data.difficulty || 1).toFixed(2);
            document.getElementById('liveDiff').textContent = diff;
        }
        
        // Update explorer page stats
        if (document.getElementById('exp-height')) {
            document.getElementById('exp-height').textContent = data.height || '0';
        }
        
        if (document.getElementById('exp-supply')) {
            const supply = (data.issued / 100000000).toFixed(2);
            document.getElementById('exp-supply').textContent = `${supply} IRM`;
        }
        
        if (document.getElementById('exp-difficulty')) {
            document.getElementById('exp-difficulty').textContent = parseFloat(data.difficulty || 1).toFixed(2);
        }
        
    } catch (error) {
        console.error('Error fetching stats:', error);
        // Fallback values
        if (document.getElementById('liveHeight')) {
            document.getElementById('liveHeight').textContent = '-';
        }
    }
}

// Fetch latest blocks
async function fetchLatestBlocks() {
    try {
        const response = await fetch(`${API_BASE}/latest`);
        if (!response.ok) throw new Error('API unavailable');
        
        const blocks = await response.json();
        
        const container = document.getElementById('latestBlocksPreview') || document.getElementById('blocksTable');
        if (!container) return;
        
        if (blocks && blocks.length > 0) {
            const blocksHTML = blocks.slice(0, 5).map(block => `
                <div class="block-item">
                    <div class="block-header">
                        <span class="block-height">Block #${block.height}</span>
                        <span class="block-time">${timeAgo(block.timestamp)}</span>
                    </div>
                    <div class="block-hash">
                        <span class="hash-label">Hash:</span>
                        <code class="hash">${block.hash.substring(0, 16)}...${block.hash.substring(block.hash.length - 8)}</code>
                    </div>
                    <div class="block-meta">
                        <span>Txs: ${block.tx_count || 1}</span>
                        <span>Size: ${(block.size / 1024).toFixed(2)} KB</span>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = blocksHTML;
        } else {
            container.innerHTML = '<div class="no-data">No blocks available</div>';
        }
    } catch (error) {
        console.error('Error fetching blocks:', error);
        const container = document.getElementById('latestBlocksPreview') || document.getElementById('blocksTable');
        if (container) {
            container.innerHTML = '<div class="error-state">Unable to load blocks. Explorer API may be offline.</div>';
        }
    }
}

// Fetch mempool
async function fetchMempool() {
    try {
        const response = await fetch(`${API_BASE}/mempool`);
        if (!response.ok) throw new Error('API unavailable');
        
        const mempool = await response.json();
        
        const container = document.getElementById('mempoolTable');
        if (!container) return;
        
        if (document.getElementById('exp-mempool')) {
            document.getElementById('exp-mempool').textContent = mempool.length || '0';
        }
        
        if (mempool && mempool.length > 0) {
            const mempoolHTML = mempool.slice(0, 10).map(tx => `
                <div class="mempool-item">
                    <div class="tx-hash">
                        <code>${tx.txid.substring(0, 16)}...${tx.txid.substring(tx.txid.length - 8)}</code>
                    </div>
                    <div class="tx-meta">
                        <span>Fee: ${(tx.fee / 100000000).toFixed(8)} IRM</span>
                        <span>Size: ${tx.size} bytes</span>
                    </div>
                </div>
            `).join('');
            
            container.innerHTML = mempoolHTML;
        } else {
            container.innerHTML = '<div class="no-data">Mempool is empty</div>';
        }
    } catch (error) {
        console.error('Error fetching mempool:', error);
    }
}

// Time ago helper
function timeAgo(timestamp) {
    const seconds = Math.floor(Date.now() / 1000 - timestamp);
    
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    fetchBlockchainStats();
    fetchLatestBlocks();
    if (document.getElementById('mempoolTable')) {
        fetchMempool();
    }
    
    // Auto-update
    setInterval(fetchBlockchainStats, UPDATE_INTERVAL);
    setInterval(fetchLatestBlocks, UPDATE_INTERVAL);
    if (document.getElementById('mempoolTable')) {
        setInterval(fetchMempool, UPDATE_INTERVAL);
    }
});

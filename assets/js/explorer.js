// Irium Block Explorer JavaScript
const API_BASE = 'https://api.iriumlabs.org/api';

console.log('Explorer JS loaded');

// Load statistics
async function loadStats() {
    try {
        console.log('Loading stats...');
        const response = await fetch(`${API_BASE}/stats`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Stats loaded:', data);
        
        const heightEl = document.getElementById('current-height');
        const blocksEl = document.getElementById('total-blocks');
        const supplyEl = document.getElementById('total-supply');
        
        if (heightEl) heightEl.textContent = data.height || '0';
        if (blocksEl) blocksEl.textContent = data.total_blocks || '0';
        if (supplyEl) supplyEl.textContent = (data.supply_irm || 0).toFixed(2) + ' IRM';
        
        return data;
    } catch (error) {
        console.error('Error loading stats:', error);
        const heightEl = document.getElementById('current-height');
        const blocksEl = document.getElementById('total-blocks');
        const supplyEl = document.getElementById('total-supply');
        
        if (heightEl) heightEl.textContent = 'Error';
        if (blocksEl) blocksEl.textContent = 'Error';
        if (supplyEl) supplyEl.textContent = 'Error';
        return null;
    }
}

// Format timestamp
// View block details
async function viewBlock(height) {
    try {
        const response = await fetch(`${API_BASE}/block/${height}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        alert(`Block ${height}\nHash: ${data.hash}\nReward: ${(data.reward / 100000000).toFixed(2)} IRM`);
    } catch (error) {
        console.error('Error loading block:', error);
        alert('Error loading block details');
    }
}

// Search block
function searchBlock() {
    const query = document.getElementById('search-input').value.trim();
    if (!query) return;
    
    if (/^\d+$/.test(query)) {
        viewBlock(parseInt(query));
    } else {
        alert('Hash search coming soon!');
    }
}

// Load blocks list
async function loadBlocks(limit = 20) {
    try {
        console.log('Loading blocks...');
        const response = await fetch(`${API_BASE}/blocks?limit=${limit}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        console.log('Blocks loaded:', data.blocks ? data.blocks.length : 0, 'blocks');
        
        const blocksList = document.getElementById('blocks-list');
        if (!blocksList) {
            console.error('blocks-list element not found');
            return;
        }
        
        if (data.blocks && data.blocks.length > 0) {
            blocksList.innerHTML = data.blocks.map(block => `
                <div style="background: rgba(0,0,0,0.3); padding: 20px; margin-bottom: 15px; border-radius: 8px; cursor: pointer; transition: transform 0.2s;" onclick="viewBlock(${block.height})" onmouseover="this.style.transform='translateY(-2px)'" onmouseout="this.style.transform='translateY(0)'">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                        <span style="font-size: 18px; font-weight: bold; color: #0066cc;">Block ${block.height}</span>
                        <span style="color: rgba(255,255,255,0.7);">${formatTime(block.time)}</span>
                    </div>
                    <div style="font-family: monospace; font-size: 14px; color: rgba(255,255,255,0.9); word-break: break-all; margin-bottom: 10px;">${block.hash}</div>
                    <div style="display: flex; gap: 20px; color: rgba(255,255,255,0.7); font-size: 14px;">
                        <span>Reward: ${(block.reward / 100000000).toFixed(2)} IRM</span>
                        <span>Transactions: ${block.transactions}</span>
                    </div>
                </div>
            `).join('');
        } else {
            blocksList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">No blocks found</p>';
        }
    } catch (error) {
        console.error('Error loading blocks:', error);
        const blocksList = document.getElementById('blocks-list');
        if (blocksList) {
            blocksList.innerHTML = '<p style="color: rgba(255,255,255,0.7);">Error loading blocks. Please try again later.</p>';
        }
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
    // DOM already loaded
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
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

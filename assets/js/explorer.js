// Irium Block Explorer JavaScript
const API_BASE = 'https://api.iriumlabs.org/api';

// Load statistics
async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        const data = await response.json();
        
        document.getElementById('current-height').textContent = data.height;
        document.getElementById('total-blocks').textContent = data.total_blocks;
        document.getElementById('total-supply').textContent = data.supply_irm.toFixed(2) + ' IRM';
        
        return data;
    } catch (error) {
        console.error('Error loading stats:', error);
        return null;
    }
}

// Load blocks list
async function loadBlocks(limit = 20) {
    try {
        const response = await fetch(`${API_BASE}/blocks?limit=${limit}`);
        const data = await response.json();
        
        const blocksList = document.getElementById('blocks-list');
        if (data.blocks && data.blocks.length > 0) {
            blocksList.innerHTML = data.blocks.map(block => `
                <div class="block-card" onclick="viewBlock(${block.height})">
                    <div class="block-header">
                        <span class="block-height">Block ${block.height}</span>
                        <span class="block-time">${formatTime(block.time)}</span>
                    </div>
                    <div class="block-hash">${block.hash}</div>
                    <div class="block-details">
                        <span>Reward: ${(block.reward / 100000000).toFixed(2)} IRM</span>
                        <span>Transactions: ${block.transactions}</span>
                    </div>
                </div>
            `).join('');
        } else {
            blocksList.innerHTML = '<p>No blocks found</p>';
        }
    } catch (error) {
        console.error('Error loading blocks:', error);
        document.getElementById('blocks-list').innerHTML = '<p>Error loading blocks</p>';
    }
}

// View block details
async function viewBlock(height) {
    try {
        const response = await fetch(`${API_BASE}/block/${height}`);
        const data = await response.json();
        
        // Show block details modal or navigate to detail page
        alert(`Block ${height}\nHash: ${data.hash}\nReward: ${(data.reward / 100000000).toFixed(2)} IRM`);
    } catch (error) {
        console.error('Error loading block:', error);
    }
}

// Search block
function searchBlock() {
    const query = document.getElementById('search-input').value.trim();
    if (!query) return;
    
    // Try as height first
    if (/^\d+$/.test(query)) {
        viewBlock(parseInt(query));
    } else {
        // Search by hash
        alert('Hash search coming soon!');
    }
}

// Format timestamp
function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

// Initialize
loadStats();
loadBlocks();

// Auto-refresh every 30 seconds
setInterval(() => {
    loadStats();
    loadBlocks();
}, 30000);

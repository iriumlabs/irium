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

// Format timestamp
function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

// View block details
async function viewBlock(height) {
    try {
        const response = await fetch(`${API_BASE}/block/${height}`);
        const data = await response.json();
        
        alert(`Block ${height}\nHash: ${data.hash}\nReward: ${(data.reward / 100000000).toFixed(2)} IRM`);
    } catch (error) {
        console.error('Error loading block:', error);
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
        const response = await fetch(`${API_BASE}/blocks?limit=${limit}`);
        const data = await response.json();
        
        const blocksList = document.getElementById('blocks-list');
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
        document.getElementById('blocks-list').innerHTML = '<p style="color: rgba(255,255,255,0.7);">Error loading blocks</p>';
    }
}

// Initialize
loadStats();
loadBlocks();

// Auto-refresh every 30 seconds
setInterval(() => {
    loadStats();
    loadBlocks();
}, 30000);

// Irium Network Dashboard JavaScript
const API_BASE = 'https://api.iriumlabs.org/api';

let blockTimeChart;

async function loadDashboard() {
    try {
        // Load stats
        const statsResponse = await fetch(`${API_BASE}/stats`);
        if (!statsResponse.ok) {
            throw new Error(`HTTP error! status: ${statsResponse.status}`);
        }
        const stats = await statsResponse.json();
        
        document.getElementById('network-height').textContent = stats.height || '0';
        document.getElementById('total-blocks').textContent = stats.total_blocks || '0';
        document.getElementById('total-supply').textContent = (stats.supply_irm || 0).toFixed(2) + ' IRM';
        
        // Load recent blocks for block time calculation
        const blocksResponse = await fetch(`${API_BASE}/blocks?limit=10`);
        if (!blocksResponse.ok) {
            throw new Error(`HTTP error! status: ${blocksResponse.status}`);
        }
        const blocks = await blocksResponse.json();
        
        if (blocks.blocks && blocks.blocks.length > 1) {
            const intervals = [];
            for (let i = 1; i < blocks.blocks.length; i++) {
                const interval = blocks.blocks[i].time - blocks.blocks[i-1].time;
                intervals.push(interval / 60); // Convert to minutes
            }
            const avgBlockTime = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            document.getElementById('block-time').textContent = avgBlockTime.toFixed(2) + ' minutes';
            
            updateChart(intervals);
        } else {
            document.getElementById('block-time').textContent = 'N/A';
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
        document.getElementById('network-height').textContent = 'Error';
        document.getElementById('total-blocks').textContent = 'Error';
        document.getElementById('total-supply').textContent = 'Error';
        document.getElementById('block-time').textContent = 'Error';
    }
}

function updateChart(intervals) {
    const ctx = document.getElementById('blockTimeChart');
    if (!ctx) {
        console.error('Chart canvas not found');
        return;
    }
    
    try {
        if (blockTimeChart) {
            blockTimeChart.destroy();
        }
        
        blockTimeChart = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: intervals.map((_, i) => `Block ${i}`),
                datasets: [{
                    label: 'Block Time (minutes)',
                    data: intervals,
                    borderColor: '#0066cc',
                    backgroundColor: 'rgba(0, 102, 204, 0.1)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error updating chart:', error);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        loadDashboard();
    });
} else {
    loadDashboard();
}

// Auto-refresh every 30 seconds
setInterval(() => {
    loadDashboard();
}, 30000);

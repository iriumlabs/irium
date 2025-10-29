// Irium Network Dashboard JavaScript
const API_BASE = 'https://api.iriumlabs.org/api';

let blockTimeChart;

async function loadDashboard() {
    const stats = await fetch(`${API_BASE}/stats`).then(r => r.json());
    
    document.getElementById('network-height').textContent = stats.height;
    document.getElementById('total-blocks').textContent = stats.total_blocks;
    document.getElementById('total-supply').textContent = stats.supply_irm.toFixed(2) + ' IRM';
    
    // Load recent blocks for block time calculation
    const blocks = await fetch(`${API_BASE}/blocks?limit=10`).then(r => r.json());
    if (blocks.blocks && blocks.blocks.length > 1) {
        const intervals = [];
        for (let i = 1; i < blocks.blocks.length; i++) {
            const interval = blocks.blocks[i].time - blocks.blocks[i-1].time;
            intervals.push(interval / 60); // Convert to minutes
        }
        const avgBlockTime = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        document.getElementById('block-time').textContent = avgBlockTime.toFixed(2) + ' minutes';
        
        updateChart(intervals);
    }
}

function updateChart(intervals) {
    const ctx = document.getElementById('blockTimeChart').getContext('2d');
    
    if (blockTimeChart) {
        blockTimeChart.destroy();
    }
    
    blockTimeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: intervals.map((_, i) => `Block ${i}`),
            datasets: [{
                label: 'Block Time (minutes)',
                data: intervals,
                borderColor: '#0066cc',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

loadDashboard();
setInterval(loadDashboard, 30000);

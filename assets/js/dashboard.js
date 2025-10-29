// Irium Network Dashboard JavaScript
const API_BASE = 'https://api.iriumlabs.org/api';

let blockTimeChart;

console.log('Dashboard JS loaded');

async function loadDashboard() {
    try {
        console.log('Loading dashboard data...');

        // Load stats
        const statsResponse = await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', `${API_BASE}/stats`, true);
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve({
                        ok: true,
                        json: () => Promise.resolve(JSON.parse(xhr.responseText))
                    });
                } else {
                    reject(new Error(`HTTP error! status: ${xhr.status}`));
                }
            };
            xhr.onerror = () => reject(new Error('Network error'));
            xhr.send();
        });
        
        const stats = await statsResponse.json();
        console.log('Stats loaded:', stats);

        const heightEl = document.getElementById('network-height');
        const blocksEl = document.getElementById('total-blocks');
        const supplyEl = document.getElementById('total-supply');

        if (heightEl) heightEl.textContent = stats.height || '0';
        if (blocksEl) blocksEl.textContent = stats.total_blocks || '0';
        if (supplyEl) supplyEl.textContent = (stats.supply_irm || 0).toFixed(2) + ' IRM';

        // Load recent blocks for block time calculation
        const blocksResponse = await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('GET', `${API_BASE}/blocks?limit=10`, true);
            xhr.onload = () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    resolve({
                        ok: true,
                        json: () => Promise.resolve(JSON.parse(xhr.responseText))
                    });
                } else {
                    reject(new Error(`HTTP error! status: ${xhr.status}`));
                }
            };
            xhr.onerror = () => reject(new Error('Network error'));
            xhr.send();
        });
        
        const blocks = await blocksResponse.json();
        console.log('Blocks loaded:', blocks.blocks ? blocks.blocks.length : 0, 'blocks');

        const blockTimeEl = document.getElementById('block-time');

        if (blocks.blocks && blocks.blocks.length > 1) {
            const intervals = [];
            for (let i = 1; i < blocks.blocks.length; i++) {
                const interval = blocks.blocks[i].time - blocks.blocks[i-1].time;
                intervals.push(interval / 60); // Convert to minutes
            }
            const avgBlockTime = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            if (blockTimeEl) blockTimeEl.textContent = avgBlockTime.toFixed(2) + ' minutes';

            updateChart(intervals);
        } else {
            if (blockTimeEl) blockTimeEl.textContent = 'N/A';
        }
    } catch (error) {
        console.error('Error loading dashboard:', error);
        const heightEl = document.getElementById('network-height');
        const blocksEl = document.getElementById('total-blocks');
        const supplyEl = document.getElementById('total-supply');
        const blockTimeEl = document.getElementById('block-time');

        if (heightEl) heightEl.textContent = 'Error';
        if (blocksEl) blocksEl.textContent = 'Error';
        if (supplyEl) supplyEl.textContent = 'Error';
        if (blockTimeEl) blockTimeEl.textContent = 'Error';
    }
}

function updateChart(intervals) {
    const ctx = document.getElementById('blockTimeChart');
    if (!ctx) {
        console.error('Chart canvas not found');
        return;
    }

    try {
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }

        if (blockTimeChart) {
            blockTimeChart.destroy();
        }

        blockTimeChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: intervals.map((_, i) => `Block ${i + 1}`),
                datasets: [{
                    label: 'Block Time (minutes)',
                    data: intervals,
                    borderColor: '#0066cc',
                    backgroundColor: 'rgba(0, 102, 204, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: {
                            color: 'rgba(255,255,255,0.8)'
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: 'rgba(255,255,255,0.7)'
                        },
                        grid: {
                            color: 'rgba(255,255,255,0.1)'
                        }
                    },
                    x: {
                        ticks: {
                            color: 'rgba(255,255,255,0.7)'
                        },
                        grid: {
                            color: 'rgba(255,255,255,0.1)'
                        }
                    }
                }
            }
        });

        console.log('Chart updated successfully');
    } catch (error) {
        console.error('Error updating chart:', error);
    }
}

// Initialize function
function initDashboard() {
    console.log('Initializing Dashboard...');
    loadDashboard();
}

// Wait for Chart.js to load if needed
function waitForChart() {
    if (typeof Chart !== 'undefined') {
        initDashboard();
    } else {
        console.log('Waiting for Chart.js...');
        setTimeout(waitForChart, 100);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitForChart);
} else {
    waitForChart();
}

// Auto-refresh every 30 seconds
setInterval(() => {
    console.log('Auto-refreshing dashboard...');
    loadDashboard();
}, 30000);

// Format timestamp to readable date
function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
}

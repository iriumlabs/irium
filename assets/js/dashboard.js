// Irium Network Dashboard JavaScript with CORS Proxy
const API_BASE = 'https://api.iriumlabs.org/api';
const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

let blockTimeChart;

console.log('Dashboard JS loaded');

async function loadDashboard() {
  try {
    console.log('Loading dashboard data...');
    
    // Load stats
    const statsProxyUrl = CORS_PROXY + encodeURIComponent(`${API_BASE}/stats`);
    const statsResponse = await fetch(statsProxyUrl);
    if (!statsResponse.ok) throw new Error(`HTTP error! status: ${statsResponse.status}`);
    const stats = await statsResponse.json();
    console.log('Dashboard stats loaded:', stats);
    
    const heightEl = document.getElementById('network-height');
    const blocksEl = document.getElementById('total-blocks');
    const supplyEl = document.getElementById('total-supply');
    
    if (heightEl) heightEl.textContent = stats.height ?? '0';
    if (blocksEl) blocksEl.textContent = stats.total_blocks ?? (stats.total ?? '0');
    if (supplyEl) supplyEl.textContent = ((stats.supply_irm ?? 0)).toFixed(2) + ' IRM';

    // Load recent blocks for block time calculation
    const blocksProxyUrl = CORS_PROXY + encodeURIComponent(`${API_BASE}/blocks?limit=10`);
    const blocksResponse = await fetch(blocksProxyUrl);
    if (!blocksResponse.ok) throw new Error(`HTTP error! status: ${blocksResponse.status}`);
    const blocks = await blocksResponse.json();
    console.log('Dashboard blocks loaded:', blocks.blocks ? blocks.blocks.length : 0, 'blocks');

    const blockTimeEl = document.getElementById('block-time');
    const list = blocks.blocks ?? blocks ?? [];

    if (Array.isArray(list) && list.length > 1) {
      // Sort blocks by height (descending) to ensure proper order
      const sortedBlocks = list.sort((a, b) => (b.height ?? 0) - (a.height ?? 0));
      console.log('Sorted blocks for time calculation:', sortedBlocks.map(b => ({ height: b.height, time: b.time })));
      
      const intervals = [];
      for (let i = 1; i < sortedBlocks.length; i++) {
        const t2 = sortedBlocks[i-1].time ?? sortedBlocks[i-1].timestamp ?? 0;
        const t1 = sortedBlocks[i].time ?? sortedBlocks[i].timestamp ?? 0;
        const interval = (t2 - t1) / 60; // Convert to minutes
        if (interval > 0 && interval < 1440) { // Only include reasonable intervals (0-24 hours)
          intervals.push(interval);
        }
      }
      
      console.log('Block time intervals:', intervals);
      
      if (intervals.length > 0) {
        const avgBlockTime = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        if (blockTimeEl) blockTimeEl.textContent = avgBlockTime.toFixed(2) + ' minutes';
        updateChart(intervals, sortedBlocks.slice(0, Math.min(intervals.length + 1, 10)));
      } else {
        if (blockTimeEl) blockTimeEl.textContent = 'N/A';
      }
    } else {
      if (blockTimeEl) blockTimeEl.textContent = 'N/A';
    }
  } catch (error) {
    console.error('Error loading dashboard:', error);
    // Fallback: derive basics from blocks
    try {
      const blocksProxyUrl = CORS_PROXY + encodeURIComponent(`${API_BASE}/blocks?limit=10`);
      const blocksResponse = await fetch(blocksProxyUrl);
      const blocks = await blocksResponse.json();
      const list = blocks.blocks ?? blocks ?? [];
      const height = Array.isArray(list) && list.length ? (list[0].height ?? 0) : 0;
      const total = blocks.total ?? (Array.isArray(list) ? list.length : 0);
      const estSupplyIrm = total * 50;
      const heightEl = document.getElementById('network-height');
      const blocksEl = document.getElementById('total-blocks');
      const supplyEl = document.getElementById('total-supply');
      const blockTimeEl = document.getElementById('block-time');
      if (heightEl) heightEl.textContent = String(height);
      if (blocksEl) blocksEl.textContent = String(total);
      if (supplyEl) supplyEl.textContent = estSupplyIrm.toFixed(2) + ' IRM';
      if (blockTimeEl) blockTimeEl.textContent = 'N/A';
    } catch (e2) {
      console.error('Dashboard fallback failed:', e2);
      for (const id of ['network-height','total-blocks','total-supply','block-time']) {
        const el = document.getElementById(id); if (el) el.textContent = 'Error';
      }
    }
  }
}

function updateChart(intervals, blocks) {
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

    // Create labels based on actual block heights
    const labels = intervals.map((_, i) => {
      if (blocks && blocks[i + 1]) {
        return `Block ${blocks[i + 1].height}`;
      }
      return `Interval ${i + 1}`;
    });

    blockTimeChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
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

    console.log('Chart updated successfully with', intervals.length, 'intervals');
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
  const date = new Date((timestamp ?? 0) * 1000);
  return isNaN(date.getTime()) ? 'N/A' : date.toLocaleString();
}

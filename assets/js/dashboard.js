// Irium Network Dashboard JavaScript with CORS Proxy
const API_BASE = 'https://api.iriumlabs.org/api';
const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

let blockTimeChart;

console.log('Dashboard JS loaded');

async function fetchJson(path) {
  const url = CORS_PROXY + encodeURIComponent(`${API_BASE}${path}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function loadDashboard() {
  try {
    console.log('Loading dashboard data...');
    
    // Load stats
    const stats = await fetchJson('/stats');
    console.log('Dashboard stats loaded:', stats);
    
    const heightEl = document.getElementById('network-height');
    const blocksEl = document.getElementById('total-blocks');
    const supplyEl = document.getElementById('total-supply');
    
    if (heightEl) heightEl.textContent = stats.height ?? '0';
    if (blocksEl) blocksEl.textContent = stats.total_blocks ?? (stats.total ?? '0');
    if (supplyEl) supplyEl.textContent = ((stats.supply_irm ?? 0)).toFixed(2) + ' IRM';

    // Load blocks for chart data - try to get more complete data
    const blocks = await fetchJson('/blocks?limit=20');
    console.log('Dashboard blocks loaded:', blocks.blocks ? blocks.blocks.length : 0, 'blocks');

    const blockTimeEl = document.getElementById('block-time');
    let list = blocks.blocks ?? blocks ?? [];

    // Try to fetch individual blocks that might be missing for better chart data
    const allBlocks = [...list];
    const missingHeights = [];
    
    // Check for missing blocks 0-3 (genesis and early blocks)
    for (let h = 0; h <= Math.min(3, stats.height || 0); h++) {
      if (!allBlocks.some(b => (b.height ?? 0) === h)) {
        missingHeights.push(h);
      }
    }
    
    console.log('Missing block heights to fetch individually for dashboard:', missingHeights);
    
    // Fetch missing blocks individually
    for (const height of missingHeights) {
      try {
        console.log(`Fetching individual block ${height} for dashboard...`);
        const blockData = await fetchJson(`/block/${height}`);
        console.log(`Block ${height} response:`, blockData);
        
        if (blockData && blockData.block && !blockData.error) {
          allBlocks.push(blockData.block);
          console.log(`Successfully fetched block ${height} for dashboard:`, blockData.block.hash);
        } else if (blockData && !blockData.error) {
          allBlocks.push(blockData);
          console.log(`Successfully fetched block ${height} for dashboard (flat structure):`, blockData.hash);
        }
      } catch (error) {
        console.log(`Failed to fetch block ${height} for dashboard:`, error.message);
      }
    }
    
    list = allBlocks;

    if (Array.isArray(list) && list.length > 1) {
      // Sort blocks by height ascending (oldest -> newest)
      const sortedBlocks = list.slice().sort((a,b)=> (a.height??0) - (b.height??0));
      console.log('Sorted blocks (asc) for time calculation:', sortedBlocks.map(b => ({ height: b.height, time: b.time })));
      
      const timeIntervals = [];
      for (let i = 1; i < sortedBlocks.length; i++) {
        const t2 = sortedBlocks[i].time ?? sortedBlocks[i].timestamp ?? 0;
        const t1 = sortedBlocks[i-1].time ?? sortedBlocks[i-1].timestamp ?? 0;
        const m = (t2 - t1) / 60;
        if (m > 0 && m < 1440) timeIntervals.push(m);
      }
      
      console.log('Block time intervals:', timeIntervals);
      
      if (timeIntervals.length > 0) {
        const avgBlockTime = timeIntervals.reduce((a, b) => a + b, 0) / timeIntervals.length;
        if (blockTimeEl) blockTimeEl.textContent = avgBlockTime.toFixed(2) + ' minutes';
        updateChart(timeIntervals, sortedBlocks.slice(0, Math.min(timeIntervals.length + 1, 20)));
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
      const blocks = await fetchJson('/blocks?limit=20');
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
      if (blocks && blocks[i+1]) {
        return `Block ${blocks[i+1].height}`;
      }
      return `Interval ${i+1}`;
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

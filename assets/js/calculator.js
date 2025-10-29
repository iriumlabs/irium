// Irium Mining Calculator
const BLOCK_REWARD = 50; // IRM per block
const BLOCK_TIME = 600; // seconds (10 minutes)

async function loadNetworkStats() {
    try {
        const response = await fetch('https://api.iriumlabs.org/api/stats');
        const data = await response.json();
        document.getElementById('network-hashrate').value = '1000000'; // Placeholder
    } catch (error) {
        console.error('Error loading network stats:', error);
    }
}

function calculate() {
    const yourHashrate = parseFloat(document.getElementById('hashrate').value);
    const networkHashrate = parseFloat(document.getElementById('network-hashrate').value) || 1000000;
    
    if (!yourHashrate || yourHashrate <= 0) {
        alert('Please enter your hashrate');
        return;
    }
    
    const blocksPerDay = (24 * 60 * 60) / BLOCK_TIME; // ~144 blocks/day
    const yourShare = yourHashrate / networkHashrate;
    const yourBlocksPerDay = blocksPerDay * yourShare;
    const yourIRMPerDay = yourBlocksPerDay * BLOCK_REWARD;
    const yourIRMPerMonth = yourIRMPerDay * 30;
    
    document.getElementById('blocks-per-day').textContent = yourBlocksPerDay.toFixed(4);
    document.getElementById('irm-per-day').textContent = yourIRMPerDay.toFixed(2) + ' IRM';
    document.getElementById('irm-per-month').textContent = yourIRMPerMonth.toFixed(2) + ' IRM';
}

loadNetworkStats();

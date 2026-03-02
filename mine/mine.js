(() => {
  const state = {
    cfg: null,
    device: 'notsure',
    tab: 'modern',
  };

  const el = (id) => document.getElementById(id);

  function resolveWorker(cfg, wallet, worker) {
    const safeWallet = (wallet || '').trim();
    const safeWorker = (worker || '').trim() || 'rig1';
    const fmt = String(cfg?.workerFormat || 'WALLET.WORKER').toUpperCase();
    if (fmt === 'WALLET.WORKER') return `${safeWallet}.${safeWorker}`;
    return fmt.replace('WALLET', safeWallet).replace('WORKER', safeWorker);
  }

  function urls(cfg) {
    const d = cfg.poolDomain;
    return {
      legacy: `stratum+tcp://${d}:${cfg.ports.legacyTcp}`,
      tls: `stratum+ssl://${d}:${cfg.ports.tls}`,
      compat: `stratum+tcp://${d}:${cfg.ports.compat}`,
    };
  }

  function suggestedProfile(device) {
    if (device === 'modern') return 'tls';
    if (device === 'old') return 'legacy';
    if (device === 'gpu') return 'legacy';
    return 'legacy';
  }

  function setActiveDevice(device) {
    state.device = device;
    document.querySelectorAll('.device-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.device === device);
    });
    updateOutputs();
  }

  function setTab(tab) {
    state.tab = tab;
    document.querySelectorAll('.tab-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    document.querySelectorAll('.tab-pane').forEach((pane) => {
      pane.classList.toggle('active', pane.dataset.tab === tab);
    });
  }

  function setText(id, value) {
    const node = el(id);
    if (node) node.textContent = value;
  }

  function setCode(id, value) {
    const node = el(id);
    if (node) node.textContent = value;
  }

  function updateOutputs() {
    const cfg = state.cfg;
    if (!cfg) return;

    const wallet = (el('wallet')?.value || '').trim();
    const worker = (el('worker')?.value || '').trim();
    const workerUser = resolveWorker(cfg, wallet || '<WALLET>', worker || 'rig1');
    const pass = cfg.defaultPassword || 'x';
    const u = urls(cfg);
    const profile = suggestedProfile(state.device);
    const selectedUrl = profile === 'tls' ? u.tls : profile === 'compat' ? u.compat : u.legacy;

    setText('suggested-profile', profile === 'tls' ? 'TLS (modern firmware)' : 'Legacy TCP (max compatibility)');
    setText('suggested-url', selectedUrl);
    setText('suggested-note', cfg.notes?.[profile === 'tls' ? 'tls' : 'legacyTcp'] || '');

    setText('modern-url', u.tls);
    setText('modern-user', workerUser);
    setText('modern-pass', pass);

    setText('old-url', u.legacy);
    setText('old-user', workerUser);
    setText('old-pass', pass);

    setCode('modern-copy', `Pool URL: ${u.tls}\nWorker/User: ${workerUser}\nPassword: ${pass}`);

    setCode('old-cmd-copy', `cgminer -o ${u.legacy} -u ${workerUser} -p ${pass}`);

    setCode('old-json-copy', JSON.stringify({
      pools: [
        { url: u.legacy, user: workerUser, pass },
        { url: u.compat, user: workerUser, pass },
      ],
      "api-listen": true,
      "api-allow": "W:127.0.0.1"
    }, null, 2));

    setCode('gpu-copy', `./irium-miner --pool ${u.legacy} --user ${workerUser} --pass ${pass}`);

    setCode('fallback-linux-copy', [
      '# Linux (basic TCP forward pattern)',
      '# Run bridge/proxy locally then point ASIC to your bridge host.',
      '# Example placeholder:',
      `socat TCP-LISTEN:3333,fork,reuseaddr TCP:${cfg.poolDomain}:${cfg.ports.legacyTcp}`,
      '# If TLS translation is needed for old firmware, use stunnel or dedicated stratum proxy.'
    ].join('\n'));

    setCode('fallback-wsl-copy', [
      '# Windows (WSL2) quick flow',
      '1) Install Ubuntu in WSL2',
      '2) Start proxy listener inside WSL on 0.0.0.0:3333',
      `3) Upstream to ${cfg.poolDomain}:${cfg.ports.legacyTcp}`,
      '4) Point ASIC Pool URL to: stratum+tcp://<LAN_IP_OF_PC>:3333'
    ].join('\n'));

    setCode('fallback-docker-copy', [
      `docker run --rm -p 3333:3333 iriumlabs/stratum-bridge:latest --listen 0.0.0.0:3333 --upstream ${cfg.poolDomain}:${cfg.ports.legacyTcp}`,
      '',
      '# If this image is not published yet, use the WSL2 method above.'
    ].join('\n'));
  }

  function attachCopyHandlers() {
    document.querySelectorAll('[data-copy-target]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const target = el(btn.dataset.copyTarget);
        if (!target) return;
        const text = target.textContent || '';
        try {
          await navigator.clipboard.writeText(text);
          const original = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = original; }, 1200);
        } catch (_) {
          // fallback
          const range = document.createRange();
          range.selectNodeContents(target);
          const sel = window.getSelection();
          sel.removeAllRanges();
          sel.addRange(range);
        }
      });
    });
  }

  async function loadConfig() {
    const res = await fetch('./config.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`config load failed: HTTP ${res.status}`);
    return res.json();
  }

  function normalizeLookup(data) {
    if (!data || typeof data !== 'object') return null;
    const d = data.result && typeof data.result === 'object' ? data.result : data;
    return {
      online: d.online ?? d.is_online ?? null,
      lastShareTime: d.last_share_time ?? d.lastShareTime ?? d.last_share_at ?? null,
      hashrate: d.hashrate ?? d.hash_rate ?? d.hashrate_hs ?? null,
      workerCount: d.worker_count ?? d.workers ?? null,
      raw: data,
    };
  }

  async function checkWorker() {
    const cfg = state.cfg;
    const wallet = (el('verify-wallet')?.value || '').trim();
    const msg = el('verify-msg');
    const rawBox = el('verify-raw-json');

    if (!wallet) {
      msg.textContent = 'Enter your wallet first.';
      msg.className = 'status-msg warn';
      return;
    }

    if (!cfg.stats || cfg.stats.enabled !== true) {
      msg.textContent = 'Worker status is not enabled yet on this pool endpoint. Paste your wallet below and we will add this soon.';
      msg.className = 'status-msg warn';
      return;
    }

    msg.textContent = 'Checking...';
    msg.className = 'status-msg';
    rawBox.textContent = '{}';

    try {
      let summary = null;
      if (cfg.stats.poolSummaryUrl) {
        const sr = await fetch(cfg.stats.poolSummaryUrl, { cache: 'no-store' });
        if (sr.ok) summary = await sr.json();
      }

      let lookup = null;
      if (cfg.stats.workerLookupUrl) {
        const url = cfg.stats.workerLookupUrl.replace('{wallet}', encodeURIComponent(wallet));
        const lr = await fetch(url, { cache: 'no-store' });
        if (lr.ok) lookup = await lr.json();
      }

      const n = normalizeLookup(lookup);

      setText('verify-online', n?.online === null ? 'Unknown' : (n.online ? 'Online' : 'Offline'));
      setText('verify-last-share', n?.lastShareTime ? String(n.lastShareTime) : 'N/A');
      setText('verify-hashrate', n?.hashrate ? String(n.hashrate) : 'N/A');
      setText('verify-worker-count', n?.workerCount ? String(n.workerCount) : 'N/A');

      if (summary && typeof summary === 'object') {
        setText('verify-pool-summary', `Pool summary loaded (${Object.keys(summary).length} fields).`);
      } else {
        setText('verify-pool-summary', 'Pool summary not available from configured endpoint.');
      }

      msg.textContent = 'Lookup completed.';
      msg.className = 'status-msg ok';
      rawBox.textContent = JSON.stringify({ summary, lookup }, null, 2);
    } catch (err) {
      msg.textContent = `Lookup failed: ${String(err.message || err)}`;
      msg.className = 'status-msg warn';
      rawBox.textContent = JSON.stringify({ error: String(err) }, null, 2);
    }
  }

  function initEvents() {
    document.querySelectorAll('.device-btn').forEach((btn) => {
      btn.addEventListener('click', () => setActiveDevice(btn.dataset.device));
    });

    document.querySelectorAll('.tab-btn').forEach((btn) => {
      btn.addEventListener('click', () => setTab(btn.dataset.tab));
    });

    ['wallet', 'worker'].forEach((id) => {
      const n = el(id);
      if (n) n.addEventListener('input', updateOutputs);
    });

    const verifyBtn = el('verify-btn');
    if (verifyBtn) verifyBtn.addEventListener('click', checkWorker);

    attachCopyHandlers();
  }

  async function boot() {
    try {
      state.cfg = await loadConfig();
      setText('coin-ticker', state.cfg.coinTicker || 'IRM');
      setText('pool-domain', state.cfg.poolDomain || 'pool.iriumlabs.org');
      setActiveDevice('notsure');
      setTab('modern');
      initEvents();
      updateOutputs();

      if (!(state.cfg.stats && state.cfg.stats.enabled === true)) {
        setText('verify-msg', 'Worker status is not enabled yet on this pool endpoint. Paste your wallet below and we will add this soon.');
        const verifyBtn = el('verify-btn');
        if (verifyBtn) verifyBtn.disabled = true;
      }
    } catch (err) {
      const app = el('mine-app');
      if (app) {
        app.innerHTML = `<div class="mine-card"><h2>Unable to load mining app config</h2><p class="mine-sub">${String(err.message || err)}</p></div>`;
      }
    }
  }

  boot();
})();

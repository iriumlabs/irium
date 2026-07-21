// Live mining metrics widget (hashrate + difficulty + difficulty change).
// Safe to include on any page: it only updates elements that exist.

const DEFAULT_API_BASE = "https://api.irium.org/api";
const CORS_PROXIES = ["", "https://api.allorigins.win/raw?url="]; // best-effort
const FETCH_TIMEOUT_MS = 15000;

async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function getApiBases() {
  const bases = [];
  if (window.IRIUM_API_BASE) bases.push(window.IRIUM_API_BASE);
  const docBase = document.documentElement.dataset.apiBase || (document.body && document.body.dataset && document.body.dataset.apiBase);
  if (docBase) bases.push(docBase);
  bases.push(DEFAULT_API_BASE);
  if (location && location.origin) bases.push(location.origin + "/api");

  const deduped = [];
  for (const base of bases) {
    const norm = String(base || "").replace(/\/+$/, "");
    if (norm && !deduped.includes(norm)) deduped.push(norm);
  }
  return deduped;
}

async function fetchJson(path) {
  const bases = getApiBases();
  const errors = [];
  for (const base of bases) {
    const url = base + path;
    for (const proxy of CORS_PROXIES) {
      const target = proxy ? proxy + encodeURIComponent(url) : url;
      try {
        const res = await fetchWithTimeout(target, { cache: "no-store" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
      } catch (err) {
        errors.push(err && err.message ? err.message : String(err));
      }
    }
  }
  throw new Error(errors[0] || "Fetch failed");
}

function fmtNum(v, digits = 2) {
  const n = Number(v);
  if (!isFinite(n)) return "N/A";
  return n.toFixed(digits);
}

function fmtPct(v) {
  const n = Number(v);
  if (!isFinite(n)) return "N/A";
  const sign = n > 0 ? "+" : "";
  return sign + n.toFixed(2) + "%";
}

function fmtHashrate(hs) {
  const n = Number(hs);
  if (!isFinite(n) || n <= 0) return "N/A";
  const units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"]; 
  let v = n;
  let u = 0;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  return v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2) + " " + units[u];
}

async function loadMiningWidget() {
  const elHash = document.getElementById("net-hashrate");
  const elDiff = document.getElementById("net-difficulty");
  const elGrowth = document.getElementById("diff-growth");
  if (!elHash && !elDiff && !elGrowth) return;

  try {
    const m = await fetchJson("/mining?window=120&series=240");
    if (elHash) elHash.textContent = fmtHashrate(m.hashrate);
    if (elDiff) elDiff.textContent = fmtNum(m.difficulty, 2);

    const g1 = (m.difficulty_change_1h_pct != null) ? fmtPct(m.difficulty_change_1h_pct) : "N/A";
    const g24 = (m.difficulty_change_24h_pct != null) ? fmtPct(m.difficulty_change_24h_pct) : "N/A";
    if (elGrowth) elGrowth.textContent = `${g1} / ${g24}`;
  } catch (e) {
    const msg = "Error";
    if (elHash) elHash.textContent = msg;
    if (elDiff) elDiff.textContent = msg;
    if (elGrowth) elGrowth.textContent = msg;
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", loadMiningWidget);
} else {
  loadMiningWidget();
}

setInterval(loadMiningWidget, 30000);

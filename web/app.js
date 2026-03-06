const apiBaseInput = document.getElementById("apiBase");
const saveEndpointBtn = document.getElementById("saveEndpoint");
const refreshAllBtn = document.getElementById("refreshAll");
const liveStatus = document.getElementById("liveStatus");
const liveMode = document.getElementById("liveMode");

const statNetwork = document.getElementById("statNetwork");
const statHeight = document.getElementById("statHeight");
const statUtxo = document.getElementById("statUtxo");
const statWork = document.getElementById("statWork");
const statRelayPeers = document.getElementById("statRelayPeers");
const statSyncLag = document.getElementById("statSyncLag");
const statLastBlockAge = document.getElementById("statLastBlockAge");
const statRelayMempool = document.getElementById("statRelayMempool");
const statNetworkHashrate = document.getElementById("statNetworkHashrate");
const statPoolHashrate = document.getElementById("statPoolHashrate");
const statPoolWorkers = document.getElementById("statPoolWorkers");
const latestRange = document.getElementById("latestRange");
const latestBlocksBody = document.getElementById("latestBlocksBody");

const blockLookupForm = document.getElementById("blockLookupForm");
const blockHeightInput = document.getElementById("blockHeightInput");
const blockLookupOut = document.getElementById("blockLookupOut");

const txLookupForm = document.getElementById("txLookupForm");
const txHeightInput = document.getElementById("txHeightInput");
const txIndexInput = document.getElementById("txIndexInput");
const txidLookupForm = document.getElementById("txidLookupForm");
const txidInput = document.getElementById("txidInput");
const txLookupOut = document.getElementById("txLookupOut");

const mempoolOut = document.getElementById("mempoolOut");
const poolStatusForm = document.getElementById("poolStatusForm");
const poolStatusOut = document.getElementById("poolStatusOut");
const poolWorkerForm = document.getElementById("poolWorkerForm");
const poolWorkerInput = document.getElementById("poolWorkerInput");
const poolWorkerOut = document.getElementById("poolWorkerOut");
const poolPayoutPendingOut = document.getElementById("poolPayoutPendingOut");
const poolPayoutCompletedOut = document.getElementById("poolPayoutCompletedOut");
const walletOut = document.getElementById("walletOut");

const DASHBOARD_POLL_INTERVAL_MS = 5000;

const state = {
  apiBase: localStorage.getItem("scam.console.apiBase") || window.location.origin,
  events: null,
  lastTipHeight: null,
  lastMempoolCount: null,
};

function parseNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function shortHash(hex, head = 12, tail = 8) {
  if (typeof hex !== "string") return "-";
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}...${hex.slice(-tail)}`;
}

function formatAgeSeconds(sec) {
  const n = Number(sec);
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n < 60) return `${Math.floor(n)}s`;
  if (n < 3600) return `${Math.floor(n / 60)}m ${Math.floor(n % 60)}s`;
  return `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`;
}

function formatHashrate(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "-";
  if (n >= 1e18) return `${(n / 1e18).toFixed(2)} EH/s`;
  if (n >= 1e15) return `${(n / 1e15).toFixed(2)} PH/s`;
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)} TH/s`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} GH/s`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} MH/s`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)} KH/s`;
  return `${n.toFixed(2)} H/s`;
}

function formatJson(data) {
  return JSON.stringify(data, null, 2);
}

function setResult(el, data, isError = false) {
  el.innerHTML = "";
  el.textContent = typeof data === "string" ? data : formatJson(data);
  el.classList.toggle("error", isError);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isWalletBalancePayload(data) {
  return (
    data &&
    typeof data === "object" &&
    "address" in data &&
    "tip_height" in data &&
    "spendable" in data &&
    "immature" in data
  );
}

function isWalletBalanceHistoryPayload(data) {
  return (
    data &&
    typeof data === "object" &&
    data.balance &&
    typeof data.balance === "object" &&
    Array.isArray(data.tx_history)
  );
}

function isWalletSendPayload(data) {
  return (
    data &&
    typeof data === "object" &&
    "txid" in data &&
    "mempool_outcome" in data &&
    "amount" in data &&
    "fee" in data
  );
}

function formatScamOnly(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return `${value}`;
  return `${(n / 1e8).toLocaleString(undefined, {
    minimumFractionDigits: 8,
    maximumFractionDigits: 8,
  })} SCAM`;
}

function formatAtomicOnly(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return `${value}`;
  return `${n.toLocaleString()} atomic`;
}

function getWalletBalanceStatus(total, spendable, immature) {
  if (total <= 0) {
    return {
      kind: "empty",
      title: "No Funds",
      detail: "This address has no UTXOs yet.",
    };
  }
  if (spendable <= 0 && immature > 0) {
    return {
      kind: "immature",
      title: "Immature Balance",
      detail: "Mining rewards are locked by coinbase maturity.",
    };
  }
  if (spendable > 0 && immature > 0) {
    return {
      kind: "partial",
      title: "Partially Spendable",
      detail: "Some UTXOs are spendable, some are still maturing.",
    };
  }
  return {
    kind: "ready",
    title: "Spendable",
    detail: "All detected funds are currently spendable.",
  };
}

function balanceLineHtml(label, valueAtomic, pct, tone) {
  const boundedPct = Math.min(100, Math.max(0, Number(pct) || 0));
  return `
    <article class="wallet-balance-card">
      <div class="wallet-balance-card-head">
        <span class="wallet-balance-label">${escapeHtml(label)}</span>
        <span class="wallet-balance-pct">${boundedPct.toFixed(2)}%</span>
      </div>
      <div class="wallet-balance-value">${escapeHtml(formatScamOnly(valueAtomic))}</div>
      <div class="wallet-balance-atomic">${escapeHtml(formatAtomicOnly(valueAtomic))}</div>
      <div class="wallet-balance-progress ${escapeHtml(tone)}"><span style="width:${boundedPct}%"></span></div>
    </article>
  `;
}

function renderWalletBalanceCard(data) {
  const total = Number(data.total) || 0;
  const spendable = Number(data.spendable) || 0;
  const immature = Number(data.immature) || 0;
  const spendablePct = total > 0 ? (spendable / total) * 100 : 0;
  const immaturePct = total > 0 ? (immature / total) * 100 : 0;
  const status = getWalletBalanceStatus(total, spendable, immature);
  return `
    <section class="wallet-balance-layout">
      <header class="wallet-balance-summary">
        <div>
          <h3>Wallet Balance</h3>
          <div class="wallet-balance-subtitle">${escapeHtml(status.detail)}</div>
        </div>
        <span class="wallet-balance-status ${escapeHtml(status.kind)}">${escapeHtml(status.title)}</span>
      </header>

      <div class="wallet-meta-grid">
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Network</span>
          <span class="wallet-meta-value">${escapeHtml(data.network_id ?? "-")}</span>
        </div>
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Tip Height</span>
          <span class="wallet-meta-value">${escapeHtml(data.tip_height ?? "-")}</span>
        </div>
        <div class="wallet-meta-item wallet-meta-item-wide">
          <span class="wallet-meta-label">Address</span>
          <span class="wallet-meta-value mono">${escapeHtml(data.address ?? "-")}</span>
        </div>
      </div>

      <div class="wallet-balance-grid">
        ${balanceLineHtml("Total", total, 100, "tone-total")}
        ${balanceLineHtml("Spendable", spendable, spendablePct, "tone-spendable")}
        ${balanceLineHtml("Immature", immature, immaturePct, "tone-immature")}
      </div>

      <div class="wallet-utxo-grid">
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">UTXOs Total</div>
          <div class="wallet-utxo-value">${(data.utxo_count ?? 0).toLocaleString()}</div>
        </article>
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">Spendable UTXOs</div>
          <div class="wallet-utxo-value">${(data.spendable_utxo_count ?? 0).toLocaleString()}</div>
        </article>
        <article class="wallet-utxo-card">
          <div class="wallet-utxo-label">Immature UTXOs</div>
          <div class="wallet-utxo-value">${(data.immature_utxo_count ?? 0).toLocaleString()}</div>
        </article>
      </div>
    </section>
  `;
}

function txDirectionMeta(direction, coinbase) {
  if (coinbase) {
    return {
      cls: "coinbase",
      title: "Coinbase",
      flow: "Block reward -> your wallet",
      sign: "+",
    };
  }
  if (direction === "in") {
    return {
      cls: "in",
      title: "Incoming",
      flow: "Sender -> your wallet",
      sign: "+",
    };
  }
  if (direction === "out") {
    return {
      cls: "out",
      title: "Outgoing",
      flow: "Your wallet -> recipient(s)",
      sign: "-",
    };
  }
  return {
    cls: "self",
    title: "Self",
    flow: "Your wallet -> your wallet",
    sign: "±",
  };
}

function renderWalletHistorySection(txHistory, historyError = "") {
  const entries = Array.isArray(txHistory) ? txHistory : [];
  let bodyHtml = "";
  if (!entries.length) {
    bodyHtml = `
      <div class="wallet-history-empty">
        No transactions detected for this wallet yet.
      </div>
    `;
  } else {
    bodyHtml = `
      <div class="wallet-history-grid">
        ${entries
          .map((entry) => {
            const direction = txDirectionMeta(entry.direction, entry.coinbase);
            const netAtomic = Number(entry.net) || 0;
            return `
              <article class="wallet-history-card">
                <div class="wallet-history-head">
                  <span class="wallet-history-badge ${escapeHtml(direction.cls)}">${escapeHtml(direction.title)}</span>
                  <span class="wallet-history-height">H${escapeHtml(entry.height ?? "-")}</span>
                </div>
                <div class="wallet-history-net">${escapeHtml(direction.sign)}${escapeHtml(formatScamOnly(netAtomic))}</div>
                <div class="wallet-history-flow">${escapeHtml(direction.flow)}</div>
                <div class="wallet-history-amounts">
                  <span>Received: ${escapeHtml(formatScamOnly(entry.received ?? 0))}</span>
                  <span>Sent: ${escapeHtml(formatScamOnly(entry.sent ?? 0))}</span>
                </div>
                <div class="wallet-history-txid mono" title="${escapeHtml(entry.txid ?? "-")}">
                  ${escapeHtml(shortHash(entry.txid ?? "-", 16, 12))}
                </div>
              </article>
            `;
          })
          .join("")}
      </div>
    `;
  }

  return `
    <section class="wallet-history-layout">
      <header class="wallet-history-header">
        <h3>Transaction History</h3>
        <span class="wallet-history-count">${entries.length} entries</span>
      </header>
      ${
        historyError
          ? `<div class="wallet-history-warning">History temporarily unavailable: ${escapeHtml(historyError)}</div>`
          : ""
      }
      ${bodyHtml}
    </section>
  `;
}

function renderWalletBalanceWithHistory(payload) {
  const balance = payload.balance;
  return `
    ${renderWalletBalanceCard(balance)}
    ${renderWalletHistorySection(payload.tx_history, payload.history_error || "")}
  `;
}

function sendOutcomeMeta(outcome) {
  switch (outcome) {
    case "accepted":
      return { cls: "accepted", title: "Accepted", detail: "Transaction accepted into mempool." };
    case "replaced":
      return { cls: "accepted", title: "Replaced", detail: "Accepted and replaced conflicting transaction(s)." };
    case "accepted_with_eviction":
      return { cls: "accepted", title: "Accepted (evicted)", detail: "Accepted with low-fee eviction from mempool." };
    case "already_present":
      return { cls: "neutral", title: "Already Present", detail: "This transaction already exists in mempool." };
    case "rejected_conflict_insufficient_fee":
      return { cls: "rejected", title: "Rejected", detail: "Conflict replacement fee was too low." };
    case "rejected_conflict_insufficient_feerate":
      return { cls: "rejected", title: "Rejected", detail: "Conflict replacement feerate was too low." };
    default:
      return { cls: "neutral", title: outcome || "Unknown", detail: "Mempool returned an unclassified outcome." };
  }
}

function renderWalletSendCard(data) {
  const outcome = sendOutcomeMeta(data.mempool_outcome);
  const selectedInputs = Array.isArray(data.selected_inputs) ? data.selected_inputs : [];
  return `
    <section class="wallet-send-layout">
      <header class="wallet-send-summary">
        <div>
          <h3>Transaction Submit Result</h3>
          <div class="wallet-send-subtitle">${escapeHtml(outcome.detail)}</div>
        </div>
        <span class="wallet-send-status ${escapeHtml(outcome.cls)}">${escapeHtml(outcome.title)}</span>
      </header>

      <div class="wallet-meta-grid">
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Network</span>
          <span class="wallet-meta-value">${escapeHtml(data.network_id ?? "-")}</span>
        </div>
        <div class="wallet-meta-item">
          <span class="wallet-meta-label">Mempool Outcome</span>
          <span class="wallet-meta-value">${escapeHtml(data.mempool_outcome ?? "-")}</span>
        </div>
        <div class="wallet-meta-item wallet-meta-item-wide">
          <span class="wallet-meta-label">TxID</span>
          <span class="wallet-meta-value mono">${escapeHtml(data.txid ?? "-")}</span>
        </div>
      </div>

      <div class="wallet-balance-grid">
        ${balanceLineHtml("Amount", data.amount ?? 0, 100, "tone-total")}
        ${balanceLineHtml("Fee", data.fee ?? 0, 100, "tone-immature")}
        ${balanceLineHtml("Change", data.change ?? 0, 100, "tone-spendable")}
      </div>

      <div class="wallet-send-inputs">
        <div class="wallet-send-inputs-title">Selected Inputs (${selectedInputs.length})</div>
        ${
          selectedInputs.length
            ? `<div class="wallet-send-input-list">
                ${selectedInputs
                  .map(
                    (input) => `
                      <article class="wallet-send-input-card">
                        <div class="mono" title="${escapeHtml(input.txid ?? "-")}">
                          ${escapeHtml(shortHash(input.txid ?? "-", 16, 12))}:${escapeHtml(input.vout ?? "-")}
                        </div>
                        <div>${escapeHtml(formatScamOnly(input.value ?? 0))}</div>
                      </article>
                    `,
                  )
                  .join("")}
              </div>`
            : `<div class="wallet-history-empty">No input details returned by RPC.</div>`
        }
      </div>
    </section>
  `;
}

function setWalletResult(data, isError = false) {
  if (!isError && isWalletBalanceHistoryPayload(data)) {
    walletOut.innerHTML = renderWalletBalanceWithHistory(data);
    walletOut.classList.remove("error");
    return;
  }
  if (!isError && isWalletBalancePayload(data)) {
    walletOut.innerHTML = renderWalletBalanceCard(data);
    walletOut.classList.remove("error");
    return;
  }
  if (!isError && isWalletSendPayload(data)) {
    walletOut.innerHTML = renderWalletSendCard(data);
    walletOut.classList.remove("error");
    return;
  }
  setResult(walletOut, data, isError);
}

function endpoint(path) {
  const base = state.apiBase.replace(/\/$/, "");
  return `${base}${path}`;
}

function setLiveStatusBadge(mode, text) {
  if (!liveStatus) return;
  liveStatus.classList.remove("connected", "reconnecting", "disconnected");
  liveStatus.classList.add(mode);
  liveStatus.textContent = text;
}

function closeLiveStream() {
  if (state.events) {
    state.events.close();
    state.events = null;
  }
}

async function request(path, { method = "GET", body } = {}) {
  const opts = {
    method,
    headers: {},
  };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const url = endpoint(path);
  let response;
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      response = await fetch(url, opts);
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
      if (attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }
  }
  if (!response) {
    const detail = lastError?.message || "network error";
    throw new Error(`Failed to fetch ${url}: ${detail}`);
  }
  const text = await response.text();
  let payload = text;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    // keep raw text
  }
  if (response.ok && typeof payload === "string") {
    const trimmed = payload.trimStart().toLowerCase();
    if (trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html")) {
      throw new Error(
        "API returned HTML instead of JSON. Проверь apiBase и перезапусти ноду с новым rpc-serve",
      );
    }
  }
  if (!response.ok) {
    const errorMessage =
      typeof payload === "object" && payload && payload.error
        ? payload.error
        : `HTTP ${response.status}: ${text || response.statusText}`;
    throw new Error(errorMessage);
  }
  return payload;
}

async function loadStatus() {
  const status = await request("/status");
  statNetwork.textContent = status.network_id ?? "-";
  statHeight.textContent = `${status.tip_height ?? "-"}`;
  statUtxo.textContent = `${status.utxo_count ?? "-"}`;
  statWork.textContent = status.cumulative_work ?? "-";
  statRelayPeers.textContent = "-";
  statSyncLag.textContent = "-";
  statLastBlockAge.textContent = "-";
  statRelayMempool.textContent = "-";
  statNetworkHashrate.textContent = formatHashrate(status.network_hashrate_hps);
  statPoolHashrate.textContent = formatHashrate(status.stratum_pool_hashrate_hps);
  statPoolWorkers.textContent =
    status.stratum_workers_active === null || status.stratum_workers_active === undefined
      ? "-"
      : `${status.stratum_workers_active}`;
  return status;
}

function renderLatestBlocks(blocks, tipHeight) {
  latestBlocksBody.innerHTML = "";
  for (const block of blocks) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${block.height}</td>
      <td class="mono" title="${block.hash}">${shortHash(block.hash)}</td>
      <td>${block.tx_count}</td>
      <td>${block.timestamp}</td>
      <td class="mono" title="${block.target}">${shortHash(block.target, 10, 8)}</td>
    `;
    latestBlocksBody.appendChild(row);
  }
  const first = blocks.length ? blocks[blocks.length - 1].height : tipHeight;
  latestRange.textContent = `${first}..${tipHeight}`;
}

async function loadLatestBlocks(tipHeight, count = 12) {
  if (!Number.isFinite(tipHeight)) {
    renderLatestBlocks([], 0);
    return;
  }
  const heights = [];
  for (let h = tipHeight; h >= 0 && heights.length < count; h -= 1) {
    heights.push(h);
  }

  const requests = heights.map(async (height) => {
    try {
      const block = await request(`/block/${height}`);
      return {
        height,
        hash: block.hash,
        tx_count: block.tx_count,
        timestamp: block.timestamp,
        target: block.target,
      };
    } catch (error) {
      const msg = String(error?.message || "");
      if (msg.includes("not found")) {
        return null;
      }
      throw error;
    }
  });

  const blocks = (await Promise.all(requests)).filter(Boolean);
  renderLatestBlocks(blocks, tipHeight);
}

async function loadMempool() {
  try {
    const mempool = await request("/mempool");
    const countFromField = Number(mempool.tx_count);
    const countFromTxids = Array.isArray(mempool.txids) ? mempool.txids.length : null;
    if (Number.isFinite(countFromField)) {
      state.lastMempoolCount = countFromField;
    } else if (Number.isFinite(countFromTxids)) {
      state.lastMempoolCount = countFromTxids;
    }
    setResult(mempoolOut, mempool);
  } catch (error) {
    setResult(mempoolOut, `Cannot load mempool snapshot: ${error.message}`, true);
  }
}

async function loadPoolStatus() {
  try {
    const status = await request("/pool/status");
    setResult(poolStatusOut, status);
  } catch (error) {
    setResult(poolStatusOut, `Cannot load pool status: ${error.message}`, true);
  }
}

async function loadPoolPayouts() {
  try {
    const pending = await request("/pool/payouts/pending");
    setResult(poolPayoutPendingOut, pending);
  } catch (error) {
    setResult(poolPayoutPendingOut, `Cannot load pending payouts: ${error.message}`, true);
  }
  try {
    const completed = await request("/pool/payouts/completed");
    setResult(poolPayoutCompletedOut, completed);
  } catch (error) {
    setResult(poolPayoutCompletedOut, `Cannot load completed payouts: ${error.message}`, true);
  }
}

async function refreshDashboard() {
  try {
    const status = await loadStatus();
    state.lastTipHeight = Number.isFinite(Number(status.tip_height))
      ? Number(status.tip_height)
      : state.lastTipHeight;
    await Promise.allSettled([
      loadLatestBlocks(status.tip_height),
      loadMempool(),
      loadPoolStatus(),
      loadPoolPayouts(),
    ]);
  } catch (error) {
    setResult(blockLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(txLookupOut, `Dashboard refresh failed: ${error.message}`, true);
    setResult(mempoolOut, `Dashboard refresh failed: ${error.message}`, true);
  }
}

function applyLiveSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return;
  statNetwork.textContent = snapshot.network_id ?? "-";
  statHeight.textContent = `${snapshot.tip_height ?? "-"}`;
  statUtxo.textContent = `${snapshot.utxo_count ?? "-"}`;
  statWork.textContent = snapshot.cumulative_work ?? "-";
  statRelayPeers.textContent =
    snapshot.relay_active_peers === null || snapshot.relay_active_peers === undefined
      ? "-"
      : `${snapshot.relay_active_peers}`;
  statSyncLag.textContent =
    snapshot.sync_lag_blocks === null || snapshot.sync_lag_blocks === undefined
      ? "-"
      : `${snapshot.sync_lag_blocks} blk`;
  statLastBlockAge.textContent = formatAgeSeconds(snapshot.last_block_age_sec);
  statRelayMempool.textContent =
    snapshot.relay_mempool_len === null || snapshot.relay_mempool_len === undefined
      ? "-"
      : `${snapshot.relay_mempool_len}`;
  statNetworkHashrate.textContent = formatHashrate(snapshot.network_hashrate_hps);
  statPoolHashrate.textContent = formatHashrate(snapshot.stratum_pool_hashrate_hps);
  statPoolWorkers.textContent =
    snapshot.stratum_workers_active === null || snapshot.stratum_workers_active === undefined
      ? "-"
      : `${snapshot.stratum_workers_active}`;

  const tipHeight = Number(snapshot.tip_height);
  if (Number.isFinite(tipHeight) && tipHeight !== state.lastTipHeight) {
    state.lastTipHeight = tipHeight;
    loadLatestBlocks(tipHeight).catch((error) => {
      setResult(blockLookupOut, `Live latest blocks failed: ${error.message}`, true);
    });
  }

  const mempoolCount = Number(snapshot.mempool_tx_count);
  if (Number.isFinite(mempoolCount) && mempoolCount !== state.lastMempoolCount) {
    state.lastMempoolCount = mempoolCount;
    loadMempool().catch((error) => {
      setResult(mempoolOut, `Live mempool refresh failed: ${error.message}`, true);
    });
  }
}

function startLiveStream() {
  closeLiveStream();
  if (typeof EventSource === "undefined") {
    setLiveStatusBadge("disconnected", "Live stream: unsupported");
    if (liveMode) liveMode.textContent = "Fallback polling: 5s";
    return;
  }

  const events = new EventSource(endpoint("/events"));
  state.events = events;
  setLiveStatusBadge("reconnecting", "Live stream: connecting");
  if (liveMode) liveMode.textContent = "SSE push + polling fallback";

  const onSnapshot = (event) => {
    try {
      const snapshot = JSON.parse(event.data);
      applyLiveSnapshot(snapshot);
    } catch (error) {
      setResult(mempoolOut, `Live snapshot parse failed: ${error.message}`, true);
    }
  };

  events.addEventListener("snapshot", onSnapshot);
  events.onmessage = onSnapshot;
  events.onopen = () => {
    setLiveStatusBadge("connected", "Live stream: connected");
  };
  events.onerror = () => {
    if (state.events !== events) return;
    setLiveStatusBadge("reconnecting", "Live stream: reconnecting");
  };
}

function serializeForm(form) {
  const fd = new FormData(form);
  const out = {};
  for (const [k, v] of fd.entries()) {
    out[k] = typeof v === "string" ? v.trim() : v;
  }
  return out;
}

function initTabs() {
  const tabButtons = document.querySelectorAll(".tab");
  const tabPanels = document.querySelectorAll(".tab-panel");
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.tab;
      tabButtons.forEach((el) => el.classList.toggle("active", el === button));
      tabPanels.forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.panel === target);
      });
    });
  });
}

function initExplorerActions() {
  blockLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(blockHeightInput.value, 0);
    try {
      const block = await request(`/block/${height}`);
      setResult(blockLookupOut, block);
    } catch (error) {
      setResult(blockLookupOut, error.message, true);
    }
  });

  txLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const height = parseNumber(txHeightInput.value, 0);
    const index = parseNumber(txIndexInput.value, 0);
    try {
      const tx = await request(`/tx/${height}/${index}`);
      setResult(txLookupOut, tx);
    } catch (error) {
      setResult(txLookupOut, error.message, true);
    }
  });

  txidLookupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const txid = (txidInput.value || "").trim().toLowerCase();
    if (!txid) {
      setResult(txLookupOut, "txid is required", true);
      return;
    }
    try {
      const tx = await request(`/txid/${encodeURIComponent(txid)}`);
      setResult(txLookupOut, tx);
    } catch (error) {
      setResult(txLookupOut, error.message, true);
    }
  });

  if (poolStatusForm) {
    poolStatusForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      await loadPoolStatus();
      await loadPoolPayouts();
    });
  }

  if (poolWorkerForm) {
    poolWorkerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const worker = (poolWorkerInput.value || "").trim();
      if (!worker) {
        setResult(poolWorkerOut, "worker label is required", true);
        return;
      }
      try {
        const data = await request(`/pool/worker/${encodeURIComponent(worker)}`);
        setResult(poolWorkerOut, data);
      } catch (error) {
        setResult(poolWorkerOut, error.message, true);
      }
    });
  }
}

function initWalletActions() {
  const historyByAddress = async (address, maxEntries = 30) =>
    request("/wallet/balance-history-by-address", {
      method: "POST",
      body: {
        address,
        max_entries: maxEntries,
      },
    });

  document.getElementById("walletNewForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      words: parseNumber(raw.words, 12),
      passphrase: raw.passphrase || "",
      seed_mode: raw.seed_mode || "bip39",
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
      ...(raw.hrp ? { hrp: raw.hrp } : {}),
    };
    try {
      const data = await request("/wallet/new", { method: "POST", body: payload });
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
    }
  });

  document
    .getElementById("walletAddressForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        mnemonic: raw.mnemonic,
        passphrase: raw.passphrase || "",
        seed_mode: raw.seed_mode || "bip39",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
        ...(raw.hrp ? { hrp: raw.hrp } : {}),
      };
      try {
        const data = await request("/wallet/address", { method: "POST", body: payload });
        setWalletResult(data);
      } catch (error) {
        setWalletResult(error.message, true);
      }
    });

  document
    .getElementById("walletBalanceForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        mnemonic: raw.mnemonic,
        passphrase: raw.passphrase || "",
        seed_mode: raw.seed_mode || "bip39",
        account: parseNumber(raw.account, 0),
        index: parseNumber(raw.index, 0),
      };
      try {
        const balance = await request("/wallet/balance", { method: "POST", body: payload });
        if (!balance?.address) {
          setWalletResult(balance);
          return;
        }
        try {
          const withHistory = await historyByAddress(balance.address);
          setWalletResult(withHistory);
        } catch (historyError) {
          setWalletResult({
            balance,
            tx_history: [],
            history_error: historyError.message,
          });
        }
      } catch (error) {
        setWalletResult(error.message, true);
      }
    });

  document
    .getElementById("walletBalanceAddressForm")
    .addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = serializeForm(event.currentTarget);
      const payload = {
        address: raw.address,
      };
      try {
        const withHistory = await historyByAddress(payload.address);
        setWalletResult(withHistory);
      } catch (error) {
        try {
          const balance = await request("/wallet/balance-by-address", {
            method: "POST",
            body: payload,
          });
          setWalletResult({
            balance,
            tx_history: [],
            history_error: error.message,
          });
        } catch (fallbackError) {
          setWalletResult(fallbackError.message, true);
        }
      }
    });

  document.getElementById("walletSendForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      mnemonic: raw.mnemonic,
      passphrase: raw.passphrase || "",
      seed_mode: raw.seed_mode || "bip39",
      to: raw.to,
      amount: parseNumber(raw.amount, 0),
      fee: parseNumber(raw.fee, 1),
      account: parseNumber(raw.account, 0),
      index: parseNumber(raw.index, 0),
    };
    try {
      const data = await request("/wallet/send", { method: "POST", body: payload });
      setWalletResult(data);
      await refreshDashboard();
    } catch (error) {
      setWalletResult(error.message, true);
    }
  });

  document.getElementById("walletDecodeForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    try {
      const data = await request("/wallet/decode", {
        method: "POST",
        body: { address: raw.address },
      });
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
    }
  });

  document.getElementById("walletQrForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const raw = serializeForm(event.currentTarget);
    const payload = {
      address: raw.address,
      ...(raw.amount ? { amount: parseNumber(raw.amount, 0) } : {}),
      ...(raw.label ? { label: raw.label } : {}),
    };
    try {
      const data = await request("/wallet/qr", { method: "POST", body: payload });
      setWalletResult(data);
    } catch (error) {
      setWalletResult(error.message, true);
    }
  });
}

function initEndpointControls() {
  apiBaseInput.value = state.apiBase;

  saveEndpointBtn.addEventListener("click", async () => {
    state.apiBase = apiBaseInput.value.trim().replace(/\/$/, "");
    localStorage.setItem("scam.console.apiBase", state.apiBase);
    await refreshDashboard();
    startLiveStream();
  });

  refreshAllBtn.addEventListener("click", async () => {
    await refreshDashboard();
  });
}

async function bootstrap() {
  initTabs();
  initEndpointControls();
  initExplorerActions();
  initWalletActions();
  await refreshDashboard();
  startLiveStream();
  setInterval(() => {
    refreshDashboard().catch((error) => {
      setResult(mempoolOut, `Auto refresh failed: ${error.message}`, true);
    });
  }, DASHBOARD_POLL_INTERVAL_MS);
  window.addEventListener("beforeunload", () => closeLiveStream());
}

bootstrap();

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
  el.textContent = typeof data === "string" ? data : formatJson(data);
  el.classList.toggle("error", isError);
}

function formatAtomicScam(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return `${value}`;
  return `${(n / 1e8).toLocaleString(undefined, {
    minimumFractionDigits: 8,
    maximumFractionDigits: 8,
  })} SCAM (${n.toLocaleString()} atomic)`;
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

function formatWalletBalanceSummary(data) {
  const total = Number(data.total) || 0;
  const spendable = Number(data.spendable) || 0;
  const immature = Number(data.immature) || 0;
  const spendablePct = total > 0 ? ((spendable / total) * 100).toFixed(2) : "0.00";
  const immaturePct = total > 0 ? ((immature / total) * 100).toFixed(2) : "0.00";
  let status = "Status: no funds detected";
  if (total > 0 && spendable === 0 && immature > 0) {
    status = "Status: funds are immature (coinbase maturity not reached yet)";
  } else if (spendable > 0 && immature > 0) {
    status = "Status: partially spendable";
  } else if (spendable > 0 && immature === 0) {
    status = "Status: fully spendable";
  }
  return [
    "Wallet Balance Summary",
    "======================",
    `Network      : ${data.network_id ?? "-"}`,
    `Address      : ${data.address ?? "-"}`,
    `Tip Height   : ${data.tip_height ?? "-"}`,
    "",
    "Balances",
    `  Total      : ${formatAtomicScam(total)}`,
    `  Spendable  : ${formatAtomicScam(spendable)} (${spendablePct}%)`,
    `  Immature   : ${formatAtomicScam(immature)} (${immaturePct}%)`,
    "",
    "UTXO counts",
    `  Total      : ${(data.utxo_count ?? 0).toLocaleString()}`,
    `  Spendable  : ${(data.spendable_utxo_count ?? 0).toLocaleString()}`,
    `  Immature   : ${(data.immature_utxo_count ?? 0).toLocaleString()}`,
    "",
    status,
  ].join("\n");
}

function setWalletResult(data, isError = false) {
  if (!isError && isWalletBalancePayload(data)) {
    setResult(walletOut, formatWalletBalanceSummary(data));
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
        const data = await request("/wallet/balance", { method: "POST", body: payload });
        setWalletResult(data);
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
        const data = await request("/wallet/balance-by-address", { method: "POST", body: payload });
        setWalletResult(data);
      } catch (error) {
        setWalletResult(error.message, true);
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
